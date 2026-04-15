use alloc::sync::Arc;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;
use core::error::Error;
use core::fmt;
use sha2::{Digest as _, Sha256};
use ssh_agent_lib::{
    proto::{Identity, Request, Response},
    ssh_encoding::{Decode as _, Encode as _},
};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::unix::UCred;
use tokio::net::{UnixListener, UnixStream};
use tokio::signal;
use tokio::sync::watch;

extern crate alloc;

#[derive(serde::Deserialize, Clone)]
struct Config {
    socket: PathBuf,
    upstream: PathBuf,
    #[serde(rename = "match", default)]
    rules: Vec<MatchRule>,
}

#[derive(serde::Deserialize, Clone)]
struct MatchRule {
    directory: PathBuf,
    fingerprints: Vec<String>,
}

impl Config {
    fn load(path: &Path) -> Result<Self, Box<dyn Error>> {
        let contents = fs::read_to_string(path)
            .map_err(|err| format!("failed to read config at {}: {err}", path.display()))?;
        let mut config: Self = toml::from_str(&contents)?;
        config.socket = expand_tilde(&config.socket);
        config.upstream = expand_tilde(&config.upstream);
        for rule in &mut config.rules {
            rule.directory = expand_tilde(&rule.directory);
        }
        Ok(config)
    }
}

#[derive(Clone, Copy)]
struct Pid(Option<u32>);

impl fmt::Display for Pid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(pid) => write!(f, "{pid}"),
            None => f.write_str("-"),
        }
    }
}

fn identity_fingerprint(id: &Identity) -> Option<String> {
    let mut buf = Vec::new();
    id.pubkey.encode(&mut buf).ok()?;
    let hash = Sha256::digest(&buf);
    let b64 = STANDARD_NO_PAD.encode(hash);
    Some(format!("SHA256:{b64}"))
}

fn expand_tilde(path: &Path) -> PathBuf {
    path.to_str()
        .and_then(|s| s.strip_prefix("~/"))
        .and_then(|rest| env::var_os("HOME").map(|h| PathBuf::from(h).join(rest)))
        .unwrap_or_else(|| path.to_path_buf())
}

async fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let len = stream.read_u32().await? as usize;
    if len > 256 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds 256 KiB",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame(stream: &mut UnixStream, data: &[u8]) -> io::Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_err| io::Error::new(io::ErrorKind::InvalidData, "frame exceeds u32"))?;
    stream.write_u32(len).await?;
    stream.write_all(data).await?;
    stream.flush().await
}

#[cfg(target_os = "linux")]
fn get_process_cwd(pid: u32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/cwd")).ok()
}

#[cfg(target_os = "linux")]
fn get_process_exe(pid: u32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(target_os = "linux")]
fn get_process_cmdline(pid: u32) -> Option<String> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let args: Vec<&str> = bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|s| core::str::from_utf8(s).ok())
        .collect();
    (!args.is_empty()).then(|| args.join(" "))
}

#[cfg(target_os = "macos")]
fn get_process_cwd(pid: u32) -> Option<PathBuf> {
    let output = process::Command::new("lsof")
        .args(["-a", "-p", &pid.to_string(), "-d", "cwd", "-Fn"])
        .output()
        .ok()?;
    let stdout = String::from_utf8(output.stdout).ok()?;
    stdout
        .lines()
        .find_map(|l| l.strip_prefix('n'))
        .map(PathBuf::from)
}

#[cfg(target_os = "macos")]
fn get_process_exe(pid: u32) -> Option<PathBuf> {
    let output = process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .ok()?;
    let stdout = String::from_utf8(output.stdout).ok()?;
    let trimmed = stdout.trim();
    (!trimmed.is_empty()).then(|| PathBuf::from(trimmed))
}

#[cfg(target_os = "macos")]
fn get_process_cmdline(pid: u32) -> Option<String> {
    let output = process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "args="])
        .output()
        .ok()?;
    let stdout = String::from_utf8(output.stdout).ok()?;
    let trimmed = stdout.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

async fn proxy_request(
    client: &mut UnixStream,
    upstream: &mut UnixStream,
    allowed_fps: Option<&[String]>,
    pid: Pid,
    raw_request: &[u8],
) -> io::Result<()> {
    let request = Request::decode(&mut &*raw_request)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("bad request: {err}")))?;

    eprintln!("[req]  pid={pid} {request:?}");

    write_frame(upstream, raw_request).await?;
    let raw_response = read_frame(upstream).await?;

    let out = match (&request, allowed_fps) {
        (&Request::RequestIdentities, Some(fps)) => filter_identities(&raw_response, fps, pid),
        (&Request::RequestIdentities, None) => {
            if let Ok(Response::IdentitiesAnswer(ref ids)) = Response::decode(&mut &*raw_response) {
                eprintln!(
                    "[resp] pid={pid} IdentitiesAnswer: {} key(s), no filter",
                    ids.len()
                );
            }
            raw_response
        }
        _ => {
            eprintln!("[resp] pid={pid} forwarded");
            raw_response
        }
    };

    write_frame(client, &out).await
}

fn filter_identities(raw: &[u8], allowed: &[String], pid: Pid) -> Vec<u8> {
    let Ok(Response::IdentitiesAnswer(ids)) = Response::decode(&mut &*raw) else {
        eprintln!("[resp] pid={pid} could not decode IdentitiesAnswer, forwarding raw");
        return raw.to_vec();
    };

    let total = ids.len();
    let filtered: Vec<_> = ids
        .into_iter()
        .filter(|id| {
            let Some(fp) = identity_fingerprint(id) else {
                eprintln!(
                    "[filt] pid={pid}   DROP  (encoding failed) ({})",
                    id.comment
                );
                return false;
            };
            let keep = allowed.iter().any(|a| a == &fp);
            let verb = if keep { "KEEP" } else { "DROP" };
            eprintln!("[filt] pid={pid}   {verb}  {fp} ({})", id.comment);
            keep
        })
        .collect();

    eprintln!(
        "[resp] pid={pid} IdentitiesAnswer: {total} upstream -> {} returned",
        filtered.len()
    );

    let mut buf = Vec::new();
    if Response::IdentitiesAnswer(filtered)
        .encode(&mut buf)
        .is_err()
    {
        eprintln!("[resp] pid={pid} failed to encode filtered response, forwarding raw");
        return raw.to_vec();
    }
    buf
}

async fn handle_connection(mut client: UnixStream, conn_config: Arc<Config>) -> io::Result<()> {
    let cred = client.peer_cred().ok();
    let pid = Pid(cred.as_ref().and_then(UCred::pid).map(i32::cast_unsigned));
    let uid = cred.as_ref().map(UCred::uid);

    let first_request = read_frame(&mut client).await?;

    let exe = pid.0.and_then(get_process_exe);
    let cmdline = pid.0.and_then(get_process_cmdline);
    let cwd = pid.0.and_then(get_process_cwd);

    eprintln!("[conn] new connection");
    eprintln!("  pid:     {pid}");
    eprintln!(
        "  uid:     {}",
        uid.map_or_else(|| "-".into(), |u| u.to_string())
    );
    eprintln!(
        "  exe:     {}",
        exe.as_deref().and_then(Path::to_str).unwrap_or("-")
    );
    eprintln!("  cmdline: {}", cmdline.as_deref().unwrap_or("-"));
    eprintln!(
        "  cwd:     {}",
        cwd.as_deref().and_then(Path::to_str).unwrap_or("-")
    );

    let matched_rule = cwd.as_ref().and_then(|cwd_path| {
        conn_config
            .rules
            .iter()
            .enumerate()
            .find(|(_, rule)| cwd_path.starts_with(&rule.directory))
    });

    match matched_rule {
        Some((idx, rule)) => eprintln!("  rule:    [{idx}] directory={}", rule.directory.display()),
        None => eprintln!("  rule:    (none, passthrough)"),
    }

    let allowed_fps: Option<&[String]> = matched_rule.map(|(_, rule)| rule.fingerprints.as_slice());
    let mut upstream = UnixStream::connect(&conn_config.upstream).await?;

    proxy_request(&mut client, &mut upstream, allowed_fps, pid, &first_request).await?;
    loop {
        let raw = read_frame(&mut client).await?;
        proxy_request(&mut client, &mut upstream, allowed_fps, pid, &raw).await?;
    }
}

fn log_config(config: &Config) {
    eprintln!("  upstream: {}", config.upstream.display());
    for rule in &config.rules {
        eprintln!(
            "  {} -> {} key(s)",
            rule.directory.display(),
            rule.fingerprints.len()
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let raw_config_path = env::args()
        .nth(1)
        .ok_or("usage: op-ssh-agent-proxy <config.toml>")?;
    let config_path = expand_tilde(Path::new(&raw_config_path));
    let initial_config = Config::load(&config_path)?;

    drop(fs::remove_file(&initial_config.socket));
    if let Some(parent) = initial_config.socket.parent() {
        fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(&initial_config.socket)?;
    eprintln!(
        "op-ssh-agent-proxy listening on {}",
        initial_config.socket.display()
    );
    log_config(&initial_config);

    let (config_tx, config_rx) = watch::channel(Arc::new(initial_config));

    let reload_path = config_path.clone();
    tokio::spawn(async move {
        let Ok(mut sig) = signal::unix::signal(signal::unix::SignalKind::user_defined1()) else {
            eprintln!("[warn] failed to register SIGUSR1 handler, config reload disabled");
            return;
        };
        loop {
            sig.recv().await;
            match Config::load(&reload_path) {
                Ok(new) => {
                    eprintln!("[reload] config reloaded");
                    log_config(&new);
                    drop(config_tx.send(Arc::new(new)));
                }
                Err(err) => eprintln!("[reload] failed: {err}"),
            }
        }
    });

    let cleanup_path = config_rx.borrow().socket.clone();
    tokio::spawn(async move {
        drop(signal::ctrl_c().await);
        drop(fs::remove_file(&cleanup_path));
        process::exit(0);
    });

    loop {
        let (client, _) = listener.accept().await?;
        let conn_config = Arc::clone(&config_rx.borrow());
        tokio::spawn(async move {
            if let Err(err) = handle_connection(client, conn_config).await {
                if err.kind() != io::ErrorKind::UnexpectedEof {
                    eprintln!("connection error: {err}");
                }
            }
        });
    }
}
