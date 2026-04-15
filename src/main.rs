//! SSH agent proxy that filters identities based on the requesting process's
//! working directory. Point `IdentityAgent` in your SSH config at this proxy's
//! socket, and it will forward requests to an upstream agent (e.g. 1Password)
//! while only exposing keys that match the caller's CWD.

use base64::Engine;
use sha2::{Digest, Sha256};
use ssh_agent_lib::{
    proto::{Identity, Request, Response},
    ssh_encoding::{Decode, Encode},
};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

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
    fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read config at {}: {e}", path.display()))?;
        let mut config: Self = toml::from_str(&contents)?;
        config.socket = expand_tilde(&config.socket);
        config.upstream = expand_tilde(&config.upstream);
        for rule in &mut config.rules {
            rule.directory = expand_tilde(&rule.directory);
        }
        Ok(config)
    }
}

/// Wrapper around `Option<u32>` that displays as the PID or "-".
#[derive(Clone, Copy)]
struct Pid(Option<u32>);

impl fmt::Display for Pid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(p) => write!(f, "{p}"),
            None => f.write_str("-"),
        }
    }
}

fn identity_fingerprint(id: &Identity) -> String {
    let mut buf = Vec::new();
    id.pubkey.encode(&mut buf).expect("key encoding failed");
    let hash = Sha256::digest(&buf);
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(hash);
    format!("SHA256:{b64}")
}

fn expand_tilde(path: &Path) -> PathBuf {
    path.to_str()
        .and_then(|s| s.strip_prefix("~/"))
        .and_then(|rest| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(rest)))
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
    stream.write_u32(data.len() as u32).await?;
    stream.write_all(data).await?;
    stream.flush().await
}

#[cfg(target_os = "linux")]
fn get_process_cwd(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
}

#[cfg(target_os = "linux")]
fn get_process_exe(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(target_os = "linux")]
fn get_process_cmdline(pid: u32) -> Option<String> {
    let bytes = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let args: Vec<&str> = bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .filter_map(|s| std::str::from_utf8(s).ok())
        .collect();
    (!args.is_empty()).then(|| args.join(" "))
}

#[cfg(target_os = "macos")]
fn get_process_cwd(pid: u32) -> Option<PathBuf> {
    // Use lsof to read the CWD of another process without unsafe.
    // lsof -a -p <pid> -d cwd -Fn outputs "p<pid>\nn<path>\n".
    let output = std::process::Command::new("lsof")
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
    // Use ps to read the executable path without unsafe.
    let output = std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .ok()?;
    let stdout = String::from_utf8(output.stdout).ok()?;
    let trimmed = stdout.trim();
    (!trimmed.is_empty()).then(|| PathBuf::from(trimmed))
}

#[cfg(target_os = "macos")]
fn get_process_cmdline(pid: u32) -> Option<String> {
    // Use ps to read the full command line without unsafe.
    let output = std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "args="])
        .output()
        .ok()?;
    let stdout = String::from_utf8(output.stdout).ok()?;
    let trimmed = stdout.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

async fn proxy_request(
    client: &mut UnixStream,
    upstream: &mut UnixStream,
    allowed_fps: Option<&[String]>,
    pid: Pid,
    raw_request: &[u8],
) -> io::Result<()> {
    let request = Request::decode(&mut &raw_request[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad request: {e}")))?;

    eprintln!("[req]  pid={pid} {request:?}");

    write_frame(upstream, raw_request).await?;
    let raw_response = read_frame(upstream).await?;

    let out = match (&request, allowed_fps) {
        (Request::RequestIdentities, Some(fps)) => filter_identities(&raw_response, fps, pid),
        (Request::RequestIdentities, None) => {
            if let Ok(Response::IdentitiesAnswer(ids)) = Response::decode(&mut &raw_response[..]) {
                eprintln!("[resp] pid={pid} IdentitiesAnswer: {} key(s), no filter", ids.len());
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
    let Ok(Response::IdentitiesAnswer(ids)) = Response::decode(&mut &raw[..]) else {
        eprintln!("[resp] pid={pid} could not decode IdentitiesAnswer, forwarding raw");
        return raw.to_vec();
    };

    let total = ids.len();
    let filtered: Vec<_> = ids
        .into_iter()
        .filter(|id| {
            let fp = identity_fingerprint(id);
            let keep = allowed.iter().any(|a| a == &fp);
            let verb = if keep { "KEEP" } else { "DROP" };
            eprintln!("[filt] pid={pid}   {verb}  {fp} ({})", id.comment);
            keep
        })
        .collect();

    eprintln!("[resp] pid={pid} IdentitiesAnswer: {total} upstream -> {} returned", filtered.len());

    let mut buf = Vec::new();
    Response::IdentitiesAnswer(filtered)
        .encode(&mut buf)
        .expect("response encoding failed");
    buf
}

async fn handle_connection(mut client: UnixStream, config: Arc<Config>) -> io::Result<()> {
    let cred = client.peer_cred().ok();
    let pid = Pid(cred.as_ref().and_then(|c| c.pid()).map(|p| p as u32));
    let uid = cred.as_ref().map(|c| c.uid());

    // Read the first request before gathering process info.  The client is
    // definitely alive and fully initialised once it has written to the socket.
    let first_request = read_frame(&mut client).await?;

    let exe = pid.0.and_then(get_process_exe);
    let cmdline = pid.0.and_then(get_process_cmdline);
    let cwd = pid.0.and_then(get_process_cwd);

    eprintln!("[conn] new connection");
    eprintln!("  pid:     {pid}");
    eprintln!("  uid:     {}", uid.map_or("-".into(), |u| u.to_string()));
    eprintln!("  exe:     {}", exe.as_deref().and_then(Path::to_str).unwrap_or("-"));
    eprintln!("  cmdline: {}", cmdline.as_deref().unwrap_or("-"));
    eprintln!("  cwd:     {}", cwd.as_deref().and_then(Path::to_str).unwrap_or("-"));

    let matched_rule = cwd.as_ref().and_then(|cwd| {
        config
            .rules
            .iter()
            .enumerate()
            .find(|(_, r)| cwd.starts_with(&r.directory))
    });

    match &matched_rule {
        Some((i, rule)) => eprintln!("  rule:    [{}] directory={}", i, rule.directory.display()),
        None => eprintln!("  rule:    (none, passthrough)"),
    }

    let allowed_fps: Option<&[String]> = matched_rule.map(|(_, r)| r.fingerprints.as_slice());
    let mut upstream = UnixStream::connect(&config.upstream).await?;

    proxy_request(&mut client, &mut upstream, allowed_fps, pid, &first_request).await?;
    loop {
        let raw = read_frame(&mut client).await?;
        proxy_request(&mut client, &mut upstream, allowed_fps, pid, &raw).await?;
    }
}

fn log_config(config: &Config) {
    eprintln!("  upstream: {}", config.upstream.display());
    for rule in &config.rules {
        eprintln!("  {} -> {} key(s)", rule.directory.display(), rule.fingerprints.len());
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::env::args()
        .nth(1)
        .ok_or("usage: op-ssh-agent-proxy <config.toml>")?;
    let config_path = expand_tilde(Path::new(&config_path));
    let config = Config::load(&config_path)?;

    let _ = std::fs::remove_file(&config.socket);
    if let Some(parent) = config.socket.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(&config.socket)?;
    eprintln!("op-ssh-agent-proxy listening on {}", config.socket.display());
    log_config(&config);

    let (config_tx, config_rx) = watch::channel(Arc::new(config));

    // Reload config on SIGUSR1.
    let reload_path = config_path.clone();
    tokio::spawn(async move {
        let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
            .expect("failed to register SIGUSR1 handler");
        loop {
            sig.recv().await;
            match Config::load(&reload_path) {
                Ok(new) => {
                    eprintln!("[reload] config reloaded");
                    log_config(&new);
                    let _ = config_tx.send(Arc::new(new));
                }
                Err(e) => eprintln!("[reload] failed: {e}"),
            }
        }
    });

    // Remove socket on ctrl-c.
    let cleanup_path = config_rx.borrow().socket.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = std::fs::remove_file(&cleanup_path);
        std::process::exit(0);
    });

    loop {
        let (client, _) = listener.accept().await?;
        let config = Arc::clone(&config_rx.borrow());
        tokio::spawn(async move {
            if let Err(e) = handle_connection(client, config).await {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    eprintln!("connection error: {e}");
                }
            }
        });
    }
}
