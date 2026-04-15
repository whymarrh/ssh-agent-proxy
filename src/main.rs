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
    fingerprint: String,
    directories: Vec<PathBuf>,
}

impl Config {
    fn load(path: &Path) -> Result<Self, Box<dyn Error>> {
        let contents = fs::read_to_string(path)
            .map_err(|err| format!("failed to read config at {}: {err}", path.display()))?;
        let mut config: Self = toml::from_str(&contents)?;
        config.socket = expand_tilde(&config.socket);
        config.upstream = expand_tilde(&config.upstream);
        for rule in &mut config.rules {
            rule.directories = rule
                .directories
                .iter()
                .map(|d| expand_tilde(d))
                .collect();
            let before = rule.directories.len();
            rule.directories.dedup();
            if rule.directories.len() < before {
                eprintln!(
                    "[warn] duplicate directories in rule for {}, duplicates ignored",
                    rule.fingerprint
                );
            }
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

fn matching_fingerprints(config: &Config, cwd: &Path) -> Vec<String> {
    config
        .rules
        .iter()
        .filter(|rule| rule.directories.iter().any(|d| cwd.starts_with(d)))
        .map(|rule| rule.fingerprint.clone())
        .collect()
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

    let matched_fps = cwd
        .as_ref()
        .map(|cwd_path| matching_fingerprints(&conn_config, cwd_path));

    let allowed_fps: Option<&[String]> = matched_fps
        .as_ref()
        .filter(|fps| !fps.is_empty())
        .map(Vec::as_slice);

    match &allowed_fps {
        Some(fps) => {
            eprintln!("  matched: {} fingerprint(s)", fps.len());
            for fp in *fps {
                eprintln!("    {fp}");
            }
        }
        None => eprintln!("  matched: (none, passthrough)"),
    }

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
            "  {} -> {} dir(s)",
            rule.fingerprint,
            rule.directories.len()
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

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_agent_lib::ssh_key::public::KeyData;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            let path = PathBuf::from(format!("target/test-{name}-{}", process::id()));
            drop(fs::remove_dir_all(&path));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            drop(fs::remove_dir_all(&self.0));
        }
    }

    fn make_identity(seed: u8, comment: &str) -> Identity {
        let mut wire = Vec::new();
        wire.extend_from_slice(&11u32.to_be_bytes());
        wire.extend_from_slice(b"ssh-ed25519");
        wire.extend_from_slice(&32u32.to_be_bytes());
        wire.extend_from_slice(&[seed; 32]);
        Identity {
            pubkey: KeyData::decode(&mut &*wire).unwrap(),
            comment: comment.into(),
        }
    }

    fn fp(id: &Identity) -> String {
        identity_fingerprint(id).unwrap()
    }

    fn encode_request(req: &Request) -> Vec<u8> {
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();
        buf
    }

    fn encode_response(resp: &Response) -> Vec<u8> {
        let mut buf = Vec::new();
        resp.encode(&mut buf).unwrap();
        buf
    }

    async fn fake_upstream(listener: UnixListener, identities: Vec<Identity>) {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else {
                break;
            };
            let ids = identities.clone();
            tokio::spawn(async move {
                loop {
                    let Ok(frame) = read_frame(&mut conn).await else {
                        break;
                    };
                    let Ok(req) = Request::decode(&mut &*frame) else {
                        break;
                    };
                    let resp = match req {
                        Request::RequestIdentities => {
                            Response::IdentitiesAnswer(ids.clone())
                        }
                        _ => Response::Failure,
                    };
                    let buf = encode_response(&resp);
                    if write_frame(&mut conn, &buf).await.is_err() {
                        break;
                    }
                }
            });
        }
    }

    async fn start_proxy(listener: UnixListener, config: Config) {
        let config = Arc::new(config);
        loop {
            let Ok((client, _)) = listener.accept().await else {
                break;
            };
            let conn_config = Arc::clone(&config);
            tokio::spawn(async move {
                drop(handle_connection(client, conn_config).await);
            });
        }
    }

    async fn send_request(client: &mut UnixStream, req: &Request) -> Response {
        let buf = encode_request(req);
        write_frame(client, &buf).await.unwrap();
        let resp_buf = read_frame(client).await.unwrap();
        Response::decode(&mut &*resp_buf).unwrap()
    }

    fn expect_identities(resp: Response) -> Vec<Identity> {
        match resp {
            Response::IdentitiesAnswer(ids) => ids,
            other => panic!("expected IdentitiesAnswer, got {other:?}"),
        }
    }

    fn make_config(dir: &TestDir, rules: Vec<MatchRule>) -> Config {
        Config {
            socket: dir.path("proxy.sock"),
            upstream: dir.path("upstream.sock"),
            rules,
        }
    }

    #[tokio::test]
    async fn passthrough_when_no_rules() {
        let dir = TestDir::new("passthrough");
        let key_a = make_identity(1, "key-a");
        let key_b = make_identity(2, "key-b");

        let upstream_listener = UnixListener::bind(dir.path("upstream.sock")).unwrap();
        let proxy_listener = UnixListener::bind(dir.path("proxy.sock")).unwrap();

        tokio::spawn(fake_upstream(upstream_listener, vec![key_a, key_b]));
        tokio::spawn(start_proxy(proxy_listener, make_config(&dir, vec![])));

        let mut client = UnixStream::connect(dir.path("proxy.sock")).await.unwrap();
        let ids = expect_identities(send_request(&mut client, &Request::RequestIdentities).await);
        assert_eq!(ids.len(), 2);
    }

    #[tokio::test]
    async fn filters_by_fingerprint_when_cwd_matches() {
        let dir = TestDir::new("filter");
        let key_a = make_identity(1, "key-a");
        let key_b = make_identity(2, "key-b");
        let fp_a = fp(&key_a);
        let cwd = env::current_dir().unwrap();

        let upstream_listener = UnixListener::bind(dir.path("upstream.sock")).unwrap();
        let proxy_listener = UnixListener::bind(dir.path("proxy.sock")).unwrap();

        tokio::spawn(fake_upstream(upstream_listener, vec![key_a, key_b]));
        tokio::spawn(start_proxy(
            proxy_listener,
            make_config(&dir, vec![MatchRule {
                fingerprint: fp_a.clone(),
                directories: vec![cwd],
            }]),
        ));

        let mut client = UnixStream::connect(dir.path("proxy.sock")).await.unwrap();
        let ids = expect_identities(send_request(&mut client, &Request::RequestIdentities).await);
        assert_eq!(ids.len(), 1);
        assert_eq!(identity_fingerprint(&ids[0]).unwrap(), fp_a);
    }

    #[tokio::test]
    async fn multiple_rules_match_same_cwd() {
        let dir = TestDir::new("multimatch");
        let key_a = make_identity(1, "key-a");
        let key_b = make_identity(2, "key-b");
        let key_c = make_identity(3, "key-c");
        let fp_a = fp(&key_a);
        let fp_b = fp(&key_b);
        let cwd = env::current_dir().unwrap();

        let upstream_listener = UnixListener::bind(dir.path("upstream.sock")).unwrap();
        let proxy_listener = UnixListener::bind(dir.path("proxy.sock")).unwrap();

        tokio::spawn(fake_upstream(upstream_listener, vec![key_a, key_b, key_c]));
        tokio::spawn(start_proxy(
            proxy_listener,
            make_config(&dir, vec![
                MatchRule {
                    fingerprint: fp_a.clone(),
                    directories: vec![cwd.clone()],
                },
                MatchRule {
                    fingerprint: fp_b.clone(),
                    directories: vec![cwd],
                },
            ]),
        ));

        let mut client = UnixStream::connect(dir.path("proxy.sock")).await.unwrap();
        let ids = expect_identities(send_request(&mut client, &Request::RequestIdentities).await);
        assert_eq!(ids.len(), 2);
        let fps: Vec<_> = ids.iter().filter_map(identity_fingerprint).collect();
        assert!(fps.contains(&fp_a));
        assert!(fps.contains(&fp_b));
    }

    #[tokio::test]
    async fn fingerprint_shared_across_directories() {
        let dir = TestDir::new("shared");
        let key_a = make_identity(1, "key-a");
        let key_b = make_identity(2, "key-b");
        let fp_a = fp(&key_a);
        let cwd = env::current_dir().unwrap();

        let upstream_listener = UnixListener::bind(dir.path("upstream.sock")).unwrap();
        let proxy_listener = UnixListener::bind(dir.path("proxy.sock")).unwrap();

        tokio::spawn(fake_upstream(upstream_listener, vec![key_a, key_b]));
        tokio::spawn(start_proxy(
            proxy_listener,
            make_config(&dir, vec![MatchRule {
                fingerprint: fp_a.clone(),
                directories: vec![cwd, PathBuf::from("/some/other/dir")],
            }]),
        ));

        let mut client = UnixStream::connect(dir.path("proxy.sock")).await.unwrap();
        let ids = expect_identities(send_request(&mut client, &Request::RequestIdentities).await);
        assert_eq!(ids.len(), 1);
        assert_eq!(identity_fingerprint(&ids[0]).unwrap(), fp_a);
    }

    #[tokio::test]
    async fn passthrough_when_cwd_does_not_match_any_rule() {
        let dir = TestDir::new("nomatch");
        let key_a = make_identity(1, "key-a");

        let upstream_listener = UnixListener::bind(dir.path("upstream.sock")).unwrap();
        let proxy_listener = UnixListener::bind(dir.path("proxy.sock")).unwrap();

        tokio::spawn(fake_upstream(upstream_listener, vec![key_a]));
        tokio::spawn(start_proxy(
            proxy_listener,
            make_config(&dir, vec![MatchRule {
                fingerprint: "SHA256:doesnotmatter".into(),
                directories: vec![PathBuf::from("/nonexistent/path")],
            }]),
        ));

        let mut client = UnixStream::connect(dir.path("proxy.sock")).await.unwrap();
        let ids = expect_identities(send_request(&mut client, &Request::RequestIdentities).await);
        assert_eq!(ids.len(), 1);
    }

    #[tokio::test]
    async fn non_identity_request_forwarded() {
        let dir = TestDir::new("nonident");
        let upstream_listener = UnixListener::bind(dir.path("upstream.sock")).unwrap();
        let proxy_listener = UnixListener::bind(dir.path("proxy.sock")).unwrap();

        tokio::spawn(fake_upstream(upstream_listener, vec![]));
        tokio::spawn(start_proxy(proxy_listener, make_config(&dir, vec![])));

        let mut client = UnixStream::connect(dir.path("proxy.sock")).await.unwrap();
        let resp = send_request(&mut client, &Request::RemoveAllIdentities).await;
        assert!(matches!(resp, Response::Failure));
    }

    #[tokio::test]
    async fn multiple_requests_on_same_connection() {
        let dir = TestDir::new("multi");
        let key_a = make_identity(1, "key-a");

        let upstream_listener = UnixListener::bind(dir.path("upstream.sock")).unwrap();
        let proxy_listener = UnixListener::bind(dir.path("proxy.sock")).unwrap();

        tokio::spawn(fake_upstream(upstream_listener, vec![key_a]));
        tokio::spawn(start_proxy(proxy_listener, make_config(&dir, vec![])));

        let mut client = UnixStream::connect(dir.path("proxy.sock")).await.unwrap();
        for _ in 0..3 {
            let ids =
                expect_identities(send_request(&mut client, &Request::RequestIdentities).await);
            assert_eq!(ids.len(), 1);
        }
    }

    #[tokio::test]
    async fn fingerprint_is_stable() {
        let id = make_identity(42, "test");
        let fp1 = fp(&id);
        let fp2 = fp(&id);
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("SHA256:"));
    }

    #[tokio::test]
    async fn different_keys_have_different_fingerprints() {
        let id_a = make_identity(1, "a");
        let id_b = make_identity(2, "b");
        assert_ne!(fp(&id_a), fp(&id_b));
    }

    #[test]
    fn expand_tilde_with_home() {
        let home = env::var("HOME").unwrap();
        let expanded = expand_tilde(Path::new("~/foo/bar"));
        assert_eq!(expanded, PathBuf::from(home).join("foo/bar"));
    }

    #[test]
    fn expand_tilde_without_prefix() {
        let path = Path::new("/absolute/path");
        assert_eq!(expand_tilde(path), path);
    }
}
