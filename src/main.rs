extern crate alloc;

use alloc::sync::Arc;
use core::fmt;
use ssh_agent_lib::{
    proto::{Identity, Response},
    ssh_encoding::{Decode as _, Encode as _},
    ssh_key::HashAlg,
};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::exit;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::unix::UCred;
use tokio::net::{UnixListener, UnixStream};
use tokio::signal;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::writer::MakeWriterExt as _;

use thiserror::Error;
use toml::de::Error as TomlError;

#[derive(Debug, Error)]
enum AppError {
    #[error("usage: op-ssh-agent-proxy <config.toml>")]
    MissingConfigArgument,

    #[error("failed to read config at {path}: {source}")]
    ConfigRead {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("failed to parse config: {0}")]
    ConfigParse(#[from] TomlError),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

mod process;

use process::{ProcessInfo, ProcessServer};

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
struct Config {
    socket: PathBuf,
    upstream: PathBuf,
    #[serde(rename = "match", default)]
    rules: Vec<MatchRule>,
}

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
struct MatchRule {
    fingerprint: String,
    directories: Vec<PathBuf>,
}

impl Config {
    fn load(path: &Path) -> Result<Self, AppError> {
        let contents = fs::read_to_string(path).map_err(|source| AppError::ConfigRead {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&contents)
    }

    fn parse(contents: &str) -> Result<Self, AppError> {
        let mut config: Self = toml::from_str(contents)?;
        config.socket = expand_tilde(&config.socket);
        config.upstream = expand_tilde(&config.upstream);
        for rule in &mut config.rules {
            rule.directories = rule.directories.iter().map(|d| expand_tilde(d)).collect();
            let before = rule.directories.len();
            rule.directories.sort();
            rule.directories.dedup();
            if rule.directories.len() < before {
                warn!(
                    fingerprint = rule.fingerprint,
                    "ignoring duplicate directories found in rule"
                );
            }
        }
        Ok(config)
    }

    fn log(&self) {
        info!(config = ?self, "loaded config");
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

fn identity_fingerprint(id: &Identity) -> String {
    id.pubkey.fingerprint(HashAlg::default()).to_string()
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

fn matching_fingerprints(config: &Config, cwd: &Path) -> Vec<String> {
    config
        .rules
        .iter()
        .filter(|rule| rule.directories.iter().any(|d| cwd.starts_with(d)))
        .map(|rule| rule.fingerprint.clone())
        .collect()
}

fn filter_identities(raw: &[u8], allowed: &[String], pid: Pid) -> Vec<u8> {
    let Ok(Response::IdentitiesAnswer(ids)) = Response::decode(&mut &*raw) else {
        warn!(%pid, "could not decode IdentitiesAnswer");
        return raw.to_vec();
    };

    let total = ids.len();
    let filtered: Vec<_> = ids
        .into_iter()
        .filter(|id| {
            let fp = identity_fingerprint(id);
            let keep = allowed.iter().any(|a| a == &fp);
            if keep {
                debug!(%pid, %fp, comment = id.comment, "KEEP");
            } else {
                debug!(%pid, %fp, comment = id.comment, "DROP");
            }
            keep
        })
        .collect();

    debug!(%pid, total, returned = filtered.len(), "successfully filtered identities");

    let mut buf = Vec::new();
    if Response::IdentitiesAnswer(filtered)
        .encode(&mut buf)
        .is_err()
    {
        error!(%pid, "failed to encode filtered response");
        return raw.to_vec();
    }
    buf
}

async fn handle_request(
    client: &mut UnixStream,
    upstream: &mut UnixStream,
    allowed_fps: Option<&[String]>,
    pid: Pid,
    raw_request: &[u8],
) -> io::Result<()> {
    write_frame(upstream, raw_request).await?;
    let raw_response = read_frame(upstream).await?;
    let is_identity_request = raw_request.first().copied() == Some(11);
    let out = if is_identity_request {
        debug!(%pid, "filtering identities for response");
        if let Some(fps) = allowed_fps {
            filter_identities(&raw_response, fps, pid)
        } else {
            if let Ok(Response::IdentitiesAnswer(ref ids)) = Response::decode(&mut &*raw_response) {
                info!(%pid, keys = ids.len(), "identities passthrough");
            }
            raw_response
        }
    } else {
        debug!(%pid, "forwarded raw response");
        raw_response
    };

    write_frame(client, &out).await
}

async fn handle_connection(
    mut client: UnixStream,
    conn_config: Arc<Config>,
    ps: ProcessServer,
) -> io::Result<()> {
    let cred = client.peer_cred().ok();
    let pid = Pid(cred.as_ref().and_then(UCred::pid).map(i32::cast_unsigned));
    let uid = cred.as_ref().map(UCred::uid);
    let info = match pid.0 {
        Some(p) => ps.lookup(p).await,
        None => ProcessInfo::empty(),
    };

    info!(
        %pid,
        uid = uid.map_or_else(|| "-".into(), |u| u.to_string()),
        exe = info.exe.as_deref().and_then(Path::to_str).unwrap_or("-"),
        cmdline = info.cmdline.as_deref().unwrap_or("-"),
        cwd = info.cwd.as_deref().and_then(Path::to_str).unwrap_or("-"),
        "connection",
    );

    let matched_fps = info
        .cwd
        .as_ref()
        .map(|cwd_path| matching_fingerprints(&conn_config, cwd_path));

    let allowed_fps: Option<&[String]> = matched_fps
        .as_ref()
        .filter(|fps| !fps.is_empty())
        .map(Vec::as_slice);

    let mut upstream = UnixStream::connect(&conn_config.upstream).await?;

    loop {
        let raw = read_frame(&mut client).await?;
        handle_request(&mut client, &mut upstream, allowed_fps, pid, &raw).await?;
    }
}

async fn run() -> Result<(), AppError> {
    let writer = io::stdout.and(io::stderr.with_max_level(tracing::Level::ERROR));
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(writer)
        .with_ansi(io::IsTerminal::is_terminal(&io::stdout()))
        .with_target(false)
        .init();

    let raw_config_path = env::args().nth(1).ok_or(AppError::MissingConfigArgument)?;
    let config_path = expand_tilde(Path::new(&raw_config_path));
    let initial_config = Config::load(&config_path)?;

    initial_config.log();
    drop(fs::remove_file(&initial_config.socket));
    if let Some(parent) = initial_config.socket.parent() {
        fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(&initial_config.socket)?;
    info!(socket = %initial_config.socket.display(), "listening for connections");

    let server = ProcessServer::spawn();
    let (config_tx, config_rx) = watch::channel(Arc::new(initial_config));

    let reload_path = config_path.clone();
    tokio::spawn(async move {
        let Ok(mut sig) = signal::unix::signal(signal::unix::SignalKind::user_defined1()) else {
            warn!("failed to register SIGUSR1 handler, config reload disabled");
            return;
        };
        loop {
            sig.recv().await;
            match Config::load(&reload_path) {
                Ok(new) => {
                    info!("SIGUSR1 config reload");
                    new.log();
                    drop(config_tx.send(Arc::new(new)));
                }
                Err(err) => error!(%err, "config reload failed"),
            }
        }
    });

    let cleanup_path = config_rx.borrow().socket.clone();
    let mut ctrl_c = std::pin::pin!(signal::ctrl_c());

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (client, _) = accept_result?;
                let conn_config = Arc::clone(&config_rx.borrow());
                let conn_server = server.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(client, conn_config, conn_server).await
                        && err.kind() != io::ErrorKind::UnexpectedEof
                    {
                        error!(%err, "connection error");
                    }
                });
            }
            _ = &mut ctrl_c => {
                info!("shutting down");
                break;
            }
        }
    }

    drop(fs::remove_file(&cleanup_path));
    Ok(())
}

#[tokio::main]
#[expect(
    clippy::print_stderr,
    reason = "error reporting before tracing is available"
)]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("{err}");
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_agent_lib::proto::Request;
    use ssh_agent_lib::ssh_key::public::KeyData;
    use tempfile::TempDir;

    struct TestEnv {
        _dir: TempDir,
        proxy_sock: PathBuf,
    }

    impl TestEnv {
        async fn new(upstream_keys: Vec<Identity>, rules: Vec<MatchRule>) -> Self {
            let dir = TempDir::new().unwrap();

            let proxy_sock = dir.path().join("proxy.sock");
            let upstream_sock = dir.path().join("upstream.sock");

            let upstream_listener = UnixListener::bind(&upstream_sock).unwrap();
            let proxy_listener = UnixListener::bind(&proxy_sock).unwrap();

            let config = Config {
                socket: proxy_sock.clone(),
                upstream: upstream_sock,
                rules,
            };

            tokio::spawn(fake_upstream(upstream_listener, upstream_keys));
            tokio::spawn(start_proxy(proxy_listener, config));

            Self {
                _dir: dir,
                proxy_sock,
            }
        }

        async fn connect(&self) -> UnixStream {
            UnixStream::connect(&self.proxy_sock).await.unwrap()
        }

        async fn request_identities(&self) -> Vec<Identity> {
            let mut client = self.connect().await;
            expect_identities(send_request(&mut client, &Request::RequestIdentities).await)
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
        identity_fingerprint(id)
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
                    let mut buf = Vec::new();
                    let resp = match req {
                        Request::RequestIdentities => Response::IdentitiesAnswer(ids.clone()),
                        _ => Response::Failure,
                    };
                    resp.encode(&mut buf).unwrap();
                    if write_frame(&mut conn, &buf).await.is_err() {
                        break;
                    }
                }
            });
        }
    }

    async fn start_proxy(listener: UnixListener, config: Config) {
        let config = Arc::new(config);
        let server = ProcessServer::spawn();
        loop {
            let Ok((client, _)) = listener.accept().await else {
                break;
            };
            let conn_config = Arc::clone(&config);
            let conn_server = server.clone();
            tokio::spawn(async move {
                drop(handle_connection(client, conn_config, conn_server).await);
            });
        }
    }

    async fn send_request(client: &mut UnixStream, req: &Request) -> Response {
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();
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

    #[tokio::test]
    async fn passthrough_when_no_rules() {
        let env = TestEnv::new(vec![make_identity(1, "a"), make_identity(2, "b")], vec![]).await;
        assert_eq!(env.request_identities().await.len(), 2);
    }

    #[tokio::test]
    async fn filters_by_fingerprint_when_cwd_matches() {
        let key_a = make_identity(1, "a");
        let fp_a = fp(&key_a);
        let env = TestEnv::new(
            vec![key_a, make_identity(2, "b")],
            vec![MatchRule {
                fingerprint: fp_a.clone(),
                directories: vec![env::current_dir().unwrap()],
            }],
        )
        .await;
        let ids = env.request_identities().await;
        assert_eq!(ids.len(), 1);
        assert_eq!(identity_fingerprint(&ids[0]), fp_a);
    }

    #[tokio::test]
    async fn multiple_rules_match_same_cwd() {
        let key_a = make_identity(1, "a");
        let key_b = make_identity(2, "b");
        let fp_a = fp(&key_a);
        let fp_b = fp(&key_b);
        let cwd = env::current_dir().unwrap();
        let env = TestEnv::new(
            vec![key_a, key_b, make_identity(3, "c")],
            vec![
                MatchRule {
                    fingerprint: fp_a.clone(),
                    directories: vec![cwd.clone()],
                },
                MatchRule {
                    fingerprint: fp_b.clone(),
                    directories: vec![cwd],
                },
            ],
        )
        .await;
        let ids = env.request_identities().await;
        assert_eq!(ids.len(), 2);
        let fps: Vec<_> = ids.iter().map(identity_fingerprint).collect();
        assert!(fps.contains(&fp_a));
        assert!(fps.contains(&fp_b));
    }

    #[tokio::test]
    async fn fingerprint_shared_across_directories() {
        let key_a = make_identity(1, "a");
        let fp_a = fp(&key_a);
        let env = TestEnv::new(
            vec![key_a, make_identity(2, "b")],
            vec![MatchRule {
                fingerprint: fp_a.clone(),
                directories: vec![env::current_dir().unwrap(), PathBuf::from("/other")],
            }],
        )
        .await;
        let ids = env.request_identities().await;
        assert_eq!(ids.len(), 1);
        assert_eq!(identity_fingerprint(&ids[0]), fp_a);
    }

    #[tokio::test]
    async fn passthrough_when_cwd_does_not_match_any_rule() {
        let env = TestEnv::new(
            vec![make_identity(1, "a")],
            vec![MatchRule {
                fingerprint: "SHA256:doesnotmatter".into(),
                directories: vec![PathBuf::from("/nonexistent/path")],
            }],
        )
        .await;
        assert_eq!(env.request_identities().await.len(), 1);
    }

    #[tokio::test]
    async fn non_identity_request_forwarded() {
        let env = TestEnv::new(vec![], vec![]).await;
        let mut client = env.connect().await;
        let resp = send_request(&mut client, &Request::RemoveAllIdentities).await;
        assert!(matches!(resp, Response::Failure));
    }

    #[tokio::test]
    async fn multiple_requests_on_same_connection() {
        let env = TestEnv::new(vec![make_identity(1, "a")], vec![]).await;
        let mut client = env.connect().await;
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
        assert_ne!(fp(&make_identity(1, "a")), fp(&make_identity(2, "b")));
    }

    #[test]
    fn expand_tilde_with_home() {
        let home = env::var("HOME").unwrap();
        assert_eq!(
            expand_tilde(Path::new("~/foo/bar")),
            PathBuf::from(home).join("foo/bar")
        );
    }

    #[test]
    fn expand_tilde_without_prefix() {
        let path = Path::new("/absolute/path");
        assert_eq!(expand_tilde(path), path);
    }

    #[test]
    fn config_deduplicates_non_consecutive_directories() {
        let toml = r#"
            socket = "/tmp/test.sock"
            upstream = "/tmp/upstream.sock"

            [[match]]
            fingerprint = "SHA256:test"
            directories = ["/a", "/b", "/a"]
        "#;
        let raw: Config = toml::from_str(toml).unwrap();
        let parsed = Config::parse(toml).unwrap();
        assert_eq!(raw.rules[0].directories.len(), 3);
        assert_eq!(parsed.rules[0].directories.len(), 2);
    }
}
