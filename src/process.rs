use std::path::PathBuf;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use tokio::sync::{mpsc, oneshot};

fn refresh_kind() -> ProcessRefreshKind {
    ProcessRefreshKind::nothing()
        .with_cmd(UpdateKind::Always)
        .with_cwd(UpdateKind::Always)
        .with_exe(UpdateKind::Always)
}

pub struct ProcessInfo {
    pub cwd: Option<PathBuf>,
    pub exe: Option<PathBuf>,
    pub cmdline: Option<String>,
}

impl ProcessInfo {
    pub const fn empty() -> Self {
        Self {
            cwd: None,
            exe: None,
            cmdline: None,
        }
    }
}

struct ProcessLookupMsg {
    pid: u32,
    reply_to: oneshot::Sender<ProcessInfo>,
}

#[derive(Clone)]
pub struct ProcessServer {
    tx: mpsc::Sender<ProcessLookupMsg>,
}

impl ProcessServer {
    pub fn spawn() -> Self {
        let (tx, mut rx) = mpsc::channel::<ProcessLookupMsg>(100);
        std::thread::spawn(move || {
            let mut sys = System::new();
            while let Some(msg) = rx.blocking_recv() {
                let sysinfo_pid = Pid::from_u32(msg.pid);
                sys.refresh_processes_specifics(
                    ProcessesToUpdate::Some(&[sysinfo_pid]),
                    false,
                    refresh_kind(),
                );
                let info = sys
                    .process(sysinfo_pid)
                    .map_or_else(ProcessInfo::empty, |proc| {
                        let cmd = proc.cmd();
                        ProcessInfo {
                            cwd: proc.cwd().map(PathBuf::from),
                            exe: proc.exe().map(PathBuf::from),
                            cmdline: (!cmd.is_empty()).then(|| {
                                cmd.iter()
                                    .map(|s| s.to_string_lossy())
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            }),
                        }
                    });
                let _ = msg.reply_to.send(info);
            }
        });
        Self { tx }
    }

    pub async fn lookup(&self, pid: u32) -> ProcessInfo {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .tx
            .send(ProcessLookupMsg {
                pid,
                reply_to: reply_tx,
            })
            .await
            .is_ok()
        {
            reply_rx.await.unwrap_or_else(|_| ProcessInfo::empty())
        } else {
            ProcessInfo::empty()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cwd_returns_current_directory() {
        let server = ProcessServer::spawn();
        let info = server.lookup(std::process::id()).await;
        assert_eq!(info.cwd.unwrap(), std::env::current_dir().unwrap());
    }

    #[tokio::test]
    async fn exe_returns_a_path() {
        let server = ProcessServer::spawn();
        let info = server.lookup(std::process::id()).await;
        assert!(!info.exe.unwrap().as_os_str().is_empty());
    }

    #[tokio::test]
    async fn cmdline_is_nonempty() {
        let server = ProcessServer::spawn();
        let info = server.lookup(std::process::id()).await;
        assert!(!info.cmdline.unwrap().is_empty());
    }

    #[tokio::test]
    async fn nonexistent_pid_returns_none() {
        let server = ProcessServer::spawn();
        let info = server.lookup(u32::MAX).await;
        assert!(info.cwd.is_none());
        assert!(info.exe.is_none());
        assert!(info.cmdline.is_none());
    }

    #[test]
    fn empty_has_all_none() {
        let info = ProcessInfo::empty();
        assert!(info.cwd.is_none());
        assert!(info.exe.is_none());
        assert!(info.cmdline.is_none());
    }
}
