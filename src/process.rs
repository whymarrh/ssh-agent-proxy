use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

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
    pub fn lookup(sys: &Mutex<System>, pid: u32) -> Self {
        let mut guard = sys.lock().unwrap_or_else(PoisonError::into_inner);
        let sysinfo_pid = Pid::from_u32(pid);
        guard.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[sysinfo_pid]),
            false,
            refresh_kind(),
        );
        guard.process(sysinfo_pid).map_or_else(Self::empty, |proc| {
            let cmd = proc.cmd();
            Self {
                cwd: proc.cwd().map(PathBuf::from),
                exe: proc.exe().map(PathBuf::from),
                cmdline: (!cmd.is_empty()).then(|| {
                    cmd.iter()
                        .map(|s| s.to_string_lossy())
                        .collect::<Vec<_>>()
                        .join(" ")
                }),
            }
        })
    }

    pub const fn empty() -> Self {
        Self {
            cwd: None,
            exe: None,
            cmdline: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cwd_returns_current_directory() {
        let sys = Mutex::new(System::new());
        let info = ProcessInfo::lookup(&sys, std::process::id());
        assert_eq!(info.cwd.unwrap(), std::env::current_dir().unwrap());
    }

    #[test]
    fn exe_returns_a_path() {
        let sys = Mutex::new(System::new());
        let info = ProcessInfo::lookup(&sys, std::process::id());
        assert!(!info.exe.unwrap().as_os_str().is_empty());
    }

    #[test]
    fn cmdline_is_nonempty() {
        let sys = Mutex::new(System::new());
        let info = ProcessInfo::lookup(&sys, std::process::id());
        assert!(!info.cmdline.unwrap().is_empty());
    }

    #[test]
    fn nonexistent_pid_returns_none() {
        let sys = Mutex::new(System::new());
        let info = ProcessInfo::lookup(&sys, u32::MAX);
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

    #[test]
    fn reusing_system_is_consistent() {
        let sys = Mutex::new(System::new());
        let pid = std::process::id();
        let a = ProcessInfo::lookup(&sys, pid);
        let b = ProcessInfo::lookup(&sys, pid);
        assert_eq!(a.cwd, b.cwd);
        assert_eq!(a.exe, b.exe);
    }
}
