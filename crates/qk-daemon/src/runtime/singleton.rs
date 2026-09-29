//! Singleton ownership: pid file (compatibility/status UX) plus an
//! atomic lock file (the real mutual exclusion).
//!
//! A pid file alone is never proof of liveness. The lock file is
//! created atomically (`create_new`); a second starter that finds it
//! checks the recorded pid: live pid means `AlreadyRunning`, dead pid
//! means a crashed predecessor whose stale file is reclaimed, and an
//! unreadable file means fail closed. The lock is held open for the
//! whole daemon lifetime and removed on graceful shutdown only when it
//! still names this instance — a failing second instance never deletes
//! the active daemon's state.

use std::io::Write as _;

use super::error::{RuntimeError, RuntimeErrorKind};
use super::paths::RuntimePaths;
use super::process::{process_liveness, Liveness};

/// Parsed pid-file content: `<pid>\n<port>\n` (frozen reference shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PidRecord {
    /// Owning daemon process id.
    pub pid: u32,
    /// Port the owner bound.
    pub port: u16,
}

/// Read and strictly parse the pid file. `Ok(None)` when absent;
/// malformed content is a typed `Pid` error, never a guessed pid and
/// never a kill of an arbitrary number.
pub fn read_pid(paths: &RuntimePaths) -> Result<Option<PidRecord>, RuntimeError> {
    let bytes = match std::fs::read(&paths.pid) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(RuntimeError::new(
                RuntimeErrorKind::Pid,
                format!("cannot read pid file: {error}"),
            ));
        }
    };
    parse_pid(&bytes).map(Some).map_err(|detail| {
        RuntimeError::new(
            RuntimeErrorKind::Pid,
            format!("malformed pid file: {detail}"),
        )
    })
}

fn parse_pid(bytes: &[u8]) -> Result<PidRecord, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "not UTF-8")?;
    let mut lines = text.lines();
    let pid: u32 = lines
        .next()
        .ok_or("empty")?
        .trim()
        .parse()
        .map_err(|_| "bad pid")?;
    if pid == 0 {
        return Err("bad pid");
    }
    let port: u16 = lines
        .next()
        .ok_or("missing port")?
        .trim()
        .parse()
        .map_err(|_| "bad port")?;
    if port == 0 {
        return Err("bad port");
    }
    Ok(PidRecord { pid, port })
}

/// Atomically publish the pid file (temp + rename; only ever called
/// after the listener is bound, so "pid file present" implies
/// "accepting requests"). Content keeps the frozen `<pid>\n<port>\n`
/// shape.
pub fn write_pid(paths: &RuntimePaths, record: PidRecord) -> Result<(), RuntimeError> {
    let tmp = paths.pid.with_extension("pid.tmp");
    let _ = std::fs::remove_file(&tmp);
    std::fs::write(&tmp, format!("{}\n{}\n", record.pid, record.port)).map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::Pid,
            format!("cannot write pid temp file: {error}"),
        )
    })?;
    std::fs::rename(&tmp, &paths.pid).map_err(|error| {
        RuntimeError::new(
            RuntimeErrorKind::Pid,
            format!("cannot publish pid file: {error}"),
        )
    })?;
    Ok(())
}

/// Remove the pid file only when it still names `record` (ownership
/// check): a second failing instance or a concurrent `stop` must never
/// delete state it does not own. Missing file after a matching read is
/// fine (already gone).
pub fn remove_pid_if_owned(paths: &RuntimePaths, record: PidRecord) -> Result<bool, RuntimeError> {
    match read_pid(paths)? {
        Some(current) if current == record => match std::fs::remove_file(&paths.pid) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(RuntimeError::new(
                RuntimeErrorKind::Pid,
                format!("cannot remove pid file: {error}"),
            )),
        },
        _ => Ok(false),
    }
}

/// Exclusive runtime ownership, held for the whole daemon lifetime.
/// The open file handle pins the claim; dropping without cleanup only
/// happens on crash, which the stale-reclaim path recovers.
pub struct SingletonLock {
    path: std::path::PathBuf,
    pid: u32,
    // Held open for the daemon lifetime (pins the create_new claim
    // against non-cooperating cleaners on platforms where that matters).
    _file: std::fs::File,
}

impl std::fmt::Debug for SingletonLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SingletonLock")
            .field("path", &self.path)
            .field("pid", &self.pid)
            .finish_non_exhaustive()
    }
}

impl SingletonLock {
    /// Process id recorded in the lock.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Release ownership: remove the lock file only if it still names
    /// this instance (same ownership rule as the pid file).
    pub fn release(self) -> Result<(), RuntimeError> {
        let path = self.path.clone();
        let pid = self.pid;
        drop(self);
        let current = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(RuntimeError::new(
                    RuntimeErrorKind::Lock,
                    format!("cannot verify lock ownership: {error}"),
                ));
            }
        };
        if current
            .lines()
            .next()
            .is_some_and(|line| line.trim() == pid.to_string())
        {
            match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(RuntimeError::new(
                    RuntimeErrorKind::Lock,
                    format!("cannot release lock file: {error}"),
                )),
            }
        } else {
            Ok(())
        }
    }
}

/// Acquire exclusive ownership of the runtime directory. A live recorded
/// pid fails fast with `AlreadyRunning` (carrying that pid for
/// diagnostics); a dead pid is a crashed predecessor whose stale file
/// is reclaimed and retried; anything unverifiable fails closed.
pub fn acquire(paths: &RuntimePaths) -> Result<SingletonLock, RuntimeError> {
    // Bounded retries: each pass either acquires, refuses, or reclaims
    // exactly one stale file, so this always terminates.
    for _ in 0..8 {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&paths.lock)
        {
            Ok(mut file) => {
                let pid = std::process::id();
                writeln!(file, "{pid}").map_err(|error| {
                    RuntimeError::new(
                        RuntimeErrorKind::Lock,
                        format!("cannot write lock file: {error}"),
                    )
                })?;
                let _ = file.sync_all();
                return Ok(SingletonLock {
                    path: paths.lock.clone(),
                    pid,
                    _file: file,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(RuntimeError::new(
                    RuntimeErrorKind::Lock,
                    format!("cannot create lock file: {error}"),
                ));
            }
        }
        match recorded_lock_pid(&paths.lock)? {
            Some(pid) => match process_liveness(pid) {
                Liveness::Alive => {
                    return Err(RuntimeError::new(
                        RuntimeErrorKind::AlreadyRunning,
                        format!("runtime directory already owned by process {pid}"),
                    ));
                }
                Liveness::Dead => {
                    // Crashed predecessor: reclaim and retry.
                    match std::fs::remove_file(&paths.lock) {
                        Ok(()) => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(error) => {
                            return Err(RuntimeError::new(
                                RuntimeErrorKind::Lock,
                                format!("cannot reclaim stale lock file: {error}"),
                            ));
                        }
                    }
                }
                Liveness::Unknown => {
                    return Err(RuntimeError::new(
                        RuntimeErrorKind::Lock,
                        "lock file held by an unverifiable process; refusing to start",
                    ));
                }
            },
            None => {
                return Err(RuntimeError::new(
                    RuntimeErrorKind::Lock,
                    "lock file is unreadable; refusing to start",
                ));
            }
        }
    }
    Err(RuntimeError::new(
        RuntimeErrorKind::Lock,
        "cannot acquire runtime lock after stale reclaims",
    ))
}

/// The pid recorded in an existing lock file, if parsable.
fn recorded_lock_pid(path: &std::path::Path) -> Result<Option<u32>, RuntimeError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(RuntimeError::new(
                RuntimeErrorKind::Lock,
                format!("cannot read lock file: {error}"),
            ));
        }
    };
    Ok(text
        .lines()
        .next()
        .and_then(|line| line.trim().parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_paths(name: &str) -> RuntimePaths {
        let dir = std::env::temp_dir().join(format!(
            "qk-runtime-singleton-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        RuntimePaths::new(dir)
    }

    #[test]
    fn pid_round_trip_and_malformed() {
        let paths = test_paths("pid");
        assert_eq!(read_pid(&paths).expect("read"), None);
        write_pid(
            &paths,
            PidRecord {
                pid: 1234,
                port: 47821,
            },
        )
        .expect("write");
        assert_eq!(
            read_pid(&paths).expect("read"),
            Some(PidRecord {
                pid: 1234,
                port: 47821
            })
        );
        // Ownership: foreign record is not removed.
        assert!(!remove_pid_if_owned(
            &paths,
            PidRecord {
                pid: 9999,
                port: 47821
            }
        )
        .expect("owned?"));
        assert!(read_pid(&paths).expect("read").is_some());
        assert!(remove_pid_if_owned(
            &paths,
            PidRecord {
                pid: 1234,
                port: 47821
            }
        )
        .expect("remove"));
        assert_eq!(read_pid(&paths).expect("read"), None);
        // Malformed content is a typed error, never a guessed pid.
        std::fs::write(&paths.pid, "not-a-pid\n").expect("plant");
        let error = read_pid(&paths).expect_err("malformed");
        assert_eq!(error.kind(), &RuntimeErrorKind::Pid);
        let _ = std::fs::remove_dir_all(&paths.home);
    }

    #[test]
    fn second_acquire_refused_first_released() {
        let paths = test_paths("lock");
        let lock = acquire(&paths).expect("first");
        let error = acquire(&paths).expect_err("second must fail");
        assert_eq!(error.kind(), &RuntimeErrorKind::AlreadyRunning);
        assert!(format!("{error}").contains(&lock.pid().to_string()));
        lock.release().expect("release");
        assert!(!paths.lock.exists());
        let _ = std::fs::remove_dir_all(&paths.home);
    }

    #[test]
    fn stale_lock_reclaimed() {
        let paths = test_paths("stale");
        std::fs::write(&paths.lock, "2147483000\n").expect("plant stale");
        let lock = acquire(&paths).expect("reclaim");
        assert_eq!(lock.pid(), std::process::id());
        lock.release().expect("release");
        let _ = std::fs::remove_dir_all(&paths.home);
    }
}
