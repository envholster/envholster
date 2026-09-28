//! Unix process controls needed to clean up secret files on normal signals.
//! Unsafe OS calls stay alongside the existing process hardening boundary.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

const SIGNALS: [i32; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];
static ACTIVE: AtomicBool = AtomicBool::new(false);
static PENDING: AtomicU32 = AtomicU32::new(0);

extern "C" fn record_signal(signal: i32) {
    // Atomics are lock-free on supported targets. All OS work happens in
    // the supervisor, so a handler cannot race a reaped/reused child PID.
    PENDING.fetch_or(1 << signal, Ordering::Relaxed);
}

/// Owns signal dispositions until secret-file cleanup has finished.
pub struct ProcessSignals {
    previous: Vec<(i32, libc::sigaction)>,
    terminal: Option<File>,
    foreground: Option<(i32, i32)>,
}

impl ProcessSignals {
    /// Must be created before materializing plaintext and dropped afterwards.
    pub fn install() -> io::Result<Self> {
        if ACTIVE.swap(true, Ordering::AcqRel) {
            return Err(io::Error::other("a process signal guard is already active"));
        }
        PENDING.store(0, Ordering::Relaxed);
        let mut guard = Self {
            previous: Vec::new(),
            terminal: File::open("/dev/tty").ok(),
            foreground: None,
        };
        for signal in SIGNALS.into_iter().chain([libc::SIGCHLD]) {
            // SAFETY: sigaction/sigset_t are C value structs; both pointers
            // refer to initialized, owned storage for the duration of the call.
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                let mut previous: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = record_signal as *const () as usize;
                action.sa_flags = libc::SA_RESTART;
                libc::sigemptyset(&mut action.sa_mask);
                if libc::sigaction(signal, &action, &mut previous) != 0 {
                    return Err(io::Error::last_os_error());
                }
                guard.previous.push((signal, previous));
            }
        }
        Ok(guard)
    }

    /// Draining happens only in ordinary process context, never in a handler.
    pub fn take_pending(&self) -> Vec<i32> {
        let pending = PENDING.swap(0, Ordering::Relaxed);
        SIGNALS
            .into_iter()
            .filter(|signal| pending & (1 << signal) != 0)
            .collect()
    }

    /// Sleep until a signal interrupts the wait, with a bounded fallback for
    /// the race between inspecting pending state and entering the syscall.
    pub fn wait_for_activity(&self) -> io::Result<()> {
        if PENDING.load(Ordering::Relaxed) != 0 {
            return Ok(());
        }
        // SAFETY: poll permits a null descriptor array when the count is zero.
        // Unlike sleep under SA_RESTART, it returns on a caught signal. SIGCHLD
        // wakes normal exit/stop handling; the one-second bound also covers a
        // handler delivered on another thread or just before this call.
        let result = unsafe { libc::poll(std::ptr::null_mut(), 0, 1000) };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        Ok(())
    }

    /// Transfers an interactive foreground job without stealing a background
    /// job's terminal. The child must already lead its own process group.
    pub fn foreground_child(&mut self, child: i32) -> io::Result<()> {
        if child <= 0 {
            return Err(io::Error::other("invalid child process group"));
        }
        if let Some(terminal) = &self.terminal {
            let fd = terminal.as_raw_fd();
            // SAFETY: these query process IDs and an owned descriptor.
            let group = unsafe { libc::getpgrp() };
            let foreground = unsafe { libc::tcgetpgrp(fd) };
            if foreground == group {
                set_foreground(fd, child)?;
                self.foreground = Some((group, child));
                // A fast reader may have received SIGTTIN before handoff.
                Self::signal_child(child, libc::SIGCONT)?;
            }
        }
        Ok(())
    }

    /// Signals the entire child job, including subprocesses such as workers.
    pub fn signal_child(child: i32, signal: i32) -> io::Result<()> {
        if child <= 0 {
            return Err(io::Error::other("invalid child process group"));
        }
        // SAFETY: a negative, validated process-group ID targets the child
        // job only. ESRCH means it exited before the signal was delivered.
        if unsafe { libc::kill(-child, signal) } == 0 {
            if matches!(
                signal,
                libc::SIGTERM | libc::SIGHUP | libc::SIGINT | libc::SIGQUIT
            ) {
                // SAFETY: same validated child group; resume permits pending
                // termination to be handled even if the job was stopped.
                unsafe {
                    libc::kill(-child, libc::SIGCONT);
                }
            }
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error)
        }
    }

    /// Fatal setup/wait errors must reap even a child that left its original job.
    pub fn abort_child(child: i32) {
        if child > 0 {
            let _ = Self::signal_child(child, libc::SIGKILL);
            // SAFETY: caller still owns the unreaped direct child PID.
            unsafe {
                libc::kill(child, libc::SIGKILL);
            }
        }
    }

    /// Preserves Ctrl-Z/fg semantics when the supervised child stops.
    pub fn child_stopped(&mut self, child: i32) -> io::Result<()> {
        if self.terminal.is_none() {
            // Headless jobs have no shell fg command to complete the handoff.
            return Self::signal_child(child, libc::SIGCONT);
        }
        self.restore_terminal();
        // Stop the original shell job, including pipeline peers. SIGTSTP lets
        // a shell sharing this group keep its ignored disposition; SIGSTOP
        // would freeze that shell when job control is disabled.
        stop_shell_job()?;
        self.foreground_child(child)?;
        Self::signal_child(child, libc::SIGCONT)
    }

    fn restore_terminal(&mut self) {
        if let (Some(terminal), Some((parent, child))) = (&self.terminal, self.foreground.take()) {
            // SAFETY: the descriptor remains owned by this guard.
            if unsafe { libc::tcgetpgrp(terminal.as_raw_fd()) } == child {
                let _ = set_foreground(terminal.as_raw_fd(), parent);
            }
        }
    }
}

fn stop_shell_job() -> io::Result<()> {
    // SAFETY: stack-owned dispositions. Only this process's SIGTSTP action is
    // changed and restored after resume. Group 0 is the current shell job;
    // peer processes retain their own actions (including a shell's ignore).
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        let mut previous: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGTSTP, &action, &mut previous) != 0 {
            return Err(io::Error::last_os_error());
        }
        let result = libc::kill(0, libc::SIGTSTP);
        let error = io::Error::last_os_error();
        let restored = libc::sigaction(libc::SIGTSTP, &previous, std::ptr::null_mut());
        if restored != 0 {
            return Err(io::Error::last_os_error());
        }
        if result != 0 {
            return Err(error);
        }
        Ok(())
    }
}

fn set_foreground(fd: i32, group: i32) -> io::Result<()> {
    // SAFETY: owned stack signal sets; the previous thread mask is restored
    // before returning. No child is spawned while SIGTTOU is blocked.
    unsafe {
        let mut blocked: libc::sigset_t = std::mem::zeroed();
        let mut previous: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut blocked);
        libc::sigaddset(&mut blocked, libc::SIGTTOU);
        let error = libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous);
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        let result = libc::tcsetpgrp(fd, group);
        let error = io::Error::last_os_error();
        let restored = libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
        if result != 0 {
            return Err(error);
        }
        if restored != 0 {
            return Err(io::Error::from_raw_os_error(restored));
        }
        Ok(())
    }
}

impl Drop for ProcessSignals {
    fn drop(&mut self) {
        self.restore_terminal();
        for (signal, previous) in self.previous.iter().rev() {
            // SAFETY: these are the original dispositions saved at install.
            unsafe {
                libc::sigaction(*signal, previous, std::ptr::null_mut());
            }
        }
        ACTIVE.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::ManuallyDrop;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    struct TestChild(Child);
    impl Drop for TestChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn stopped_headless_child_is_resumed_without_a_shell() {
        let mut child = TestChild(
            Command::new("/bin/sh")
                .args(["-c", "kill -STOP $$; exit 0"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0)
                .spawn()
                .unwrap(),
        );
        let pid = child.0.id() as i32;
        let mut status = 0;
        // SAFETY: a live direct child, and an owned status output. WUNTRACED
        // observes the stop without reaping the child managed by TestChild.
        let stopped = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
        assert_eq!(stopped, pid);
        assert!(libc::WIFSTOPPED(status));
        // Drop restores process-wide dispositions; this fixture never installed
        // any. Empty fields need no cleanup in the shared test process.
        let mut guard = ManuallyDrop::new(ProcessSignals {
            previous: Vec::new(),
            terminal: None,
            foreground: None,
        });
        guard.child_stopped(pid).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "headless child stayed stopped");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
