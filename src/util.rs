//! Low-level OS helpers and parsing utilities.

use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, io, mem, ptr};

/// Parse a human size string such as `200G`, `1.5TiB`, `512M`, `4096`.
/// Suffix multipliers are base-2 (K=1024, M=1024^2, ...), matching mergerfs.
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        bail!("empty size");
    }
    let split = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '_'))
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let val: f64 = num
        .replace('_', "")
        .parse()
        .with_context(|| format!("invalid size number in {s:?}"))?;
    let mult: f64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kib" | "kb" => 1024.0,
        "m" | "mib" | "mb" => 1024f64.powi(2),
        "g" | "gib" | "gb" => 1024f64.powi(3),
        "t" | "tib" | "tb" => 1024f64.powi(4),
        "p" | "pib" | "pb" => 1024f64.powi(5),
        other => bail!("unknown size unit {other:?} in {s:?}"),
    };
    Ok((val * mult) as u64)
}

/// Parse a human duration such as `14d`, `2w`, `36h`, `90min`.
pub fn parse_duration(s: &str) -> Result<Duration> {
    humantime::parse_duration(s.trim()).with_context(|| format!("invalid duration {s:?}"))
}

/// Read an extended attribute as raw bytes, or `None` if absent/unsupported.
pub fn getxattr(path: &Path, name: &str) -> Option<Vec<u8>> {
    let cpath = CString::new(path.as_os_str().as_bytes()).ok()?;
    let cname = CString::new(name).ok()?;
    unsafe {
        let len = libc::getxattr(cpath.as_ptr(), cname.as_ptr(), ptr::null_mut(), 0);
        if len < 0 {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        let got = libc::getxattr(
            cpath.as_ptr(),
            cname.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        );
        if got < 0 {
            return None;
        }
        buf.truncate(got as usize);
        Some(buf)
    }
}

/// Read an xattr as a UTF-8 string (trimming a trailing NUL if present).
pub fn getxattr_str(path: &Path, name: &str) -> Option<String> {
    let mut b = getxattr(path, name)?;
    if b.last() == Some(&0) {
        b.pop();
    }
    String::from_utf8(b).ok()
}

/// Bytes available to an unprivileged user on the filesystem holding `path`.
pub fn free_bytes(path: &Path) -> Result<u64> {
    let cpath = CString::new(path.as_os_str().as_bytes())?;
    let mut st: libc::statvfs = unsafe { mem::zeroed() };
    let r = unsafe { libc::statvfs(cpath.as_ptr(), &mut st) };
    if r != 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("statvfs {}", path.display()));
    }
    Ok(st.f_bavail as u64 * st.f_frsize as u64)
}

fn to_timespec(t: SystemTime) -> libc::timespec {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    libc::timespec {
        tv_sec: d.as_secs() as libc::time_t,
        tv_nsec: d.subsec_nanos() as _,
    }
}

/// Set atime+mtime on `path` (does not follow symlinks of the final component
/// only insofar as utimensat default; we pass 0 flags = follow).
pub fn set_times(path: &Path, atime: SystemTime, mtime: SystemTime) -> io::Result<()> {
    let times = [to_timespec(atime), to_timespec(mtime)];
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path has NUL"))?;
    let r = unsafe { libc::utimensat(libc::AT_FDCWD, cpath.as_ptr(), times.as_ptr(), 0) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---- systemd notify / watchdog ------------------------------------------------

/// Send a notification string to the systemd notify socket if present.
pub fn sd_notify(state: &str) {
    let sock = match env::var_os("NOTIFY_SOCKET") {
        Some(s) => s,
        None => return,
    };
    let bytes = sock.as_bytes();
    if bytes.is_empty() {
        return;
    }
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return;
        }
        let mut addr: libc::sockaddr_un = mem::zeroed();
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let cap = addr.sun_path.len();
        if bytes.len() >= cap {
            libc::close(fd);
            return;
        }
        let mut tmp = bytes.to_vec();
        // Abstract namespace sockets are encoded with a leading NUL; systemd
        // exposes them with a leading '@'.
        if tmp[0] == b'@' {
            tmp[0] = 0;
        }
        let dst = addr.sun_path.as_mut_ptr() as *mut u8;
        ptr::copy_nonoverlapping(tmp.as_ptr(), dst, tmp.len());
        let base = mem::size_of::<libc::sa_family_t>();
        let addrlen = (base + tmp.len()) as libc::socklen_t;
        let msg = state.as_bytes();
        libc::sendto(
            fd,
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
            0,
            &addr as *const _ as *const libc::sockaddr,
            addrlen,
        );
        libc::close(fd);
    }
}

/// Watchdog interval requested by systemd (`WATCHDOG_USEC`), halved per the
/// systemd convention of pinging at least twice per interval.
pub fn watchdog_interval() -> Option<Duration> {
    let usec: u64 = env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
    if usec == 0 {
        return None;
    }
    Some(Duration::from_micros(usec / 2))
}

// ---- signal handling ----------------------------------------------------------

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

pub fn install_signal_handlers() {
    unsafe {
        let mut sa: libc::sigaction = mem::zeroed();
        sa.sa_sigaction = on_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGTERM, &sa, ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, ptr::null_mut());
    }
}

pub fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// Sleep up to `dur`, returning early if a shutdown signal arrives.
pub fn interruptible_sleep(dur: Duration) {
    let step = Duration::from_millis(200);
    let mut remaining = dur;
    while remaining > Duration::ZERO {
        if shutdown_requested() {
            return;
        }
        let s = remaining.min(step);
        std::thread::sleep(s);
        remaining = remaining.saturating_sub(s);
    }
}
