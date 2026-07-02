use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::plan::{Branch, Move};
use crate::scan::TMP_PREFIX;
use crate::util::{fmt_bytes, Watchdog};

#[derive(Debug, Default)]
pub struct Stats {
    pub files: u64,
    pub bytes: u64,
    pub skipped: u64,
    pub errors: u64,
}

enum MoveOutcome {
    Done,
    /// File changed/vanished/locked under us; not an error, retry next pass.
    Skipped(String),
}

pub fn execute(
    branches: &[Branch],
    moves: &[Move],
    dry_run: bool,
    throttle_bps: Option<u64>,
    wd: &Watchdog,
    stop: &AtomicBool,
) -> Stats {
    let mut stats = Stats::default();
    for mv in moves {
        if stop.load(Ordering::SeqCst) {
            log::info!("stop requested; aborting remaining {} moves", moves.len() as u64 - stats.files - stats.skipped - stats.errors);
            break;
        }
        let src_root = &branches[mv.from].path;
        let dst_root = &branches[mv.to].path;
        if dry_run {
            log::info!(
                "DRY-RUN [{}] {} : {} -> {} ({})",
                mv.reason,
                mv.rel.display(),
                src_root.display(),
                dst_root.display(),
                fmt_bytes(mv.size)
            );
            stats.files += 1;
            stats.bytes += mv.size;
            continue;
        }
        match move_one(src_root, dst_root, &mv.rel, throttle_bps, wd, stop) {
            Ok(MoveOutcome::Done) => {
                log::info!(
                    "[{}] {} : {} -> {} ({})",
                    mv.reason,
                    mv.rel.display(),
                    src_root.display(),
                    dst_root.display(),
                    fmt_bytes(mv.size)
                );
                stats.files += 1;
                stats.bytes += mv.size;
            }
            Ok(MoveOutcome::Skipped(why)) => {
                log::info!("skipped {}: {}", mv.rel.display(), why);
                stats.skipped += 1;
            }
            Err(e) => {
                log::error!("failed to move {}: {}", mv.rel.display(), e);
                stats.errors += 1;
            }
        }
    }
    stats
}

fn cstr(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

/// Create missing parent directories on the destination branch, mirroring
/// mode/ownership from the source branch where possible.
fn mirror_parent_dirs(src_root: &Path, dst_root: &Path, rel: &Path) -> io::Result<()> {
    let parent = match rel.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => return Ok(()),
    };
    let mut cur_src = src_root.to_path_buf();
    let mut cur_dst = dst_root.to_path_buf();
    for comp in parent.components() {
        cur_src.push(comp);
        cur_dst.push(comp);
        match fs::symlink_metadata(&cur_dst) {
            Ok(_) => continue,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        match fs::create_dir(&cur_dst) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
        if let Ok(md) = fs::symlink_metadata(&cur_src) {
            let _ = fs::set_permissions(&cur_dst, md.permissions());
            if let Ok(c) = cstr(&cur_dst) {
                unsafe {
                    if libc::chown(c.as_ptr(), md.uid(), md.gid()) != 0 {
                        log::debug!("chown {} failed: {}", cur_dst.display(), io::Error::last_os_error());
                    }
                }
            }
        }
    }
    Ok(())
}

fn copy_xattrs(src: &Path, dst: &Path) {
    let (csrc, cdst) = match (cstr(src), cstr(dst)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return,
    };
    unsafe {
        let len = libc::llistxattr(csrc.as_ptr(), std::ptr::null_mut(), 0);
        if len <= 0 {
            return; // none, or unsupported
        }
        let mut names = vec![0u8; len as usize];
        let len = libc::llistxattr(csrc.as_ptr(), names.as_mut_ptr() as *mut libc::c_char, names.len());
        if len <= 0 {
            return;
        }
        names.truncate(len as usize);
        for name in names.split(|b| *b == 0).filter(|n| !n.is_empty()) {
            let cname = match CString::new(name) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let vlen = libc::lgetxattr(csrc.as_ptr(), cname.as_ptr(), std::ptr::null_mut(), 0);
            if vlen < 0 {
                continue;
            }
            let mut val = vec![0u8; vlen as usize];
            let vlen = libc::lgetxattr(
                csrc.as_ptr(),
                cname.as_ptr(),
                val.as_mut_ptr() as *mut libc::c_void,
                val.len(),
            );
            if vlen < 0 {
                continue;
            }
            if libc::lsetxattr(
                cdst.as_ptr(),
                cname.as_ptr(),
                val.as_ptr() as *const libc::c_void,
                vlen as usize,
                0,
            ) != 0
            {
                log::debug!(
                    "lsetxattr {:?} on {} failed: {}",
                    String::from_utf8_lossy(name),
                    dst.display(),
                    io::Error::last_os_error()
                );
            }
        }
    }
}

fn move_one(
    src_root: &Path,
    dst_root: &Path,
    rel: &Path,
    throttle_bps: Option<u64>,
    wd: &Watchdog,
    stop: &AtomicBool,
) -> io::Result<MoveOutcome> {
    let src_path = src_root.join(rel);
    let dst_path = dst_root.join(rel);

    // Re-verify the source right before moving (the scan may be minutes old).
    let before = match fs::symlink_metadata(&src_path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(MoveOutcome::Skipped("source vanished".into()))
        }
        Err(e) => return Err(e),
    };
    if !before.file_type().is_file() {
        return Ok(MoveOutcome::Skipped("not a regular file anymore".into()));
    }
    if before.nlink() > 1 {
        return Ok(MoveOutcome::Skipped("file has hardlinks".into()));
    }
    if fs::symlink_metadata(&dst_path).is_ok() {
        return Ok(MoveOutcome::Skipped(
            "destination path already exists on target branch".into(),
        ));
    }

    mirror_parent_dirs(src_root, dst_root, rel)?;

    let dst_parent = dst_path.parent().unwrap_or(dst_root).to_path_buf();
    let tmp_path: PathBuf = dst_parent.join(format!(
        "{}{}.{}",
        TMP_PREFIX,
        std::process::id(),
        crate::util::unix_now()
    ));

    let mut src = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&src_path)?;
    let mut tmp = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)?;

    // Copy with optional throttle; clean up the temp file on any failure.
    let copy_result = (|| -> io::Result<MoveOutcome> {
        let mut buf = vec![0u8; 1 << 20];
        let mut written: u64 = 0;
        let start = Instant::now();
        loop {
            if stop.load(Ordering::SeqCst) {
                return Ok(MoveOutcome::Skipped("interrupted by shutdown".into()));
            }
            let n = src.read(&mut buf)?;
            if n == 0 {
                break;
            }
            tmp.write_all(&buf[..n])?;
            written += n as u64;
            wd.tick();
            if let Some(bps) = throttle_bps {
                let want = Duration::from_secs_f64(written as f64 / bps as f64);
                let got = start.elapsed();
                if want > got {
                    std::thread::sleep(want - got);
                }
            }
        }
        tmp.sync_all()?;

        // Metadata: mode, ownership, xattrs, then times last.
        let fd = {
            use std::os::unix::io::AsRawFd;
            tmp.as_raw_fd()
        };
        unsafe {
            if libc::fchown(fd, before.uid(), before.gid()) != 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EPERM) {
                    log::warn!(
                        "cannot preserve ownership of {} (need CAP_CHOWN / root): {e}",
                        rel.display()
                    );
                } else {
                    return Err(e);
                }
            }
            if libc::fchmod(fd, (before.mode() & 0o7777) as libc::mode_t) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        copy_xattrs(&src_path, &tmp_path);
        let times = [
            libc::timespec {
                tv_sec: before.atime(),
                tv_nsec: before.atime_nsec(),
            },
            libc::timespec {
                tv_sec: before.mtime(),
                tv_nsec: before.mtime_nsec(),
            },
        ];
        unsafe {
            if libc::futimens(fd, times.as_ptr()) != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        // The source must not have changed while we copied it.
        let after = fs::symlink_metadata(&src_path)?;
        if after.ino() != before.ino()
            || after.size() != before.size()
            || after.mtime() != before.mtime()
            || after.mtime_nsec() != before.mtime_nsec()
        {
            return Ok(MoveOutcome::Skipped("source changed during copy".into()));
        }

        // Publish: rename temp into place (never clobber), then drop source.
        let ctmp = cstr(&tmp_path)?;
        let cdst = cstr(&dst_path)?;
        let rc = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                ctmp.as_ptr(),
                libc::AT_FDCWD,
                cdst.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if rc != 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EEXIST) {
                return Ok(MoveOutcome::Skipped(
                    "destination appeared during copy".into(),
                ));
            }
            return Err(e);
        }
        // From here the file briefly exists on both branches, which mergerfs
        // handles fine. The window where it exists on neither is zero.
        if let Err(e) = fs::remove_file(&src_path) {
            // Couldn't remove the source: revert to avoid a lasting duplicate.
            let _ = fs::remove_file(&dst_path);
            return Err(io::Error::new(
                e.kind(),
                format!("could not unlink source after copy (reverted): {e}"),
            ));
        }
        // Best-effort durability of the directory entries.
        if let Ok(d) = File::open(&dst_parent) {
            let _ = d.sync_all();
        }
        if let Some(sp) = src_path.parent() {
            if let Ok(d) = File::open(sp) {
                let _ = d.sync_all();
            }
        }
        Ok(MoveOutcome::Done)
    })();

    match copy_result {
        Ok(MoveOutcome::Done) => Ok(MoveOutcome::Done),
        Ok(MoveOutcome::Skipped(why)) => {
            let _ = fs::remove_file(&tmp_path);
            Ok(MoveOutcome::Skipped(why))
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}
