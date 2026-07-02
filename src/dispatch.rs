//! Executes planned moves against the underlying branch filesystems.
//!
//! A move preserves the file's relative path under the destination branch. If
//! source and destination share a filesystem the move is a `rename(2)`;
//! otherwise it is a copy to a temporary file (fsynced), a metadata/atime/mtime
//! restore, an atomic rename into place, and an unlink of the source. Both
//! atime and mtime are preserved: atime so a move does not reset the very
//! signal tiering decisions rely on, mtime so the file keeps its position in
//! any mtime-ordered view of the merged pool.
//!
//! Moving a file also perturbs the *containing directories*: unlinking the
//! source bumps the source directory's mtime, the rename-in bumps the
//! destination directory's, and any directory created on the destination
//! branch is born with the current time. mergerfs surfaces a directory's
//! times from one of its branches, so without care every cycle would reshuffle
//! mtime-ordered directory listings. Each move therefore snapshots the
//! directory times it is about to disturb and restores them afterwards, and
//! gives any freshly-created destination directory the mtime of its
//! counterpart on the source branch.

use crate::policy::Move;
use crate::tier::TierMap;
use crate::util::set_times;
use anyhow::{Context, Result};
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub struct Dispatcher<'a> {
    tiers: &'a TierMap,
    dry_run: bool,
}

#[derive(Debug, Default)]
pub struct DispatchStats {
    pub moved: usize,
    pub bytes: u64,
    pub failed: usize,
}

/// atime+mtime of a path, captured so it can be restored after we disturb it.
#[derive(Clone, Copy)]
struct DirTimes {
    atime: SystemTime,
    mtime: SystemTime,
}

fn dir_times(path: &Path) -> Option<DirTimes> {
    let md = fs::metadata(path).ok()?;
    Some(DirTimes {
        atime: md.accessed().ok()?,
        mtime: md.modified().ok()?,
    })
}

fn restore_dir_times(path: &Path, t: DirTimes) {
    if let Err(e) = set_times(path, t.atime, t.mtime) {
        log::debug!(
            "could not restore directory times on {}: {e}",
            path.display()
        );
    }
}

impl<'a> Dispatcher<'a> {
    pub fn new(tiers: &'a TierMap, dry_run: bool) -> Self {
        Dispatcher { tiers, dry_run }
    }

    pub fn run(&self, moves: &[Move]) -> DispatchStats {
        let mut stats = DispatchStats::default();
        for m in moves {
            let src_root = &self.tiers.branch(m.src_branch_idx).branch.path;
            let dst_root = &self.tiers.branch(m.dst_branch_idx).branch.path;
            let src = src_root.join(&m.rel);
            let dst = dst_root.join(&m.rel);
            if self.dry_run {
                log::info!(
                    "[dry-run] {} {} -> {} ({} bytes)",
                    m.reason,
                    src_root.display(),
                    dst_root.display(),
                    m.size
                );
                stats.moved += 1;
                stats.bytes += m.size;
                continue;
            }
            match self.execute(src_root, dst_root, &src, &dst, m) {
                Ok(()) => {
                    stats.moved += 1;
                    stats.bytes += m.size;
                    log::info!(
                        "moved {} ({}): {} -> {}",
                        m.rel.display(),
                        m.reason,
                        self.tiers.branch(m.src_branch_idx).label,
                        self.tiers.branch(m.dst_branch_idx).label,
                    );
                }
                Err(e) => {
                    stats.failed += 1;
                    log::warn!("failed to move {}: {e:#}", m.rel.display());
                }
            }
        }
        stats
    }

    fn execute(
        &self,
        src_root: &Path,
        dst_root: &Path,
        src: &Path,
        dst: &Path,
        m: &Move,
    ) -> Result<()> {
        // The source may have vanished or changed since the scan.
        let src_md =
            fs::symlink_metadata(src).with_context(|| format!("stat source {}", src.display()))?;
        if !src_md.is_file() {
            anyhow::bail!("source is no longer a regular file");
        }

        // Snapshot the times of the directories this move will disturb so they
        // can be put back: the source's parent (the unlink will bump it) and,
        // if it already exists, the destination's parent (the rename-in bumps
        // it). Newly-created destination directories are handled separately.
        let src_parent = src.parent().map(Path::to_path_buf);
        let src_parent_times = src_parent.as_deref().and_then(dir_times);
        let dst_parent = dst.parent().map(Path::to_path_buf);
        let dst_parent_pre = dst_parent.as_deref().and_then(dir_times);

        // Determine which destination directories we must create, and snapshot
        // each one's counterpart on the source branch *before* the move
        // disturbs anything (the unlink below bumps the source directory's
        // mtime). A freshly-created cold-tier directory will inherit these.
        let mut created: Vec<(PathBuf, Option<DirTimes>)> = Vec::new();
        if let Some(parent) = dst.parent() {
            for dir in missing_dirs(parent) {
                let counterpart = dir
                    .strip_prefix(dst_root)
                    .ok()
                    .map(|rel| src_root.join(rel));
                let times = counterpart.as_deref().and_then(dir_times);
                created.push((dir, times));
            }
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }

        // Same filesystem ⇒ atomic rename, nothing to copy.
        let mut same_fs = false;
        if let Ok(dst_parent_md) = fs::metadata(dst.parent().unwrap_or(Path::new("/"))) {
            if dst_parent_md.dev() == src_md.dev() {
                fs::rename(src, dst)
                    .with_context(|| format!("rename {} -> {}", src.display(), dst.display()))?;
                same_fs = true;
            }
        }
        if !same_fs {
            self.copy_across(src, dst, &src_md, m)?;
        }

        // The file is now in place and the source is gone. Restore the
        // directory times we disturbed.
        //
        // Freshly-created destination directories inherit the mtime/atime of
        // their counterpart on the source branch (snapshotted before the move),
        // so a folder that first appears on the cold tier does not read as
        // "just now". Setting a directory's own times does not affect its
        // parent, so order is immaterial.
        for (dir, times) in &created {
            if let Some(t) = times {
                restore_dir_times(dir, *t);
            }
        }
        // If the destination parent already existed, the rename-in bumped it;
        // put it back to what it was before this move.
        if let (Some(parent), Some(t)) = (dst_parent.as_deref(), dst_parent_pre) {
            restore_dir_times(parent, t);
        }
        // The unlink/rename-out bumped the source parent; undo that too.
        if let (Some(parent), Some(t)) = (src_parent.as_deref(), src_parent_times) {
            // Only meaningful if the directory still exists.
            if parent.exists() {
                restore_dir_times(parent, t);
            }
        }
        Ok(())
    }

    fn copy_across(&self, src: &Path, dst: &Path, src_md: &fs::Metadata, m: &Move) -> Result<()> {
        let tmp = tmp_path(dst);
        // Clean any stale temp from a previous crash.
        let _ = fs::remove_file(&tmp);

        let copied = (|| -> Result<()> {
            let mut r = fs::File::open(src).with_context(|| format!("open {}", src.display()))?;
            let mut w = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .with_context(|| format!("create {}", tmp.display()))?;
            io::copy(&mut r, &mut w).context("copy data")?;
            w.sync_all().context("fsync destination")?;
            Ok(())
        })();
        if let Err(e) = copied {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }

        // Restore permissions and ownership where possible, and preserve times.
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(src_md.mode()));
        restore_owner(&tmp, src_md);
        if let Err(e) = set_times(&tmp, m.atime, m.mtime) {
            log::debug!("could not preserve times on {}: {e}", tmp.display());
        }

        fs::rename(&tmp, dst)
            .with_context(|| format!("rename {} -> {}", tmp.display(), dst.display()))?;
        fs::remove_file(src).with_context(|| format!("unlink source {}", src.display()))?;
        Ok(())
    }
}

/// The ancestors of `dir` (including `dir`) that do not yet exist, shallowest
/// first. Does not touch the filesystem, so callers can snapshot the source
/// counterparts' times before creating anything.
fn missing_dirs(dir: &Path) -> Vec<PathBuf> {
    let mut missing = Vec::new();
    let mut cur = Some(dir);
    while let Some(p) = cur {
        if p.exists() {
            break;
        }
        missing.push(p.to_path_buf());
        cur = p.parent();
    }
    missing.reverse();
    missing
}

fn tmp_path(dst: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".mergerfs-tier.");
    if let Some(n) = dst.file_name() {
        name.push(n);
    }
    name.push(".tmp");
    dst.with_file_name(name)
}

fn restore_owner(path: &Path, md: &fs::Metadata) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    if let Ok(c) = CString::new(path.as_os_str().as_bytes()) {
        unsafe {
            // Best effort; requires privilege to change owner across users.
            libc::lchown(c.as_ptr(), md.uid(), md.gid());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mergerfs::{Branch, BranchMode};
    use crate::tier::{TierBranch, TierMap};
    use std::time::Duration;

    fn t(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn tmpdir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("mtier-test-{}-{}", std::process::id(), nanos));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn tiers(a: PathBuf, b: PathBuf) -> TierMap {
        TierMap {
            branches: vec![
                TierBranch {
                    branch: Branch {
                        path: a,
                        mode: BranchMode::ReadWrite,
                    },
                    tier: 0,
                    label: "fast".into(),
                },
                TierBranch {
                    branch: Branch {
                        path: b,
                        mode: BranchMode::ReadWrite,
                    },
                    tier: 1,
                    label: "slow".into(),
                },
            ],
            max_tier: 1,
        }
    }

    // A move must not reset the mtime of the file, the source directory, or a
    // freshly-created destination directory — otherwise mtime-ordered views of
    // the merged pool reshuffle on every cycle.
    #[test]
    fn move_preserves_file_and_directory_mtimes() {
        let root = tmpdir();
        let a = root.join("a");
        let b = root.join("b");
        fs::create_dir_all(a.join("sub")).unwrap();

        let file = a.join("sub/foo.txt");
        fs::write(&file, b"hello").unwrap();

        let file_mtime = t(1_000_000_000); // 2001
        let dir_mtime = t(1_100_000_000); // 2004
        set_times(&file, file_mtime, file_mtime).unwrap();
        set_times(&a.join("sub"), dir_mtime, dir_mtime).unwrap();

        let map = tiers(a.clone(), b.clone());
        let mv = Move {
            rel: PathBuf::from("sub/foo.txt"),
            size: 5,
            src_branch_idx: 0,
            dst_branch_idx: 1,
            atime: file_mtime,
            mtime: file_mtime,
            reason: "test".into(),
        };

        let stats = Dispatcher::new(&map, false).run(&[mv]);
        assert_eq!(stats.moved, 1);
        assert_eq!(stats.failed, 0);

        // File landed with its mtime intact.
        let moved = b.join("sub/foo.txt");
        assert!(moved.exists(), "file should be on the slow branch");
        assert!(!file.exists(), "source file should be gone");
        let got = fs::metadata(&moved).unwrap().modified().unwrap();
        assert_eq!(got, file_mtime, "file mtime must be preserved");

        // The directory created on the destination branch inherits the source
        // directory's mtime, not "now".
        let dst_dir = fs::metadata(b.join("sub")).unwrap().modified().unwrap();
        assert_eq!(
            dst_dir, dir_mtime,
            "new dest dir should inherit source dir mtime"
        );

        // The source directory, bumped by the unlink, was restored.
        let src_dir = fs::metadata(a.join("sub")).unwrap().modified().unwrap();
        assert_eq!(src_dir, dir_mtime, "source dir mtime must be restored");

        let _ = fs::remove_dir_all(&root);
    }
}
