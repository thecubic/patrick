use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use crate::plan::Branch;
use crate::util::{unix_now, Watchdog};

pub const TMP_PREFIX: &str = ".tierd.tmp.";

#[derive(Debug)]
pub struct FileMeta {
    /// Path relative to the branch root == path within the merged view.
    pub rel: PathBuf,
    /// Index into the flattened branch list.
    pub branch: usize,
    pub size: u64,
    pub atime: i64,
    pub mtime: i64,
    pub nlink: u64,
}

/// Walk every branch and collect regular files. Symlinks and special files
/// are left alone. Stale temp files from a crashed previous run are removed
/// (unless `dry_run`).
pub fn scan_branches(
    branches: &[Branch],
    wd: &Watchdog,
    dry_run: bool,
) -> io::Result<Vec<FileMeta>> {
    let now = unix_now();
    let mut out = Vec::new();

    for (bi, b) in branches.iter().enumerate() {
        // A missing branch root is a hard error: planning against a partial
        // view could trigger a mass migration.
        let mut stack = vec![b.path.clone()];
        let mut first = true;

        while let Some(dir) = stack.pop() {
            wd.tick();
            let rd = match fs::read_dir(&dir) {
                Ok(rd) => rd,
                Err(e) => {
                    if first {
                        return Err(io::Error::new(
                            e.kind(),
                            format!("branch {} unreadable: {e}", b.path.display()),
                        ));
                    }
                    // Subdirectory vanished mid-scan or is unreadable: skip.
                    log::warn!("skipping {}: {e}", dir.display());
                    continue;
                }
            };
            first = false;

            for ent in rd {
                let ent = match ent {
                    Ok(e) => e,
                    Err(e) => {
                        log::warn!("readdir error under {}: {e}", dir.display());
                        continue;
                    }
                };
                let path = ent.path();
                // DirEntry::metadata() does not traverse symlinks.
                let md = match ent.metadata() {
                    Ok(m) => m,
                    Err(e) => {
                        log::warn!("stat {} failed: {e}", path.display());
                        continue;
                    }
                };
                let ft = md.file_type();
                if ft.is_dir() {
                    stack.push(path);
                    continue;
                }
                if !ft.is_file() {
                    continue;
                }
                let name = ent.file_name();
                if name.to_string_lossy().starts_with(TMP_PREFIX) {
                    // Leftover from an interrupted copy; remove if old.
                    if now - md.mtime() > 86_400 && !dry_run {
                        log::info!("removing stale temp file {}", path.display());
                        let _ = fs::remove_file(&path);
                    }
                    continue;
                }
                let rel = match path.strip_prefix(&b.path) {
                    Ok(r) => r.to_path_buf(),
                    Err(_) => continue,
                };
                out.push(FileMeta {
                    rel,
                    branch: bi,
                    size: md.size(),
                    atime: md.atime(),
                    mtime: md.mtime(),
                    nlink: md.nlink(),
                });
            }
        }
    }
    Ok(out)
}
