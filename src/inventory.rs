//! Filesystem inventory: every regular-file instance living directly on a
//! branch, recorded with the metadata the policies need.

use crate::tier::TierMap;
use anyhow::Result;
use std::path::PathBuf;
use std::time::SystemTime;
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct FileInstance {
    /// Path relative to the branch root (no leading slash).
    pub rel: PathBuf,
    pub branch_idx: usize,
    pub tier: usize,
    pub size: u64,
    pub atime: SystemTime,
    pub mtime: SystemTime,
}

pub struct Inventory {
    pub files: Vec<FileInstance>,
}

impl Inventory {
    pub fn scan(tiers: &TierMap, excludes: &[String]) -> Result<Inventory> {
        let mut files = Vec::new();
        for (branch_idx, tb) in tiers.branches.iter().enumerate() {
            let root = &tb.branch.path;
            if !root.exists() {
                log::warn!("branch {} does not exist; skipping", root.display());
                continue;
            }
            for entry in WalkDir::new(root)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let md = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if !md.is_file() {
                    continue;
                }
                let rel = match entry.path().strip_prefix(root) {
                    Ok(r) => r.to_path_buf(),
                    Err(_) => continue,
                };
                let rel_str = rel.to_string_lossy();
                if excludes.iter().any(|g| glob_contains(g, &rel_str)) {
                    continue;
                }
                files.push(FileInstance {
                    rel,
                    branch_idx,
                    tier: tb.tier,
                    size: md.len(),
                    atime: md.accessed().unwrap_or(SystemTime::UNIX_EPOCH),
                    mtime: md.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                });
            }
        }
        Ok(Inventory { files })
    }
}

/// Simple `*`-glob containment used for exclude rules (matches whole rel path).
fn glob_contains(pat: &str, name: &str) -> bool {
    if let Some((pre, suf)) = pat.split_once('*') {
        name.starts_with(pre) && name.ends_with(suf) && name.len() >= pre.len() + suf.len()
    } else {
        pat == name
    }
}
