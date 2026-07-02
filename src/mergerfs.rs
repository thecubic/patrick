//! Detection of a live mergerfs mount: its branches, branch modes, and the
//! mount options relevant to tiering.
//!
//! Primary source is the runtime control interface exposed by mergerfs itself:
//! the pseudo file `<mount>/.mergerfs` carries `user.mergerfs.*` xattrs that
//! report the *current* configuration, including any branches added or removed
//! at runtime. If that is unavailable we fall back to scanning `/proc` for the
//! mergerfs process backing the mount and parsing its command line, and to
//! `/proc/self/mountinfo` for the source/options fields.

use crate::util::{getxattr_str, parse_size};
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Read/write/no-create mode of a branch as reported by mergerfs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchMode {
    ReadWrite,
    ReadOnly,
    NoCreate,
}

impl BranchMode {
    fn parse(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "RO" => BranchMode::ReadOnly,
            "NC" => BranchMode::NoCreate,
            _ => BranchMode::ReadWrite,
        }
    }
    /// Whether the daemon may place freshly demoted files on this branch.
    pub fn writable(self) -> bool {
        matches!(self, BranchMode::ReadWrite)
    }
}

#[derive(Debug, Clone)]
pub struct Branch {
    pub path: PathBuf,
    pub mode: BranchMode,
}

#[derive(Debug, Clone)]
pub struct MergerfsMount {
    pub mountpoint: PathBuf,
    pub branches: Vec<Branch>,
    /// `minfreespace` in bytes (mergerfs default is 4 GiB if unknown).
    pub minfreespace: u64,
    /// Raw option string as seen in mountinfo, for diagnostics.
    pub raw_options: BTreeMap<String, Option<String>>,
}

const DEFAULT_MINFREESPACE: u64 = 4 * 1024 * 1024 * 1024;

/// Detect the mergerfs configuration backing `mountpoint`.
pub fn detect(mountpoint: &Path) -> Result<MergerfsMount> {
    let mountpoint = mountpoint
        .canonicalize()
        .with_context(|| format!("mountpoint {} does not exist", mountpoint.display()))?;

    verify_is_mergerfs(&mountpoint)?;

    // 1. Authoritative: the runtime control xattrs.
    if let Some(m) = from_runtime_xattrs(&mountpoint) {
        if !m.branches.is_empty() {
            return Ok(m);
        }
    }

    // 2. Fallback: the backing process command line.
    let opts = mountinfo_options(&mountpoint).unwrap_or_default();
    if let Some(pid) = find_backing_pid(&mountpoint)? {
        if let Some(mut m) = from_cmdline(&mountpoint, pid)? {
            m.raw_options = opts;
            if m.minfreespace == 0 {
                m.minfreespace = minfreespace_from_opts(&m.raw_options);
            }
            return Ok(m);
        }
    }

    // 3. Last resort: the mountinfo source field.
    if let Some(src) = mountinfo_source(&mountpoint)? {
        let branches = parse_branches(&src);
        if !branches.is_empty() {
            return Ok(MergerfsMount {
                mountpoint,
                branches,
                minfreespace: minfreespace_from_opts(&opts),
                raw_options: opts,
            });
        }
    }

    bail!(
        "could not determine mergerfs branches for {}",
        mountpoint.display()
    )
}

fn verify_is_mergerfs(mountpoint: &Path) -> Result<()> {
    let mi = fs::read_to_string("/proc/self/mountinfo").context("reading /proc/self/mountinfo")?;
    let want = mountpoint.to_string_lossy();
    for line in mi.lines() {
        if let Some(entry) = MountInfoLine::parse(line) {
            if entry.mount_point == want {
                if entry.fstype == "fuse.mergerfs" || entry.fstype == "mergerfs" {
                    return Ok(());
                }
                bail!(
                    "{} is mounted but is {} not mergerfs",
                    mountpoint.display(),
                    entry.fstype
                );
            }
        }
    }
    bail!("{} is not a mount point", mountpoint.display())
}

fn from_runtime_xattrs(mountpoint: &Path) -> Option<MergerfsMount> {
    let ctl = mountpoint.join(".mergerfs");
    let branches_raw = getxattr_str(&ctl, "user.mergerfs.branches")?;
    let branches = parse_branches(&branches_raw);
    let minfreespace = getxattr_str(&ctl, "user.mergerfs.minfreespace")
        .and_then(|s| parse_size(&s).ok())
        .unwrap_or(DEFAULT_MINFREESPACE);
    Some(MergerfsMount {
        mountpoint: mountpoint.to_path_buf(),
        branches,
        minfreespace,
        raw_options: BTreeMap::new(),
    })
}

/// Parse a mergerfs branches string: colon-separated, each entry optionally
/// suffixed with `=RW|RO|NC`, and possibly containing shell globs.
fn parse_branches(s: &str) -> Vec<Branch> {
    let mut out = Vec::new();
    for entry in s.split(':') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (path_part, mode) = match entry.rsplit_once('=') {
            Some((p, m)) if matches!(m.to_ascii_uppercase().as_str(), "RW" | "RO" | "NC") => {
                (p, BranchMode::parse(m))
            }
            _ => (entry, BranchMode::ReadWrite),
        };
        for p in expand_glob(path_part) {
            out.push(Branch { path: p, mode });
        }
    }
    // De-duplicate while preserving order (tier order is meaningful).
    let mut seen = std::collections::HashSet::new();
    out.retain(|b| seen.insert(b.path.clone()));
    out
}

/// Minimal glob expansion for branch specs (only a trailing `*` on the final
/// component is commonly used by mergerfs configs, but we handle a single `*`
/// anywhere in the basename).
fn expand_glob(pattern: &str) -> Vec<PathBuf> {
    if !pattern.contains('*') {
        return vec![PathBuf::from(pattern)];
    }
    let p = Path::new(pattern);
    let (dir, name) = match (p.parent(), p.file_name()) {
        (Some(d), Some(n)) => (d.to_path_buf(), n.to_string_lossy().into_owned()),
        _ => return vec![PathBuf::from(pattern)],
    };
    let mut matches = Vec::new();
    if let Ok(rd) = fs::read_dir(&dir) {
        for ent in rd.flatten() {
            let fname = ent.file_name();
            if glob_match(&name, &fname.to_string_lossy()) {
                matches.push(ent.path());
            }
        }
    }
    matches.sort();
    if matches.is_empty() {
        vec![PathBuf::from(pattern)]
    } else {
        matches
    }
}

/// `*`-only glob match (single wildcard splitting prefix/suffix).
fn glob_match(pat: &str, name: &str) -> bool {
    if let Some((pre, suf)) = pat.split_once('*') {
        name.len() >= pre.len() + suf.len() && name.starts_with(pre) && name.ends_with(suf)
    } else {
        pat == name
    }
}

fn minfreespace_from_opts(opts: &BTreeMap<String, Option<String>>) -> u64 {
    opts.get("minfreespace")
        .and_then(|v| v.as_deref())
        .and_then(|s| parse_size(s).ok())
        .unwrap_or(DEFAULT_MINFREESPACE)
}

// ---- /proc fallbacks ----------------------------------------------------------

struct MountInfoLine<'a> {
    mount_point: String,
    fstype: &'a str,
    source: &'a str,
    super_opts: &'a str,
}

impl<'a> MountInfoLine<'a> {
    /// mountinfo format: fields before " - " are mount fields; after are
    /// fstype, source, super-options.
    fn parse(line: &'a str) -> Option<MountInfoLine<'a>> {
        let (left, right) = line.split_once(" - ")?;
        let lf: Vec<&str> = left.split_whitespace().collect();
        let rf: Vec<&str> = right.split_whitespace().collect();
        if lf.len() < 5 || rf.len() < 2 {
            return None;
        }
        Some(MountInfoLine {
            mount_point: unescape_octal(lf[4]),
            fstype: rf[0],
            source: rf[1],
            super_opts: rf.get(2).copied().unwrap_or(""),
        })
    }
}

/// mountinfo escapes space/tab/newline/backslash as octal `\NNN`.
fn unescape_octal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            if let Ok(code) = u8::from_str_radix(&s[i + 1..i + 4], 8) {
                out.push(code as char);
                i += 4;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

fn mountinfo_source(mountpoint: &Path) -> Result<Option<String>> {
    let mi = fs::read_to_string("/proc/self/mountinfo")?;
    let want = mountpoint.to_string_lossy();
    for line in mi.lines() {
        if let Some(e) = MountInfoLine::parse(line) {
            if e.mount_point == want {
                return Ok(Some(e.source.to_string()));
            }
        }
    }
    Ok(None)
}

fn mountinfo_options(mountpoint: &Path) -> Option<BTreeMap<String, Option<String>>> {
    let mi = fs::read_to_string("/proc/self/mountinfo").ok()?;
    let want = mountpoint.to_string_lossy();
    for line in mi.lines() {
        if let Some(e) = MountInfoLine::parse(line) {
            if e.mount_point == want {
                return Some(parse_opt_string(e.super_opts));
            }
        }
    }
    None
}

fn parse_opt_string(s: &str) -> BTreeMap<String, Option<String>> {
    let mut m = BTreeMap::new();
    for kv in s.split(',') {
        if kv.is_empty() {
            continue;
        }
        match kv.split_once('=') {
            Some((k, v)) => {
                m.insert(k.to_string(), Some(v.to_string()));
            }
            None => {
                m.insert(kv.to_string(), None);
            }
        }
    }
    m
}

/// Find the pid of the mergerfs process serving `mountpoint` by scanning
/// `/proc/*/cmdline` for a mergerfs invocation that names the mountpoint.
fn find_backing_pid(mountpoint: &Path) -> Result<Option<i32>> {
    let want = mountpoint.to_string_lossy().to_string();
    for ent in fs::read_dir("/proc")?.flatten() {
        let name = ent.file_name();
        let pid: i32 = match name.to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let cmd = match fs::read(ent.path().join("cmdline")) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let args: Vec<String> = cmd
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        if args.is_empty() {
            continue;
        }
        let exe = Path::new(&args[0])
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if exe != "mergerfs" {
            continue;
        }
        if args.iter().any(|a| a == &want) {
            return Ok(Some(pid));
        }
    }
    Ok(None)
}

fn from_cmdline(mountpoint: &Path, pid: i32) -> Result<Option<MergerfsMount>> {
    let cmd = fs::read(format!("/proc/{pid}/cmdline"))?;
    let args: Vec<String> = cmd
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();

    // Positional args (excluding flags and their values) are <branches> <mount>.
    let mut positionals = Vec::new();
    let mut opt_string = String::new();
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        if a == "-o" {
            if let Some(v) = args.get(i + 1) {
                opt_string.push_str(v);
                opt_string.push(',');
            }
            i += 2;
            continue;
        }
        if let Some(rest) = a.strip_prefix("-o") {
            opt_string.push_str(rest);
            opt_string.push(',');
            i += 1;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        positionals.push(a.clone());
        i += 1;
    }

    let want = mountpoint.to_string_lossy();
    let branch_spec = positionals
        .iter()
        .find(|p| p.as_str() != want)
        .cloned()
        .or_else(|| positionals.first().cloned());

    let branches = branch_spec.map(|s| parse_branches(&s)).unwrap_or_default();
    if branches.is_empty() {
        return Ok(None);
    }
    let opts = parse_opt_string(&opt_string);
    Ok(Some(MergerfsMount {
        mountpoint: mountpoint.to_path_buf(),
        branches,
        minfreespace: minfreespace_from_opts(&opts),
        raw_options: opts,
    }))
}
