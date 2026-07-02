use std::collections::{HashMap, HashSet};
use std::io;
use std::path::PathBuf;

use crate::config::{Config, Rule};
use crate::policy::TieringPolicy;
use crate::scan::FileMeta;
use crate::util::{fmt_bytes, fs_usage};

#[derive(Debug, Clone)]
pub struct Branch {
    pub tier: usize,
    pub path: PathBuf,
}

/// Flatten config tiers into a single branch list.
pub fn flatten_branches(cfg: &Config) -> Vec<Branch> {
    let mut v = Vec::new();
    for (ti, t) in cfg.tiers.iter().enumerate() {
        for p in &t.branches {
            v.push(Branch {
                tier: ti,
                path: p.clone(),
            });
        }
    }
    v
}

#[derive(Debug)]
pub struct Move {
    pub rel: PathBuf,
    pub from: usize, // branch index
    pub to: usize,   // branch index
    pub size: u64,
    pub reason: &'static str,
}

struct PlanState<'a> {
    cfg: &'a Config,
    branches: &'a [Branch],
    free: Vec<u64>,     // current free bytes per branch
    total: Vec<u64>,    // fs size per branch
    incoming: Vec<u64>, // bytes planned INTO each branch this pass
    outgoing: Vec<u64>, // bytes planned OUT of each branch this pass
    planned: HashMap<PathBuf, usize>, // rel -> destination tier
    moves: Vec<Move>,
    budget: Option<i64>,
}

impl<'a> PlanState<'a> {
    fn eff_tier(&self, f: &FileMeta) -> usize {
        self.planned
            .get(&f.rel)
            .copied()
            .unwrap_or(self.branches[f.branch].tier)
    }

    /// Pick the destination branch within a tier: most projected free space,
    /// and must keep `min_free` headroom after receiving the file.
    fn choose_branch(&self, tier: usize, size: u64) -> Option<usize> {
        self.branches
            .iter()
            .enumerate()
            .filter(|(_, b)| b.tier == tier)
            .map(|(i, _)| (i, self.free[i].saturating_sub(self.incoming[i])))
            .filter(|(_, proj_free)| *proj_free >= size.saturating_add(self.cfg.min_free))
            .max_by_key(|(_, proj_free)| *proj_free)
            .map(|(i, _)| i)
    }

    /// Projected (used, total) bytes for a tier after the plan so far.
    fn tier_projected(&self, tier: usize) -> (u64, u64) {
        let mut used = 0u64;
        let mut total = 0u64;
        for (i, b) in self.branches.iter().enumerate() {
            if b.tier != tier {
                continue;
            }
            total += self.total[i];
            used += (self.total[i].saturating_sub(self.free[i]))
                .saturating_add(self.incoming[i])
                .saturating_sub(self.outgoing[i]);
        }
        (used, total)
    }

    fn plan(&mut self, f: &FileMeta, to_tier: usize, reason: &'static str) -> bool {
        if self.planned.contains_key(&f.rel) {
            return false;
        }
        if self.branches[f.branch].tier == to_tier {
            return false;
        }
        if let Some(b) = self.budget {
            if (f.size as i64) > b {
                return false;
            }
        }
        let dst = match self.choose_branch(to_tier, f.size) {
            Some(d) => d,
            None => {
                log::debug!(
                    "no room in tier {:?} for {} ({})",
                    self.cfg.tiers[to_tier].name,
                    f.rel.display(),
                    fmt_bytes(f.size)
                );
                return false;
            }
        };
        self.incoming[dst] += f.size;
        self.outgoing[f.branch] += f.size;
        if let Some(b) = self.budget.as_mut() {
            *b -= f.size as i64;
        }
        self.planned.insert(f.rel.clone(), to_tier);
        self.moves.push(Move {
            rel: f.rel.clone(),
            from: f.branch,
            to: dst,
            size: f.size,
            reason,
        });
        true
    }
}

fn demotable(f: &FileMeta, rule: Option<&Rule>, now: i64, cooldown: i64) -> bool {
    if f.nlink != 1 {
        return false; // moving would break the hardlink
    }
    if now - f.mtime < cooldown {
        return false; // possibly still being written
    }
    if let Some(r) = rule {
        if r.pin.is_some() {
            return false;
        }
        if let Some(keep) = r.keep_secs {
            if now - f.atime < keep {
                return false; // protected by keep_at_least window
            }
        }
    }
    true
}

pub fn build_plan(
    cfg: &Config,
    branches: &[Branch],
    files: &[FileMeta],
    policy: &dyn TieringPolicy,
    now: i64,
) -> io::Result<Vec<Move>> {
    let last = cfg.tiers.len() - 1;
    let cooldown = cfg.mtime_cooldown_secs;

    let mut free = Vec::with_capacity(branches.len());
    let mut total = Vec::with_capacity(branches.len());
    for b in branches {
        let u = fs_usage(&b.path).map_err(|e| {
            io::Error::new(e.kind(), format!("statvfs {} failed: {e}", b.path.display()))
        })?;
        free.push(u.free);
        total.push(u.total);
    }

    // Files present on more than one branch are ambiguous; never touch them.
    let mut dup: HashSet<&std::path::Path> = HashSet::new();
    {
        let mut seen: HashSet<&std::path::Path> = HashSet::new();
        for f in files {
            if !seen.insert(f.rel.as_path()) {
                dup.insert(f.rel.as_path());
            }
        }
        for d in &dup {
            log::warn!("{} exists on multiple branches; leaving it alone", d.display());
        }
    }

    // Resolve each file's rule once (longest-prefix match).
    let rule_of: Vec<Option<&Rule>> = files.iter().map(|f| cfg.find_rule(&f.rel)).collect();

    let mut st = PlanState {
        cfg,
        branches,
        free,
        total,
        incoming: vec![0; branches.len()],
        outgoing: vec![0; branches.len()],
        planned: HashMap::new(),
        moves: Vec::new(),
        budget: cfg.max_move_per_pass.map(|b| b as i64),
    };

    let temp = |f: &FileMeta| policy.temperature(f, now);
    fn sorted_cold_first<'f>(
        mut v: Vec<&'f FileMeta>,
        temp: &dyn Fn(&FileMeta) -> i64,
    ) -> Vec<&'f FileMeta> {
        v.sort_by_key(|f| temp(f));
        v
    }

    // -- 1. Pins: gather strays onto the pinned tier (either direction). ----
    for (f, r) in files.iter().zip(&rule_of) {
        if let Some(rule) = r {
            if let Some(t) = rule.pin {
                if st.eff_tier(f) != t && f.nlink == 1 && !dup.contains(f.rel.as_path()) {
                    st.plan(f, t, "pin");
                }
            }
        }
    }

    // -- 2. Aggressive subtrees: push down regardless of watermarks. --------
    {
        let cands: Vec<&FileMeta> = files
            .iter()
            .zip(&rule_of)
            .filter(|(f, r)| {
                r.and_then(|r| r.aggressive_target)
                    .map_or(false, |t| st.eff_tier(f) < t)
                    && demotable(f, **r, now, cooldown)
                    && !dup.contains(f.rel.as_path())
            })
            .map(|(f, _)| f)
            .collect();
        for f in sorted_cold_first(cands, &temp) {
            let t = cfg.find_rule(&f.rel).and_then(|r| r.aggressive_target).unwrap();
            st.plan(f, t, "aggressive");
        }
    }

    // -- 3. Quotas: cap subtree footprint on the fast tiers. -----------------
    for (ri, rule) in cfg.rules.iter().enumerate() {
        let quota = match rule.quota {
            Some(q) => q,
            None => continue,
        };
        // A file belongs to this rule only if it is its longest-prefix match.
        let mine = |i: usize| -> bool {
            rule_of[i].map_or(false, |r| std::ptr::eq(r, &cfg.rules[ri]))
        };
        let mut usage: u64 = files
            .iter()
            .enumerate()
            .filter(|(i, f)| mine(*i) && st.eff_tier(f) < last)
            .map(|(_, f)| f.size)
            .sum();
        if usage <= quota {
            continue;
        }
        log::info!(
            "quota /{}: {} used of {} allowed on fast tiers",
            rule.rel.display(),
            fmt_bytes(usage),
            fmt_bytes(quota)
        );
        let cands: Vec<&FileMeta> = files
            .iter()
            .enumerate()
            .filter(|(i, f)| {
                mine(*i)
                    && st.eff_tier(f) < last
                    && demotable(f, rule_of[*i], now, cooldown)
                    && !dup.contains(f.rel.as_path())
            })
            .map(|(_, f)| f)
            .collect();
        for f in sorted_cold_first(cands, &temp) {
            if usage <= quota {
                break;
            }
            if st.plan(f, last, "quota") {
                usage = usage.saturating_sub(f.size);
            }
        }
    }

    // -- 4. keep_at_least: promote recently-used files back to tier 0. ------
    {
        let mut cands: Vec<&FileMeta> = files
            .iter()
            .zip(&rule_of)
            .filter(|(f, r)| {
                r.and_then(|r| r.keep_secs)
                    .map_or(false, |k| now - f.atime < k)
                    && st.eff_tier(f) > 0
                    && f.nlink == 1
                    && now - f.mtime >= cooldown
                    && !dup.contains(f.rel.as_path())
            })
            .map(|(f, _)| f)
            .collect();
        cands.sort_by_key(|f| std::cmp::Reverse(temp(f))); // hottest first
        let high0 = st.tier_projected(0).1 / 100 * cfg.tiers[0].high as u64;
        for f in cands {
            let (used, _) = st.tier_projected(0);
            if used.saturating_add(f.size) > high0 {
                break; // don't promote past the high watermark
            }
            st.plan(f, 0, "keep-promote");
        }
    }

    // -- 5. Watermarks: per-tier pressure relief, coldest first. ------------
    for t in 0..last {
        let (used, tot) = st.tier_projected(t);
        if tot == 0 {
            continue;
        }
        let high = tot / 100 * cfg.tiers[t].high as u64;
        let low = tot / 100 * cfg.tiers[t].low as u64;
        if used <= high {
            continue;
        }
        log::info!(
            "tier {:?} at {} of {} ({}% > high {}%), demoting",
            cfg.tiers[t].name,
            fmt_bytes(used),
            fmt_bytes(tot),
            used * 100 / tot,
            cfg.tiers[t].high
        );
        let cands: Vec<&FileMeta> = files
            .iter()
            .enumerate()
            .filter(|(i, f)| {
                st.eff_tier(f) == t
                    && branches[f.branch].tier == t // not a file merely planned into t
                    && demotable(f, rule_of[*i], now, cooldown)
                    && !dup.contains(f.rel.as_path())
            })
            .map(|(_, f)| f)
            .collect();
        for f in sorted_cold_first(cands, &temp) {
            let (used, _) = st.tier_projected(t);
            if used <= low {
                break;
            }
            st.plan(f, t + 1, "watermark");
        }
    }

    Ok(st.moves)
}
