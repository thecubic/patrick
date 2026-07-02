//! Default policy: tier by access time.
//!
//! Three passes, all sharing one move budget:
//!   1. Eager demotion of files matched by `aggressive`/`max_age` rules.
//!   2. Per-subtree quota enforcement, dispatching moves in each subtree's
//!      configured `dispatch_sort` order (oldest-atime-first by default).
//!   3. `minfreespace` maintenance, demoting the coldest files off any branch
//!      that has dropped below the free-space floor.
//!
//! All passes work against a projected view of tiers and free space so that
//! cascading demotions and the move budget stay consistent.

use super::{Move, PolicyContext, TieringPolicy};
use crate::config::{DispatchSorting, Rule};
use std::cmp::Ordering;
use std::path::Path;
use std::time::{Duration, SystemTime};

pub struct AccessTimePolicy;

impl TieringPolicy for AccessTimePolicy {
    fn name(&self) -> &str {
        "access_time"
    }

    fn plan(&self, ctx: &PolicyContext) -> Vec<Move> {
        let mut p = Planner::new(ctx);
        p.eager_pass();
        p.quota_pass();
        p.minfreespace_pass();
        p.moves
    }
}

struct Planner<'a> {
    ctx: &'a PolicyContext<'a>,
    free: Vec<u64>,
    proj_tier: Vec<usize>,
    proj_branch: Vec<usize>,
    moved: Vec<bool>,
    moves: Vec<Move>,
    bytes_moved: u64,
    budget_exhausted: bool,
}

impl<'a> Planner<'a> {
    fn new(ctx: &'a PolicyContext<'a>) -> Self {
        let n = ctx.inventory.files.len();
        let mut proj_tier = Vec::with_capacity(n);
        let mut proj_branch = Vec::with_capacity(n);
        for f in &ctx.inventory.files {
            proj_tier.push(f.tier);
            proj_branch.push(f.branch_idx);
        }
        Planner {
            ctx,
            free: ctx.free.clone(),
            proj_tier,
            proj_branch,
            moved: vec![false; n],
            moves: Vec::new(),
            bytes_moved: 0,
            budget_exhausted: false,
        }
    }

    fn age(&self, t: SystemTime) -> Duration {
        self.ctx.now.duration_since(t).unwrap_or(Duration::ZERO)
    }

    fn rule_for(&self, rel: &Path) -> &Rule {
        self.ctx.config.rule_for(rel)
    }

    fn pinned(&self, idx: usize, rule: &Rule) -> bool {
        if rule.pin {
            return true;
        }
        // Files modified too recently are likely in use; let them settle.
        if self.age(self.ctx.inventory.files[idx].mtime) < self.ctx.config.settle {
            return true;
        }
        match rule.min_age {
            Some(min) => self.age(self.ctx.inventory.files[idx].atime) < min,
            None => false,
        }
    }

    /// Pick a destination branch on a tier `>= min_tier` with room for `size`.
    /// Cascades to slower tiers if the preferred tier is full.
    fn find_dest(&self, min_tier: usize, size: u64) -> Option<usize> {
        let need = size + self.ctx.minfreespace;
        for tier in min_tier..=self.ctx.tiers.max_tier {
            let mut best: Option<(usize, u64)> = None;
            for idx in self.ctx.tiers.at_tier(tier) {
                if !self.ctx.tiers.branch(idx).branch.mode.writable() {
                    continue;
                }
                if self.free[idx] >= need {
                    match best {
                        Some((_, bf)) if bf >= self.free[idx] => {}
                        _ => best = Some((idx, self.free[idx])),
                    }
                }
            }
            if let Some((idx, _)) = best {
                return Some(idx);
            }
        }
        None
    }

    /// Plan a demotion of file `idx` to a tier at or below `min_tier`.
    /// Returns true if a move was planned.
    fn demote(&mut self, idx: usize, min_tier: usize, reason: &str) -> bool {
        if self.budget_exhausted || self.moved[idx] {
            return false;
        }
        let f = &self.ctx.inventory.files[idx];
        if min_tier <= self.proj_tier[idx] {
            return false; // not actually slower
        }
        if let Some(limit) = self.ctx.config.max_move_bytes_per_cycle {
            if self.bytes_moved + f.size > limit {
                self.budget_exhausted = true;
                return false;
            }
        }
        let dst = match self.find_dest(min_tier, f.size) {
            Some(d) => d,
            None => return false,
        };
        let src = self.proj_branch[idx];
        if dst == src {
            return false;
        }
        self.free[src] = self.free[src].saturating_add(f.size);
        self.free[dst] = self.free[dst].saturating_sub(f.size);
        self.proj_tier[idx] = self.ctx.tiers.branch(dst).tier;
        self.proj_branch[idx] = dst;
        self.moved[idx] = true;
        self.bytes_moved += f.size;
        self.moves.push(Move {
            rel: f.rel.clone(),
            size: f.size,
            src_branch_idx: src,
            dst_branch_idx: dst,
            atime: f.atime,
            mtime: f.mtime,
            reason: reason.to_string(),
        });
        true
    }

    fn eager_pass(&mut self) {
        let mut candidates: Vec<usize> = Vec::new();
        for (idx, f) in self.ctx.inventory.files.iter().enumerate() {
            let rule = self.rule_for(&f.rel);
            if self.pinned(idx, rule) {
                continue;
            }
            let trigger =
                rule.aggressive || matches!(rule.max_age, Some(max) if self.age(f.atime) > max);
            if trigger {
                candidates.push(idx);
            }
        }
        // Coldest first.
        candidates.sort_by(|&a, &b| self.cmp_by(a, b, DispatchSorting::AscendingAccess));
        for idx in candidates {
            if self.budget_exhausted {
                break;
            }
            let rule = self.rule_for(&self.ctx.inventory.files[idx].rel).clone();
            let min_tier = rule
                .target_tier
                .unwrap_or(self.proj_tier[idx] + 1)
                .max(self.proj_tier[idx] + 1);
            self.demote(idx, min_tier, "eager");
        }
    }

    fn quota_pass(&mut self) {
        // Subtree rules (already sorted deepest/highest-priority first), then
        // the default rule as a whole-pool quota.
        let mut rules: Vec<Rule> = self
            .ctx
            .config
            .rules
            .iter()
            .filter(|r| r.quota.is_some())
            .cloned()
            .collect();
        if self.ctx.config.default_rule.quota.is_some() {
            rules.push(self.ctx.config.default_rule.clone());
        }
        for rule in rules {
            self.enforce_quota(&rule);
        }
    }

    fn enforce_quota(&mut self, rule: &Rule) {
        let quota = match rule.quota {
            Some(q) => q,
            None => return,
        };
        let max_tier = rule.quota_max_tier;
        let in_subtree = |rel: &Path| -> bool {
            rule.path.as_os_str().is_empty() || rel.starts_with(&rule.path)
        };

        let usage = |this: &Self| -> u64 {
            let mut sum = 0u64;
            for (idx, f) in this.ctx.inventory.files.iter().enumerate() {
                if this.proj_tier[idx] <= max_tier && in_subtree(&f.rel) {
                    sum += f.size;
                }
            }
            sum
        };

        if usage(self) <= quota {
            return;
        }

        let mut candidates: Vec<usize> = Vec::new();
        for (idx, f) in self.ctx.inventory.files.iter().enumerate() {
            if self.moved[idx] || self.proj_tier[idx] > max_tier || !in_subtree(&f.rel) {
                continue;
            }
            let eff = self.rule_for(&f.rel);
            if self.pinned(idx, eff) {
                continue;
            }
            candidates.push(idx);
        }
        candidates.sort_by(|&a, &b| self.cmp_by(a, b, rule.dispatch_sort));

        let target = rule.target_tier.unwrap_or(max_tier + 1).max(max_tier + 1);
        for idx in candidates {
            if self.budget_exhausted || usage(self) <= quota {
                break;
            }
            self.demote(idx, target, "quota");
        }
    }

    fn minfreespace_pass(&mut self) {
        let floor = self.ctx.minfreespace;
        // Fastest tiers first.
        let mut branch_order: Vec<usize> = (0..self.ctx.tiers.branches.len()).collect();
        branch_order.sort_by_key(|&i| self.ctx.tiers.branch(i).tier);

        let sort = self.ctx.config.default_rule.dispatch_sort;
        for b in branch_order {
            while self.free[b] < floor && !self.budget_exhausted {
                let mut candidates: Vec<usize> = Vec::new();
                for (idx, _f) in self.ctx.inventory.files.iter().enumerate() {
                    if self.moved[idx] || self.proj_branch[idx] != b {
                        continue;
                    }
                    let eff = self.rule_for(&self.ctx.inventory.files[idx].rel);
                    if self.pinned(idx, eff) {
                        continue;
                    }
                    candidates.push(idx);
                }
                if candidates.is_empty() {
                    break;
                }
                candidates.sort_by(|&x, &y| self.cmp_by(x, y, sort));
                let pick = candidates[0];
                let min_tier = self.proj_tier[pick] + 1;
                if !self.demote(pick, min_tier, "minfreespace") {
                    break; // nowhere slower to put it
                }
            }
        }
    }

    fn cmp_by(&self, a: usize, b: usize, sort: DispatchSorting) -> Ordering {
        let fa = &self.ctx.inventory.files[a];
        let fb = &self.ctx.inventory.files[b];
        match sort {
            DispatchSorting::AscendingAccess => fa.atime.cmp(&fb.atime),
            DispatchSorting::DescendingAccess => fb.atime.cmp(&fa.atime),
            DispatchSorting::AscendingModification => fa.mtime.cmp(&fb.mtime),
            DispatchSorting::DescendingModification => fb.mtime.cmp(&fa.mtime),
            DispatchSorting::AscendingSize => fa.size.cmp(&fb.size),
            DispatchSorting::DescendingSize => fb.size.cmp(&fa.size),
        }
        .then(fa.rel.cmp(&fb.rel))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, RawConfig};
    use crate::inventory::{FileInstance, Inventory};
    use crate::mergerfs::{Branch, BranchMode, MergerfsMount};
    use crate::tier::TierMap;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::time::Duration;

    fn cfg(toml: &str) -> Config {
        let raw: RawConfig = toml::from_str(toml).unwrap();
        raw.compile().unwrap()
    }

    fn mount() -> MergerfsMount {
        MergerfsMount {
            mountpoint: PathBuf::from("/pool"),
            branches: vec![
                Branch {
                    path: PathBuf::from("/b0"),
                    mode: BranchMode::ReadWrite,
                },
                Branch {
                    path: PathBuf::from("/b1"),
                    mode: BranchMode::ReadWrite,
                },
            ],
            minfreespace: 0,
            raw_options: BTreeMap::new(),
        }
    }

    fn file(rel: &str, branch: usize, tier: usize, size: u64, age_secs: u64) -> FileInstance {
        let now = SystemTime::now();
        let t = now - Duration::from_secs(age_secs);
        FileInstance {
            rel: PathBuf::from(rel),
            branch_idx: branch,
            tier,
            size,
            atime: t,
            mtime: t,
        }
    }

    fn plan(config: &Config, m: &MergerfsMount, files: Vec<FileInstance>) -> Vec<Move> {
        let tiers = TierMap::build(m, &config.tiers);
        let inv = Inventory { files };
        let free = vec![0u64, 1_000_000_000_000]; // b0 full-ish, b1 huge
        let ctx = PolicyContext {
            config,
            tiers: &tiers,
            inventory: &inv,
            minfreespace: 0,
            free,
            now: SystemTime::now(),
        };
        AccessTimePolicy.plan(&ctx)
    }

    const TIERS: &str = r#"
settle = "0s"
[[tier]]
level = 0
paths = ["/b0"]
[[tier]]
level = 1
paths = ["/b1"]
"#;

    #[test]
    fn quota_dispatch_oldest_first() {
        let config = cfg(&format!(
            r#"
{TIERS}
[[rule]]
path = "media"
quota = "300"
dispatch_sort = "ascending_access"
"#
        ));
        let m = mount();
        // 4 files of 100 each on tier0 → 400 used, quota 300 → must move 100 (1 file).
        let files = vec![
            file("media/a", 0, 0, 100, 10), // newest
            file("media/b", 0, 0, 100, 100),
            file("media/c", 0, 0, 100, 1000),
            file("media/d", 0, 0, 100, 10000), // oldest
        ];
        let moves = plan(&config, &m, files);
        assert_eq!(
            moves.len(),
            1,
            "should move exactly one file to satisfy quota"
        );
        assert_eq!(
            moves[0].rel,
            PathBuf::from("media/d"),
            "oldest dispatched first"
        );
        assert_eq!(moves[0].dst_branch_idx, 1);
    }

    #[test]
    fn quota_dispatch_descending_size() {
        let config = cfg(&format!(
            r#"
{TIERS}
[[rule]]
path = "media"
quota = "300"
dispatch_sort = "descending_size"
"#
        ));
        let m = mount();
        let files = vec![
            file("media/a", 0, 0, 50, 10),
            file("media/big", 0, 0, 250, 10),
            file("media/c", 0, 0, 50, 10),
            file("media/d", 0, 0, 50, 10),
        ]; // total 400, quota 300 → move 100; largest_first moves big(250) → under quota in one move
        let moves = plan(&config, &m, files);
        assert_eq!(moves.len(), 1);
        assert_eq!(moves[0].rel, PathBuf::from("media/big"));
    }

    #[test]
    fn min_age_pins_recent_files() {
        let config = cfg(&format!(
            r#"
{TIERS}
[[rule]]
path = "media"
quota = "0"
min_age = "1h"
dispatch_sort = "ascending_access"
"#
        ));
        let m = mount();
        // quota 0 means everything not pinned must leave tier0. Recent file is pinned.
        let files = vec![
            file("media/recent", 0, 0, 100, 60), // 1min old → pinned by min_age=1h
            file("media/old", 0, 0, 100, 7200),  // 2h old → eligible
        ];
        let moves = plan(&config, &m, files);
        assert_eq!(moves.len(), 1);
        assert_eq!(moves[0].rel, PathBuf::from("media/old"));
    }

    #[test]
    fn default_rule_applies_when_no_subtree_matches() {
        let config = cfg(&format!(
            r#"
{TIERS}
[[rule]]
quota = "150"
dispatch_sort = "ascending_access"
"#
        ));
        let m = mount();
        let files = vec![
            file("anything/x", 0, 0, 100, 10000),
            file("other/y", 0, 0, 100, 5),
        ]; // whole-pool quota 150, total 200 → move 50→ one file (oldest)
        let moves = plan(&config, &m, files);
        assert_eq!(moves.len(), 1);
        assert_eq!(moves[0].rel, PathBuf::from("anything/x"));
    }
}
