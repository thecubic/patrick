//! Tier ordering over mergerfs branches.
//!
//! mergerfs branch order is not inherently a speed ranking, so tiers are
//! assigned explicitly from config when provided. Tier 0 is the fastest;
//! "demote" means moving to a higher tier index. When config gives no tier
//! mapping, branch order is used as the ranking (first branch = fastest).

use crate::config::TierSpec;
use crate::mergerfs::{Branch, MergerfsMount};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct TierBranch {
    pub branch: Branch,
    pub tier: usize,
    pub label: String,
}

#[derive(Debug, Clone)]
pub struct TierMap {
    pub branches: Vec<TierBranch>,
    pub max_tier: usize,
}

impl TierMap {
    pub fn build(mount: &MergerfsMount, specs: &[TierSpec]) -> TierMap {
        let mut branches = Vec::with_capacity(mount.branches.len());
        for (idx, b) in mount.branches.iter().enumerate() {
            let (tier, label) = assign(&b.path, idx, specs);
            branches.push(TierBranch {
                branch: b.clone(),
                tier,
                label,
            });
        }
        let max_tier = branches.iter().map(|b| b.tier).max().unwrap_or(0);
        TierMap { branches, max_tier }
    }

    pub fn branch(&self, idx: usize) -> &TierBranch {
        &self.branches[idx]
    }

    /// Indices of branches at a given tier.
    pub fn at_tier(&self, tier: usize) -> impl Iterator<Item = usize> + '_ {
        self.branches
            .iter()
            .enumerate()
            .filter(move |(_, b)| b.tier == tier)
            .map(|(i, _)| i)
    }
}

fn assign(path: &Path, order_idx: usize, specs: &[TierSpec]) -> (usize, String) {
    if specs.is_empty() {
        return (order_idx, format!("tier{order_idx}"));
    }
    for spec in specs {
        if spec.paths.iter().any(|p| path_matches(path, p)) {
            return (spec.level, spec.label.clone().unwrap_or_else(|| format!("tier{}", spec.level)));
        }
    }
    // Unmatched branches sink below all configured tiers.
    let fallback = specs.iter().map(|s| s.level).max().unwrap_or(0) + 1;
    (fallback, format!("tier{fallback}"))
}

fn path_matches(path: &Path, spec: &str) -> bool {
    let ps = path.to_string_lossy();
    if let Some(prefix) = spec.strip_suffix("/*").or_else(|| spec.strip_suffix('*')) {
        ps.starts_with(prefix)
    } else {
        ps == spec || path == Path::new(spec)
    }
}
