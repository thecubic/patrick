//! Configuration schema

use crate::util::{parse_duration, parse_size};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Operation order inside of a correction pass
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DispatchSorting {
    #[default]
    AscendingAccess,
    DescendingAccess,
    AscendingModification,
    DescendingModification,
    AscendingSize,
    DescendingSize,
}

// ---- raw (deserialized) schema -----------------------------------------------

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    pub mount: Option<String>,
    pub interval: Option<String>,
    pub policy: Option<String>,
    pub max_move_bytes_per_cycle: Option<String>,
    pub settle: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default, rename = "tier")]
    pub tiers: Vec<RawTier>,
    #[serde(default, rename = "rule")]
    pub rules: Vec<RawRule>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTier {
    pub level: usize,
    pub label: Option<String>,
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRule {
    /// Subtree path relative to the mount root, NO leading slash.
    /// Absent ⇒ this is the default rule.
    pub path: Option<String>,
    pub quota: Option<String>,
    /// Files on tiers ≤ this index count toward the quota (default 0).
    pub quota_max_tier: Option<usize>,
    /// Keep files accessed within this window on fast storage (pin).
    pub min_age: Option<String>,
    /// Eagerly demote files older than this regardless of quota.
    pub max_age: Option<String>,
    /// Demote everything not pinned by `min_age` (equivalent to max_age=0).
    #[serde(default)]
    pub aggressive: bool,
    /// Destination tier for demotions (default: one tier slower).
    pub target_tier: Option<usize>,
    /// Never move files in this subtree.
    #[serde(default)]
    pub pin: bool,
    /// Move ordering for this subtree's quota/demotion pass.
    pub dispatch_sort: Option<DispatchSorting>,
    /// Cross-subtree ordering weight (higher = enforced earlier).
    #[serde(default)]
    pub priority: i32,
}

// ---- compiled forms ----------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TierSpec {
    pub level: usize,
    pub label: Option<String>,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    /// Empty for the default rule; otherwise the relative subtree path.
    pub path: PathBuf,
    pub quota: Option<u64>,
    pub quota_max_tier: usize,
    pub min_age: Option<Duration>,
    pub max_age: Option<Duration>,
    pub aggressive: bool,
    pub target_tier: Option<usize>,
    pub pin: bool,
    pub dispatch_sort: DispatchSorting,
    pub priority: i32,
    /// Number of path components, for longest-prefix matching.
    pub depth: usize,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub mount: Option<PathBuf>,
    pub interval: Duration,
    pub policy: String,
    pub max_move_bytes_per_cycle: Option<u64>,
    pub settle: Duration,
    pub dry_run: bool,
    pub tiers: Vec<TierSpec>,
    pub rules: Vec<Rule>,
    pub default_rule: Rule,
    pub exclude: Vec<String>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let raw: RawConfig =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        raw.compile()
    }

    pub fn defaults() -> Config {
        RawConfig::default()
            .compile()
            .expect("default config compiles")
    }

    /// Resolve the effective rule for a relative path: the deepest matching
    /// subtree rule, falling back to the default rule.
    pub fn rule_for(&self, rel: &Path) -> &Rule {
        let mut best: Option<&Rule> = None;
        for r in &self.rules {
            if path_under(rel, &r.path) {
                match best {
                    Some(b) if b.depth >= r.depth => {}
                    _ => best = Some(r),
                }
            }
        }
        best.unwrap_or(&self.default_rule)
    }
}

impl RawConfig {
    pub fn compile(self) -> Result<Config> {
        let interval = self
            .interval
            .as_deref()
            .map(parse_duration)
            .transpose()?
            .unwrap_or(Duration::from_secs(300));
        let settle = self
            .settle
            .as_deref()
            .map(parse_duration)
            .transpose()?
            .unwrap_or(Duration::from_secs(300));
        let max_move = self
            .max_move_bytes_per_cycle
            .as_deref()
            .map(parse_size)
            .transpose()?;

        let tiers = self
            .tiers
            .into_iter()
            .map(|t| TierSpec {
                level: t.level,
                label: t.label,
                paths: t.paths,
            })
            .collect();

        // Separate the default (no `path`) rule from subtree rules.
        let mut default_raw: Option<RawRule> = None;
        let mut subtree_raw = Vec::new();
        for raw in self.rules {
            let is_default = raw.path.as_deref().map(|p| p.is_empty()).unwrap_or(true);
            if is_default {
                if default_raw.is_some() {
                    bail!("more than one default rule (a rule with no `path`) defined");
                }
                default_raw = Some(raw);
            } else {
                subtree_raw.push(raw);
            }
        }
        let default_rule = match default_raw {
            Some(raw) => compile_rule(raw, None)?,
            None => builtin_default_rule(),
        };
        let mut subtree_rules = Vec::with_capacity(subtree_raw.len());
        for raw in subtree_raw {
            subtree_rules.push(compile_rule(raw, Some(&default_rule))?);
        }
        subtree_rules.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then(b.depth.cmp(&a.depth))
                .then(a.path.cmp(&b.path))
        });

        Ok(Config {
            mount: self.mount.map(PathBuf::from),
            interval,
            policy: self.policy.unwrap_or_else(|| "access_time".to_string()),
            max_move_bytes_per_cycle: max_move,
            settle,
            dry_run: self.dry_run,
            tiers,
            rules: subtree_rules,
            default_rule,
            exclude: self.exclude,
        })
    }
}

fn builtin_default_rule() -> Rule {
    Rule {
        path: PathBuf::new(),
        quota: None,
        quota_max_tier: 0,
        min_age: None,
        max_age: None,
        aggressive: false,
        target_tier: None,
        pin: false,
        dispatch_sort: DispatchSorting::AscendingAccess,
        priority: 0,
        depth: 0,
    }
}

fn compile_rule(raw: RawRule, default: Option<&Rule>) -> Result<Rule> {
    let path_str = raw.path.unwrap_or_default();
    if path_str.starts_with('/') {
        bail!(
            "rule path {path_str:?} must be relative (no leading slash); the rule \
             with no path is the default that used to be \"/\""
        );
    }
    let is_default = path_str.is_empty();
    let path = PathBuf::from(&path_str);
    let depth = if is_default {
        0
    } else {
        path.components().count()
    };
    let dispatch_sort = raw
        .dispatch_sort
        .or_else(|| default.map(|d| d.dispatch_sort))
        .unwrap_or_default();
    Ok(Rule {
        path,
        quota: raw.quota.as_deref().map(parse_size).transpose()?,
        quota_max_tier: raw.quota_max_tier.unwrap_or(0),
        min_age: raw
            .min_age
            .as_deref()
            .map(parse_duration)
            .transpose()?
            .or_else(|| default.and_then(|d| d.min_age)),
        max_age: raw
            .max_age
            .as_deref()
            .map(parse_duration)
            .transpose()?
            .or_else(|| default.and_then(|d| d.max_age)),
        aggressive: raw.aggressive,
        target_tier: raw
            .target_tier
            .or_else(|| default.and_then(|d| d.target_tier)),
        pin: raw.pin,
        dispatch_sort,
        priority: raw.priority,
        depth,
    })
}

/// True if `rel` is at or below `base` (component-wise prefix). Empty base
/// (the default rule) matches everything.
fn path_under(rel: &Path, base: &Path) -> bool {
    if base.as_os_str().is_empty() {
        return true;
    }
    rel.starts_with(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile(toml: &str) -> Result<Config> {
        let raw: RawConfig = ::toml::from_str(toml).unwrap();
        raw.compile()
    }

    #[test]
    fn rejects_leading_slash() {
        let err = compile("[[rule]]\npath = \"/media\"\n").unwrap_err();
        assert!(err.to_string().contains("relative"), "{err}");
    }

    #[test]
    fn default_rule_is_pathless() {
        let c = compile("[[rule]]\nmin_age = \"7d\"\n").unwrap();
        assert!(c.default_rule.path.as_os_str().is_empty());
        assert_eq!(c.default_rule.min_age, Some(Duration::from_secs(7 * 86400)));
        // A path with no matching rule resolves to the default.
        let r = c.rule_for(Path::new("whatever/here"));
        assert!(r.path.as_os_str().is_empty());
    }

    #[test]
    fn rejects_two_default_rules() {
        let err = compile("[[rule]]\nmin_age=\"1d\"\n[[rule]]\nmax_age=\"2d\"\n").unwrap_err();
        assert!(err.to_string().contains("default rule"), "{err}");
    }

    #[test]
    fn subtree_inherits_default_dispatch_sort() {
        let c = compile(concat!(
            "[[rule]]\ndispatch_sort = \"descending_size\"\n",
            "[[rule]]\npath = \"media\"\nquota = \"1G\"\n",
        ))
        .unwrap();
        let r = c.rule_for(Path::new("media/x"));
        assert_eq!(r.dispatch_sort, DispatchSorting::DescendingSize);
    }

    #[test]
    fn longest_prefix_wins() {
        let c = compile(concat!(
            "[[rule]]\npath = \"a\"\nquota=\"1G\"\n",
            "[[rule]]\npath = \"a/b/c\"\nquota=\"2G\"\n",
        ))
        .unwrap();
        assert_eq!(
            c.rule_for(Path::new("a/b/c/f")).quota,
            Some(2 * 1024u64.pow(3))
        );
        assert_eq!(c.rule_for(Path::new("a/x")).quota, Some(1024u64.pow(3)));
    }
}
