//! Pluggable tiering policies.
//!
//! A policy inspects the inventory and current free space and returns an
//! ordered list of [`Move`]s. The daemon executes them in order, so a policy
//! expresses its dispatch priority simply by the order it emits moves.

pub mod access_time;

use crate::config::Config;
use crate::inventory::Inventory;
use crate::tier::TierMap;
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct Move {
    pub rel: PathBuf,
    pub size: u64,
    pub src_branch_idx: usize,
    pub dst_branch_idx: usize,
    pub atime: SystemTime,
    pub mtime: SystemTime,
    pub reason: String,
}

pub struct PolicyContext<'a> {
    pub config: &'a Config,
    pub tiers: &'a TierMap,
    pub inventory: &'a Inventory,
    pub minfreespace: u64,
    /// Free bytes per branch, indexed like `tiers.branches`.
    pub free: Vec<u64>,
    pub now: SystemTime,
}

pub trait TieringPolicy {
    fn name(&self) -> &str;
    fn plan(&self, ctx: &PolicyContext) -> Vec<Move>;
}

/// Resolve a policy by name. New algorithms register here.
pub fn by_name(name: &str) -> Option<Box<dyn TieringPolicy>> {
    match name {
        "access_time" | "atime" => Some(Box::new(access_time::AccessTimePolicy)),
        _ => None,
    }
}
