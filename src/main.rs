//! mergerfs-tier — storage-tiering daemon for mergerfs pools.

mod config;
mod dispatch;
mod inventory;
mod mergerfs;
mod policy;
mod tier;
mod util;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use config::Config;
use dispatch::Dispatcher;
use inventory::Inventory;
use policy::PolicyContext;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};
use tier::TierMap;

#[derive(Parser)]
#[command(name = "mergerfs-tier", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the tiering daemon (default operating mode).
    Run(RunArgs),
    /// Detect and print the branches, tiers, and options of a mergerfs mount.
    Detect(DetectArgs),
    /// Compute and print one tiering plan without moving anything.
    Plan(RunArgs),
}

#[derive(Parser)]
struct RunArgs {
    /// Path to the TOML config file.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// mergerfs mount point (overrides `mount` in config).
    #[arg(short, long)]
    mount: Option<PathBuf>,
    /// Plan but do not execute any moves.
    #[arg(long)]
    dry_run: bool,
    /// Run a single cycle and exit.
    #[arg(long)]
    once: bool,
}

#[derive(Parser)]
struct DetectArgs {
    /// mergerfs mount point.
    #[arg(short, long)]
    mount: PathBuf,
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Run(args) => run_daemon(args),
        Cmd::Detect(args) => detect(args),
        Cmd::Plan(args) => plan_once(args),
    };
    if let Err(e) = result {
        log::error!("{e:#}");
        std::process::exit(1);
    }
}

fn load_config(args: &RunArgs) -> Result<Config> {
    let mut cfg = match &args.config {
        Some(p) => Config::load(p)?,
        None => Config::defaults(),
    };
    if args.dry_run {
        cfg.dry_run = true;
    }
    Ok(cfg)
}

fn resolve_mount(cfg: &Config, cli_mount: &Option<PathBuf>) -> Result<PathBuf> {
    cli_mount
        .clone()
        .or_else(|| cfg.mount.clone())
        .context("no mount point given (use --mount or set `mount` in config)")
}

fn detect(args: DetectArgs) -> Result<()> {
    let m = mergerfs::detect(&args.mount)?;
    let cfg = Config::defaults();
    let tiers = TierMap::build(&m, &cfg.tiers);
    println!("mount:        {}", m.mountpoint.display());
    println!("minfreespace: {} bytes", m.minfreespace);
    if !m.raw_options.is_empty() {
        let opts: Vec<String> = m
            .raw_options
            .iter()
            .map(|(k, v)| match v {
                Some(v) => format!("{k}={v}"),
                None => k.clone(),
            })
            .collect();
        println!("options:      {}", opts.join(","));
    }
    println!("branches:");
    for tb in &tiers.branches {
        println!(
            "  [tier {} {}] {:?} {}",
            tb.tier,
            tb.label,
            tb.branch.mode,
            tb.branch.path.display()
        );
    }
    Ok(())
}

fn plan_once(mut args: RunArgs) -> Result<()> {
    args.dry_run = true;
    let cfg = load_config(&args)?;
    let mount = resolve_mount(&cfg, &args.mount)?;
    let m = mergerfs::detect(&mount)?;
    let tiers = TierMap::build(&m, &cfg.tiers);
    let moves = compute_plan(&cfg, &m, &tiers)?;
    if moves.is_empty() {
        println!("no moves planned");
        return Ok(());
    }
    println!("{} move(s) planned:", moves.len());
    for mv in &moves {
        println!(
            "  {:>12} {} : {} -> {}",
            mv.reason,
            mv.rel.display(),
            tiers.branch(mv.src_branch_idx).label,
            tiers.branch(mv.dst_branch_idx).label,
        );
    }
    Ok(())
}

fn run_daemon(args: RunArgs) -> Result<()> {
    util::install_signal_handlers();
    let cfg = load_config(&args)?;
    let mount = resolve_mount(&cfg, &args.mount)?;

    if policy::by_name(&cfg.policy).is_none() {
        bail!("unknown policy {:?}", cfg.policy);
    }

    log::info!(
        "mergerfs-tier starting: mount={} policy={} interval={:?} dry_run={}",
        mount.display(),
        cfg.policy,
        cfg.interval,
        cfg.dry_run
    );
    util::sd_notify("READY=1\nSTATUS=running");
    let watchdog = util::watchdog_interval();

    loop {
        let started = Instant::now();
        match cycle(&cfg, &mount) {
            Ok(stats) => {
                util::sd_notify(&format!(
                    "STATUS=last cycle: {} moved, {} failed, {} bytes in {:?}\nWATCHDOG=1",
                    stats.moved,
                    stats.failed,
                    stats.bytes,
                    started.elapsed()
                ));
            }
            Err(e) => {
                log::error!("cycle failed: {e:#}");
                util::sd_notify(&format!("STATUS=cycle error: {e}\nWATCHDOG=1"));
            }
        }

        if args.once || util::shutdown_requested() {
            break;
        }

        // Sleep the interval, but never longer than the watchdog wants.
        let nap = match watchdog {
            Some(w) => cfg.interval.min(w),
            None => cfg.interval,
        };
        util::interruptible_sleep(nap);
        if util::shutdown_requested() {
            break;
        }
        if let Some(_w) = watchdog {
            util::sd_notify("WATCHDOG=1");
        }
    }

    log::info!("mergerfs-tier shutting down");
    util::sd_notify("STOPPING=1");
    Ok(())
}

fn cycle(cfg: &Config, mount: &Path) -> Result<dispatch::DispatchStats> {
    let m = mergerfs::detect(mount).context("detecting mergerfs mount")?;
    log::debug!(
        "detected {} branch(es), minfreespace={}",
        m.branches.len(),
        m.minfreespace
    );
    let tiers = TierMap::build(&m, &cfg.tiers);
    let moves = compute_plan(cfg, &m, &tiers)?;
    log::info!("planned {} move(s)", moves.len());
    let dispatcher = Dispatcher::new(&tiers, cfg.dry_run);
    Ok(dispatcher.run(&moves))
}

fn compute_plan(
    cfg: &Config,
    m: &mergerfs::MergerfsMount,
    tiers: &TierMap,
) -> Result<Vec<policy::Move>> {
    let policy = policy::by_name(&cfg.policy).context("resolving policy")?;
    let inv = Inventory::scan(tiers, &cfg.exclude).context("scanning branches")?;
    log::debug!("policy {} over {} file(s)", policy.name(), inv.files.len());

    let mut free = Vec::with_capacity(tiers.branches.len());
    for tb in &tiers.branches {
        free.push(util::free_bytes(&tb.branch.path).unwrap_or(0));
    }

    let ctx = PolicyContext {
        config: cfg,
        tiers,
        inventory: &inv,
        minfreespace: m.minfreespace,
        free,
        now: SystemTime::now(),
    };
    Ok(policy.plan(&ctx))
}
