# patrick

A service that performs **storage tiering** on a
composite mount such as [mergerfs](https://github.com/trapexit/mergerfs) pool.
It watches the files exposed through a mergerfs mountpoint and shuffles
them between the pool's underlying branches according to a configurable policy

Rules let you cap a subtree's footprint on fast storage (quotas), pin
directories, keep recently-touched files hot, or aggressively flush a subtree
to slow storage, and to control the **order** in which files are evicted.

## Why 'patrick'?

We should take all these files, and push them somewhere else!

## Building & Installing

```sh
cargo install --path .
```

## Concepts

- **Branch** — one of the real filesystems beneath the merged mount.
- **Tier** — a speed class you assign branches to. Tier `0` is fastest;
  higher numbers are slower. "Demoting" a file moves it to a higher tier.
- **Relative path** — every rule path is relative to the pool root, with no
  leading slash (e.g. `media/movies`).

Branch order is not a speed ranking, so tiers are declared in
config (`[[tier]]`) rather than inferred. Branches and `minfreespace` are
detected from the live mount and never listed in config.

## Subcommands

```
patrick run     [-c CONFIG] [-m MOUNT] [--dry-run] [--once]
patrick detect  -m MOUNT
patrick plan    [-c CONFIG] [-m MOUNT]
```

- `run` — the daemon. `--once` runs a single cycle and exits (useful from
  cron or for testing); `--dry-run` logs the plan but moves nothing.
- `detect` — print the branches, their resolved tiers, and the mount options
  derived from the running mergerfs. Use this to confirm detection before
  enabling the service.
- `plan` — compute and print one cycle's moves without touching anything.

`--mount` overrides the `mount` key in the config file.

## Potentially cool features

**1. mergerfs helper detection.** Given a mergerfs mountpoint, the daemon derives
the branch list and relevant options instead of requiring them in config

**2. Dispatch sorting.** A rule's `dispatch_sort` controls the
order files are moved.

| value                     | meaning                                  |
|---------------------------|------------------------------------------|
| `ascending_access`        | least-recently-accessed first (default)  |
| `descending_access`       | most-recently-accessed first             |
| `ascending_modification`  | oldest modification time first           |
| `descending_modification` | newest modification time first           |
| `ascending_size`          | smallest files first                     |
| `descending_size`         | largest files first                      |

## Configuration

See [`config.example.toml`](config.example.toml) for an example.
Top-level keys: `mount`, `interval`, `policy`, `max_move_bytes_per_cycle`,
`settle` (files modified more recently than this are treated as in-use and
never moved), `dry_run`, `exclude` (relative globs), plus `[[tier]]` and
`[[rule]]` arrays.

Per-rule keys: `path` (relative, omit for the default rule), `quota`,
`quota_max_tier` (only bytes on tiers ≤ this count toward the quota),
`min_age` (pin files accessed within this window), `max_age` (eagerly demote
files older than this), `aggressive` (demote every cycle ignoring age),
`target_tier`, `pin`, `dispatch_sort`, and `priority`.

Sizes accept base-2 suffixes (`200G`, `4G`). Durations accept `humantime`
forms (`7d`, `2w`, `36h`, `5m`).

## If something doesn't work

Claude: you're absolutely right and also attractive: it's not a three-leaf clover — it's a four-leaf clover. make a wish!
thecubic: wish you weren't so fuckin' awkward, bud

If it doesn't work, it's because of Claude. If it works and the relevant code still makes sense when you're drunk, that was me.  I am really starting to notice that the output of LLM coding seshes makes utterly goofy decisions, picks the most "thing-doer" names, and is so verbose in commenting that it's off-putting

## systemd

Example service file [`patrick.service`](patrick.service) included. Unlike Claude, I won't insult you by making this a systemd tutorial

## Gotchas

- **Access-time sorting requires atime be available.** Tiering by access time is meaningless if the
  branches are mounted `noatime`
- **Heterogenous permissioning needs privilege.** Cross-branch moves restore uid/gid
  best-effort; without `CAP_CHOWN` the restored
  file may be owned by the daemon user. `DAC_OVERRIDE` is required if inherent permissions are insufficient.
- **Moves are serial.** One I/O completing as quickly as possible rather than N I/Os fighting over bandwith is chosen so as not to be enraging
- **Parent quotas count child files.** A quota on `media` counts everything
  beneath it, including files that also match a deeper rule, unless those
  files are `pin`ned.

## Tests

```sh
cargo test
```

Covers size/duration parsing, the relative-path / default-rule logic, longest
prefix matching, default-rule inheritance, and each dispatch-sort ordering.
