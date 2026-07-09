//! CLI definitions (clap derive).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "fdiff",
    version,
    about = "Everything-style full-disk snapshot + diff for forensic triage \
             (cheat / DLL hijack detection)"
)]
pub struct Cli {
    /// Override DB path (defaults to %LOCALAPPDATA%\fdiff\fdiff.db).
    #[arg(long, global = true)]
    pub db: Option<PathBuf>,

    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// List all NTFS volumes on this machine.
    Volumes,
    /// Take a snapshot of all NTFS volumes (or those listed) and write it to the DB.
    Scan(ScanArgs),
    /// Real-time NTFS change monitor (USN journal). Stops on Ctrl-C.
    Watch(WatchArgs),
    /// List stored snapshots.
    List,
    /// Remove a snapshot from the DB.
    Rm { name: String },
    /// Compare two snapshots.
    Diff(DiffArgs),
    /// Manage persistent exclusion rules (saved to `%LOCALAPPDATA%\fdiff\config.json`).
    #[command(subcommand)]
    Config(ConfigCmd),
}

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    /// Show the current saved rules and config file path.
    Show,
    /// Add an exclusion rule. Kind defaults to `prefix`.
    Add {
        /// Pattern. Variables `${LOCALAPPDATA}` / `%LOCALAPPDATA%` are
        /// expanded at runtime.
        pattern: String,
        /// Rule kind: prefix | glob | regex.
        #[arg(long, default_value = "prefix")]
        kind: String,
    },
    /// Remove a rule by 1-based index (see `config show`) or exact pattern.
    Rm { key: String },
    /// Replace the config with the seeded defaults (Edge / ContentDeliveryManager / etc).
    Reset,
    /// Print the config file's absolute path.
    Path,
}

#[derive(clap::Args, Debug)]
pub struct WatchArgs {
    /// Only monitor these volume labels (e.g. `--volumes C,D`).
    /// Defaults to all NTFS volumes.
    #[arg(long, value_delimiter = ',')]
    pub volumes: Vec<String>,

    /// Only emit events for files whose extension matches.
    /// `--ext pe` expands to the full PE set
    /// (exe, dll, sys, scr, cpl, ocx, drv, efi, pyd, com).
    #[arg(long, value_delimiter = ',')]
    pub ext: Vec<String>,

    /// Copy every Created/Modified/Renamed PE file to this directory and
    /// append entries to `watch_manifest.jsonl` in there.
    #[arg(long)]
    pub dump: Option<PathBuf>,

    /// Emit machine-readable JSONL (one event per line) to stdout.
    #[arg(long)]
    pub json: bool,

    /// Don't auto-skip fdiff's own database / dump directories.
    #[arg(long)]
    pub include_self: bool,
}

#[derive(clap::Args, Debug)]
pub struct ScanArgs {
    /// Friendly name for this snapshot, e.g. "before" / "after".
    pub name: String,

    /// Only scan these volume labels (whitelist, e.g. `--volumes C,D`).
    /// Defaults to all NTFS volumes when neither --volumes nor --exclude-volumes is set.
    #[arg(long, value_delimiter = ',')]
    pub volumes: Vec<String>,

    /// Skip these volume labels (blacklist, e.g. `--exclude-volumes D,E`).
    /// Applied after --volumes if both are present.
    #[arg(long, value_delimiter = ',')]
    pub exclude_volumes: Vec<String>,

    /// Skip the hash stage entirely (much faster).
    #[arg(long)]
    pub no_hash: bool,

    /// Also compute BLAKE3 in addition to SHA-256.
    #[arg(long)]
    pub blake3: bool,

    /// Free-form note saved with the snapshot.
    #[arg(long)]
    pub note: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct DiffArgs {
    pub before: String,
    pub after: String,

    /// Emit machine-readable JSON to stdout instead of the colored summary.
    #[arg(long)]
    pub json: bool,

    /// Copy every changed PE file to this directory and write manifest.json there.
    #[arg(long)]
    pub dump: Option<PathBuf>,

    /// Include directories in the comparison. Off by default — Windows
    /// constantly rewrites directory mtimes which produces a lot of noise.
    #[arg(long)]
    pub include_dirs: bool,

    /// Only show files whose extension matches. Comma-separated, no dot, case
    /// insensitive. Example: `--ext exe,dll,sys`. A handy shortcut for the
    /// common forensic case is `--ext pe`, which expands to the full PE set
    /// (exe, dll, sys, scr, cpl, ocx, drv, efi, pyd, com).
    #[arg(long, value_delimiter = ',')]
    pub ext: Vec<String>,

    /// Don't auto-skip fdiff's own database / dump directories. By default
    /// %LOCALAPPDATA%\fdiff and the path passed to --dump are hidden, since
    /// scans always pick up our own writes.
    #[arg(long)]
    pub include_self: bool,

    /// Cap each category (Added / Removed / Modified / Replaced) to this many
    /// rows. 0 = unlimited. Useful when you only want a quick triage view.
    #[arg(long, default_value_t = 0)]
    pub limit: usize,
}
