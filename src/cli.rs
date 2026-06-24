//! CLI definitions (clap derive).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "fdiff",
    version,
    about = "Everything-style full-disk snapshot + diff for forensic triage \
             (cheat / DLL hijack detection)",
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
    /// List stored snapshots.
    List,
    /// Remove a snapshot from the DB.
    Rm { name: String },
    /// Compare two snapshots.
    Diff(DiffArgs),
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

    /// Skip files whose path starts with this prefix (case-insensitive).
    /// Repeatable. Example: `--exclude-path "C:\Windows\WinSxS"`.
    /// Slashes and trailing backslashes are normalized for you.
    #[arg(long, value_name = "PATH")]
    pub exclude_path: Vec<String>,

    /// Glob pattern(s) to exclude (matched against full path).
    /// Repeatable. Example: `--exclude '**/$Recycle.Bin/**'`.
    #[arg(long)]
    pub exclude: Vec<String>,

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
}
