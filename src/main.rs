mod cli;
mod diff;
mod dump;
mod hasher;
mod mft;
mod privilege;
mod report;
mod store;
mod volume;

use std::path::PathBuf;
use std::thread;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use crossbeam_channel::bounded;
use globset::{Glob, GlobSetBuilder};

use crate::cli::{Cli, Cmd, DiffArgs, ScanArgs};
use crate::mft::{FileRecord, ScanOptions};

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Cli::parse();
    match args.cmd {
        Cmd::Volumes => cmd_volumes(),
        Cmd::Scan(a) => cmd_scan(args.db, a),
        Cmd::List => cmd_list(args.db),
        Cmd::Rm { name } => cmd_rm(args.db, &name),
        Cmd::Diff(a) => cmd_diff(args.db, a),
    }
}

fn db_path(p: Option<PathBuf>) -> Result<PathBuf> {
    match p {
        Some(x) => Ok(x),
        None => store::default_db_path(),
    }
}

fn cmd_volumes() -> Result<()> {
    privilege::ensure_admin()?;
    let vols = volume::enumerate_ntfs_volumes()?;
    if vols.is_empty() {
        println!("(no NTFS volumes found)");
    }
    for v in vols {
        println!(
            "{:8}  {}  {}",
            v.label(),
            v.fs_name,
            v.guid_path
        );
    }
    Ok(())
}

fn cmd_scan(db: Option<PathBuf>, a: ScanArgs) -> Result<()> {
    privilege::ensure_admin()?;
    privilege::try_enable_backup_privilege();

    let db_p = db_path(db)?;
    let mut conn = store::open(&db_p)?;
    let snapshot_id = store::create_snapshot(&conn, &a.name, a.note.as_deref())?;

    let mut vols = volume::enumerate_ntfs_volumes()?;
    if !a.volumes.is_empty() {
        let wanted: Vec<String> = a
            .volumes
            .iter()
            .map(|v| v.trim().trim_end_matches('\\').trim_end_matches(':').to_uppercase())
            .collect();
        vols.retain(|v| {
            let lab = v.label().to_uppercase();
            wanted
                .iter()
                .any(|w| lab == *w || lab.trim_end_matches(':') == *w)
        });
    }
    if vols.is_empty() {
        anyhow::bail!("no matching NTFS volumes to scan");
    }
    println!(
        "Scanning {} volume(s): {}",
        vols.len(),
        vols.iter().map(|v| v.label()).collect::<Vec<_>>().join(", ")
    );

    // Build glob set for exclusions.
    let exclude = {
        let mut b = GlobSetBuilder::new();
        for pat in &a.exclude {
            b.add(Glob::new(pat).with_context(|| format!("bad glob: {pat}"))?);
        }
        b.build()?
    };
    let opts = ScanOptions { exclude };

    // Set up channel and writer thread.
    let (tx, rx) = bounded::<FileRecord>(200_000);

    // We move ownership of `conn` into the writer thread; scanning runs on the main thread.
    let writer = thread::Builder::new()
        .name("fdiff-writer".into())
        .spawn(move || -> Result<u64> {
            let n = store::writer::drain_into_db(&mut conn, snapshot_id, rx)?;
            // After insert, build indexes once.
            store::schema::create_indexes(&conn)?;
            Ok(n)
        })?;

    let t0 = Instant::now();
    for v in &vols {
        match mft::scan_volume(v, &opts, &tx) {
            Ok(stats) => println!(
                "  {} -> {} files ({} sent, {} skipped) in {:.2}s",
                v.label(),
                stats.total,
                stats.sent,
                stats.skipped,
                t0.elapsed().as_secs_f32()
            ),
            Err(e) => eprintln!("  {} ERROR: {e:#}", v.label()),
        }
    }
    drop(tx);
    let written = writer.join().map_err(|_| anyhow::anyhow!("writer panicked"))??;
    println!("Wrote {} rows in {:.2}s.", written, t0.elapsed().as_secs_f32());

    // Hash pass.
    if !a.no_hash {
        let mut conn = store::open(&db_p)?;
        let t1 = Instant::now();
        println!("Hashing PE files (sha256{}) ...", if a.blake3 { " + blake3" } else { "" });
        let stats = hasher::hash_snapshot(
            &mut conn,
            snapshot_id,
            &hasher::HashOptions { with_blake3: a.blake3 },
        )?;
        println!(
            "Hashed {}/{} files ({} failed) in {:.2}s",
            stats.hashed,
            stats.considered,
            stats.failed,
            t1.elapsed().as_secs_f32()
        );
    }

    println!("Snapshot '{}' saved (id={}).", a.name, snapshot_id);
    Ok(())
}

fn cmd_list(db: Option<PathBuf>) -> Result<()> {
    let conn = store::open(&db_path(db)?)?;
    let snaps = store::list_snapshots(&conn)?;
    if snaps.is_empty() {
        println!("(no snapshots)");
    }
    println!("{:<24} {:<6} {:<19} {}", "name", "id", "taken", "note");
    for s in snaps {
        use chrono::TimeZone;
        let ts = chrono::Local
            .timestamp_opt(s.taken_at, 0)
            .single()
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| "?".into());
        println!(
            "{:<24} {:<6} {:<19} {}",
            s.name,
            s.id,
            ts,
            s.note.unwrap_or_default()
        );
    }
    Ok(())
}

fn cmd_rm(db: Option<PathBuf>, name: &str) -> Result<()> {
    let conn = store::open(&db_path(db)?)?;
    let n = store::delete_snapshot(&conn, name)?;
    println!("Removed snapshot '{name}' ({n} file rows).");
    Ok(())
}

fn cmd_diff(db: Option<PathBuf>, a: DiffArgs) -> Result<()> {
    let conn = store::open(&db_path(db)?)?;
    let rep = diff::diff(&conn, &a.before, &a.after)?;

    if a.json {
        println!("{}", report::to_json(&rep));
    } else {
        report::print_console(&rep);
    }

    if let Some(out) = a.dump.as_ref() {
        let n = dump::dump_changes(&rep, out)?;
        println!("\nDumped {} files (incl. before/after sides) to {:?}", n, out);
    }
    Ok(())
}
