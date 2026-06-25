mod cli;
mod config;
mod diff;
mod dump;
mod hasher;
mod mft;
mod privilege;
mod report;
mod store;
mod volume;
mod watch;

use std::path::PathBuf;
use std::thread;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use crossbeam_channel::bounded;
use globset::{Glob, GlobSetBuilder};

use crate::cli::{Cli, Cmd, ConfigCmd, DiffArgs, ScanArgs, WatchArgs};
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
        Cmd::Watch(a) => cmd_watch(args.db, a),
        Cmd::List => cmd_list(args.db),
        Cmd::Rm { name } => cmd_rm(args.db, &name),
        Cmd::Diff(a) => cmd_diff(args.db, a),
        Cmd::Config(sub) => cmd_config(sub),
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
    if !a.exclude_volumes.is_empty() {
        let banned: Vec<String> = a
            .exclude_volumes
            .iter()
            .map(|v| v.trim().trim_end_matches('\\').trim_end_matches(':').to_uppercase())
            .collect();
        vols.retain(|v| {
            let lab = v.label().to_uppercase();
            !banned
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

    // Build glob set for exclusions (from CLI --exclude only; config globs are
    // handled by config::compile below).
    let exclude_globset = {
        let mut b = GlobSetBuilder::new();
        for pat in &a.exclude {
            b.add(Glob::new(pat).with_context(|| format!("bad glob: {pat}"))?);
        }
        b.build()?
    };

    // Merge persistent config + per-run CLI exclusions into one compiled set.
    let cfg = if a.no_config {
        config::Config::default()
    } else {
        match config::load_or_default() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[warn] config load failed: {e:#} — continuing without it");
                config::Config::default()
            }
        }
    };
    let compiled = config::compile(&cfg, &a.exclude_path, &[], &a.exclude_regex)?;
    let mut exclude_prefixes: Vec<String> = compiled.prefix_vec();
    let exclude_regexes = compiled.regexes.clone();

    // Always exclude fdiff's own DB directory from scans — otherwise every
    // snapshot picks up the live SQLite WAL it just wrote.
    if let Some(parent) = db_p.parent() {
        let p = ScanOptions::normalize_prefix(&parent.to_string_lossy());
        if !p.is_empty() {
            exclude_prefixes.push(p);
        }
    }
    if let Ok(default) = store::default_db_path() {
        if let Some(parent) = default.parent() {
            let p = ScanOptions::normalize_prefix(&parent.to_string_lossy());
            if !p.is_empty() {
                exclude_prefixes.push(p);
            }
        }
    }
    exclude_prefixes.sort();
    exclude_prefixes.dedup();

    if !compiled.display.is_empty() {
        println!("Applying {} exclusion rule(s):", compiled.display.len());
        for line in &compiled.display {
            println!("  - {line}");
        }
    }
    let opts = ScanOptions {
        exclude: exclude_globset,
        exclude_prefixes,
        exclude_regexes,
    };

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
    let resolved_db = db_path(db)?;
    let conn = store::open(&resolved_db)?;
    // Best-effort: make sure indexes exist on older DBs created before v0.3.
    let _ = store::schema::create_indexes(&conn);

    // ---- Extension filter ----
    // Normalize: strip leading dots, lowercase, expand "pe" shortcut.
    let mut ext_filter: Vec<String> = Vec::new();
    for raw in &a.ext {
        let token = raw.trim().trim_start_matches('.').to_ascii_lowercase();
        if token.is_empty() {
            continue;
        }
        if token == "pe" {
            for e in diff::PE_EXT_SET {
                ext_filter.push((*e).to_string());
            }
        } else {
            ext_filter.push(token);
        }
    }
    ext_filter.sort();
    ext_filter.dedup();

    // ---- Path / glob / regex exclusions (config + CLI) ----
    let cfg = if a.no_config {
        config::Config::default()
    } else {
        match config::load_or_default() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[warn] config load failed: {e:#} — continuing without it");
                config::Config::default()
            }
        }
    };
    let compiled = config::compile(
        &cfg,
        &a.exclude_path,
        &a.exclude,
        &a.exclude_regex,
    )?;
    let mut exclude_prefixes: Vec<String> = compiled.prefix_vec();
    let exclude_regexes = compiled.regexes.clone();
    let exclude_globs = compiled.globs.clone();

    if !a.include_self {
        // Always hide fdiff's DB directory unless the user opted in.
        if let Some(parent) = resolved_db.parent() {
            let p = mft::ScanOptions::normalize_prefix(&parent.to_string_lossy());
            if !p.is_empty() {
                exclude_prefixes.push(p);
            }
        }
        if let Ok(default) = store::default_db_path() {
            if let Some(parent) = default.parent() {
                let p = mft::ScanOptions::normalize_prefix(&parent.to_string_lossy());
                if !p.is_empty() {
                    exclude_prefixes.push(p);
                }
            }
        }
        if let Some(out) = a.dump.as_ref() {
            let p = mft::ScanOptions::normalize_prefix(&out.to_string_lossy());
            if !p.is_empty() {
                exclude_prefixes.push(p);
            }
        }
        exclude_prefixes.sort();
        exclude_prefixes.dedup();
    }

    if !ext_filter.is_empty() {
        println!(
            "Filtering by extension: .{}",
            ext_filter.join(", .")
        );
    }
    if !compiled.display.is_empty() {
        println!("Hiding {} rule(s) in diff:", compiled.display.len());
        for line in &compiled.display {
            println!("  - {line}");
        }
    }

    let opts = diff::DiffOptions {
        include_dirs: a.include_dirs,
        limit_per_category: a.limit,
        ext_filter,
        exclude_prefixes,
        exclude_regexes,
        exclude_globs,
    };
    let t0 = std::time::Instant::now();
    let rep = diff::diff(&conn, &a.before, &a.after, &opts)?;
    eprintln!("(diff took {:.2}s)", t0.elapsed().as_secs_f32());

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

fn cmd_watch(db: Option<PathBuf>, a: WatchArgs) -> Result<()> {
    privilege::ensure_admin()?;
    privilege::try_enable_backup_privilege();

    // Expand --ext.
    let mut ext_filter: Vec<String> = Vec::new();
    for raw in &a.ext {
        let token = raw.trim().trim_start_matches('.').to_ascii_lowercase();
        if token.is_empty() {
            continue;
        }
        if token == "pe" {
            for e in diff::PE_EXT_SET {
                ext_filter.push((*e).to_string());
            }
        } else {
            ext_filter.push(token);
        }
    }
    ext_filter.sort();
    ext_filter.dedup();

    // Path / glob / regex exclusions (config + CLI).
    let cfg = if a.no_config {
        config::Config::default()
    } else {
        match config::load_or_default() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[warn] config load failed: {e:#} — continuing without it");
                config::Config::default()
            }
        }
    };
    let compiled = config::compile(
        &cfg,
        &a.exclude_path,
        &[],
        &a.exclude_regex,
    )?;
    let mut exclude_prefixes: Vec<String> = compiled.prefix_vec();
    let exclude_regexes = compiled.regexes.clone();
    let exclude_globs = compiled.globs.clone();

    if !a.include_self {
        let db_p = db_path(db.clone())?;
        if let Some(parent) = db_p.parent() {
            let p = watch::normalize_prefix(&parent.to_string_lossy());
            if !p.is_empty() {
                exclude_prefixes.push(p);
            }
        }
        if let Ok(default) = store::default_db_path() {
            if let Some(parent) = default.parent() {
                let p = watch::normalize_prefix(&parent.to_string_lossy());
                if !p.is_empty() {
                    exclude_prefixes.push(p);
                }
            }
        }
        if let Some(out) = a.dump.as_ref() {
            let p = watch::normalize_prefix(&out.to_string_lossy());
            if !p.is_empty() {
                exclude_prefixes.push(p);
            }
        }
        exclude_prefixes.sort();
        exclude_prefixes.dedup();
    }

    if !compiled.display.is_empty() {
        eprintln!("Hiding {} rule(s):", compiled.display.len());
        for line in &compiled.display {
            eprintln!("  - {line}");
        }
    }

    let opts = watch::WatchOptions {
        volumes: a.volumes,
        ext_filter,
        exclude_prefixes,
        exclude_regexes,
        exclude_globs,
        dump_dir: a.dump,
        json: a.json,
        no_close_events: false,
    };
    watch::run_watch(opts)
}

fn cmd_config(sub: ConfigCmd) -> Result<()> {
    match sub {
        ConfigCmd::Show => {
            let cfg = config::load_or_default()?;
            config::show(&cfg);
            Ok(())
        }
        ConfigCmd::Path => {
            println!("{}", config::config_path_for_display());
            Ok(())
        }
        ConfigCmd::Reset => {
            let (p, cfg) = config::reset_to_defaults()?;
            println!("Reset config to defaults at {}", p.display());
            config::show(&cfg);
            Ok(())
        }
        ConfigCmd::Add { pattern, kind } => {
            let kind = match kind.to_ascii_lowercase().as_str() {
                "prefix" => config::RuleKind::Prefix,
                "glob" => config::RuleKind::Glob,
                "regex" | "re" => config::RuleKind::Regex,
                other => anyhow::bail!("unknown kind '{other}', must be prefix|glob|regex"),
            };
            let mut cfg = config::load_or_default()?;
            // Pre-validate compilation so the user finds out now, not later.
            let _ = config::compile(
                &config::Config {
                    exclude_paths: vec![config::ExcludeRule {
                        kind,
                        pattern: pattern.clone(),
                    }],
                },
                &[],
                &[],
                &[],
            )?;
            config::add_rule(&mut cfg, config::ExcludeRule { kind, pattern: pattern.clone() });
            let p = config::save(&cfg)?;
            println!("Added [{:?}] {} to {}", kind, pattern, p.display());
            Ok(())
        }
        ConfigCmd::Rm { key } => {
            let mut cfg = config::load_or_default()?;
            let n = config::remove_rule(&mut cfg, &key)?;
            if n == 0 {
                anyhow::bail!("no rule matched '{key}' (try `fdiff config show` for indices)");
            }
            let p = config::save(&cfg)?;
            println!("Removed {n} rule(s); updated {}", p.display());
            Ok(())
        }
    }
}
