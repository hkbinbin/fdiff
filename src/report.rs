//! Console + JSON reporter.

use std::fmt::Write as _;

use crate::diff::{ChangeEntry, ChangeKind, DiffReport, FileSide};

pub fn print_console(rep: &DiffReport) {
    println!(
        "fdiff: {} -> {}",
        rep.before_snapshot, rep.after_snapshot
    );

    print_section("Added", &rep.added);
    print_section("Removed", &rep.removed);
    print_section_modified("Modified / Renamed", &rep.modified);
    print_section_replaced("Replaced (same path, FRN changed — possible DLL hijack)", &rep.replaced);

    println!(
        "\nSummary: +{} added  -{} removed  ~{} modified  !{} replaced",
        rep.added.len(),
        rep.removed.len(),
        rep.modified.len(),
        rep.replaced.len(),
    );
}

fn print_section(title: &str, items: &[ChangeEntry]) {
    println!("\n== {} ({}) ==", title, items.len());
    for it in items {
        let side = it.after.as_ref().or(it.before.as_ref());
        if let Some(s) = side {
            println!("  {}", fmt_side(s));
        }
    }
}

fn print_section_modified(title: &str, items: &[ChangeEntry]) {
    println!("\n== {} ({}) ==", title, items.len());
    for it in items {
        let tag = match it.kind {
            ChangeKind::Renamed => "[RENAMED]   ",
            ChangeKind::RenamedModified => "[RENAMED+MOD]",
            ChangeKind::Modified => "[MODIFIED] ",
            _ => "           ",
        };
        let after = it.after.as_ref();
        let before = it.before.as_ref();
        if let Some(a) = after {
            println!("  {} {}", tag, fmt_side(a));
        }
        if let Some(b) = before {
            if it.kind == ChangeKind::Renamed || it.kind == ChangeKind::RenamedModified {
                println!("             was: {}", b.path);
            } else {
                println!(
                    "             was size={} mtime={} sha={}",
                    b.size,
                    b.mtime,
                    b.sha256_hex.as_deref().unwrap_or("<none>")
                );
            }
        }
    }
}

fn print_section_replaced(title: &str, items: &[ChangeEntry]) {
    println!("\n== {} ({}) ==", title, items.len());
    for it in items {
        if let (Some(b), Some(a)) = (&it.before, &it.after) {
            println!("  [REPLACED]  {}", fmt_side(a));
            println!(
                "              before: frn={} size={} sha={}",
                b.frn,
                b.size,
                b.sha256_hex.as_deref().unwrap_or("<none>")
            );
            println!(
                "              after : frn={} size={} sha={}",
                a.frn,
                a.size,
                a.sha256_hex.as_deref().unwrap_or("<none>")
            );
        }
    }
}

fn fmt_side(s: &FileSide) -> String {
    let mut out = String::new();
    let sha = s.sha256_hex.as_deref().unwrap_or("<no-hash>");
    let sha_short = if sha.len() >= 16 { &sha[..16] } else { sha };
    let _ = write!(
        out,
        "{:>11}  {}  {}  {}",
        s.size,
        fmt_ts(s.mtime),
        sha_short,
        s.path
    );
    out
}

fn fmt_ts(unix: i64) -> String {
    use chrono::TimeZone;
    chrono::Local
        .timestamp_opt(unix, 0)
        .single()
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "?".into())
}

pub fn to_json(rep: &DiffReport) -> String {
    serde_json::to_string_pretty(rep).unwrap_or_else(|_| "{}".into())
}
