//! Two-snapshot diff.
//!
//! Speed strategy: do as much filtering as possible inside SQLite (which has
//! the right indexes), and only ship to Rust the rows that are actually
//! changed. We split the comparison into four independent queries instead of
//! one big FULL OUTER JOIN:
//!
//! 1. **Modified / Renamed** — `b INNER JOIN a ON (snapshot, volume, frn)`
//!    with a WHERE clause that filters out unchanged rows in the engine.
//! 2. **Added**             — rows present in `after` but not in `before`
//!                            (`NOT EXISTS` lets the planner use the PK).
//! 3. **Removed**           — symmetric of Added.
//! 4. **Replaced**          — same `(volume, path)` but different `frn`,
//!                            the DLL-hijack signature; uses `idx_files_path`.
//!
//! By default directories are excluded (their mtime is noisy). Pass
//! `--include-dirs` to bring them back.

use anyhow::{anyhow, Result};
use indicatif::{ProgressBar, ProgressStyle};
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
    Renamed,         // same FRN, different path
    Replaced,        // same path, different FRN — DLL hijack signal
    RenamedModified, // same FRN, path + content both changed
}

#[derive(Debug, Clone, Serialize)]
pub struct FileSide {
    pub volume: String,
    pub frn: u64,
    pub path: String,
    pub size: u64,
    pub mtime: i64,
    pub sha256_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChangeEntry {
    pub kind: ChangeKind,
    pub before: Option<FileSide>,
    pub after: Option<FileSide>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct DiffReport {
    pub before_snapshot: String,
    pub after_snapshot: String,
    pub added: Vec<ChangeEntry>,
    pub removed: Vec<ChangeEntry>,
    pub modified: Vec<ChangeEntry>, // also holds Renamed / RenamedModified
    pub replaced: Vec<ChangeEntry>,
}

/// Tunables for `diff()`.
#[derive(Debug, Clone, Copy)]
pub struct DiffOptions {
    /// Include directories in the comparison. Default false — directory mtimes
    /// are constantly rewritten by normal Windows activity and produce noise.
    pub include_dirs: bool,
    /// Cap result count per category. 0 = unlimited.
    pub limit_per_category: usize,
}

impl Default for DiffOptions {
    fn default() -> Self {
        Self {
            include_dirs: false,
            limit_per_category: 0,
        }
    }
}

pub fn diff(
    conn: &Connection,
    before_name: &str,
    after_name: &str,
    opts: &DiffOptions,
) -> Result<DiffReport> {
    let before_id = snapshot_id(conn, before_name)?;
    let after_id = snapshot_id(conn, after_name)?;

    let mut report = DiffReport {
        before_snapshot: before_name.into(),
        after_snapshot: after_name.into(),
        ..Default::default()
    };

    let _dir_pred = if opts.include_dirs {
        "" // no extra predicate
    } else {
        "AND is_dir = 0"
    };
    let limit_sql = if opts.limit_per_category > 0 {
        format!(" LIMIT {}", opts.limit_per_category)
    } else {
        String::new()
    };

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner} {msg}")
            .unwrap()
            .tick_chars("⠁⠃⠇⡇⣇⣧⣷⣿"),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(120));

    // -----------------------------------------------------------------------
    // 1) Modified / Renamed / RenamedModified — INNER JOIN, WHERE in SQL.
    //
    // We let SQLite skip every row that's unchanged. Walks through the PK
    // (snapshot_id, volume, frn) on both sides — effectively a merge join.
    // -----------------------------------------------------------------------
    pb.set_message("comparing FRN-matched rows...");
    let q_mod = format!(
        r#"
        SELECT
            b.volume, b.frn, b.path, b.size, b.mtime, b.sha256,
                     a.path, a.size, a.mtime, a.sha256
        FROM files b
        INNER JOIN files a
            ON a.snapshot_id = ?2
           AND a.volume = b.volume
           AND a.frn    = b.frn
        WHERE b.snapshot_id = ?1
          {dir_pred_b}
          {dir_pred_a}
          AND (
              b.path <> a.path
           OR (b.sha256 IS NOT NULL AND a.sha256 IS NOT NULL AND b.sha256 <> a.sha256)
           OR ((b.sha256 IS NULL OR a.sha256 IS NULL) AND (b.size <> a.size OR b.mtime <> a.mtime))
          )
        {limit}
        "#,
        dir_pred_b = if opts.include_dirs { "" } else { "AND b.is_dir = 0" },
        dir_pred_a = if opts.include_dirs { "" } else { "AND a.is_dir = 0" },
        limit = limit_sql,
    );

    let mut stmt = conn.prepare(&q_mod)?;
    let mut it = stmt.query(rusqlite::params![before_id, after_id])?;
    while let Some(r) = it.next()? {
        let volume: String = r.get(0)?;
        let b_frn: i64 = r.get(1)?;
        let b_path: String = r.get(2)?;
        let b_size: i64 = r.get(3)?;
        let b_mtime: i64 = r.get(4)?;
        let b_sha: Option<Vec<u8>> = r.get(5)?;

        let a_path: String = r.get(6)?;
        let a_size: i64 = r.get(7)?;
        let a_mtime: i64 = r.get(8)?;
        let a_sha: Option<Vec<u8>> = r.get(9)?;

        let path_changed = b_path != a_path;
        let content_changed = match (&b_sha, &a_sha) {
            (Some(x), Some(y)) => x != y,
            _ => b_size != a_size || b_mtime != a_mtime,
        };
        let kind = match (path_changed, content_changed) {
            (false, false) => continue, // shouldn't happen — SQL already filtered
            (true, false) => ChangeKind::Renamed,
            (false, true) => ChangeKind::Modified,
            (true, true) => ChangeKind::RenamedModified,
        };

        report.modified.push(ChangeEntry {
            kind,
            before: Some(FileSide {
                volume: volume.clone(),
                frn: b_frn as u64,
                path: b_path,
                size: b_size as u64,
                mtime: b_mtime,
                sha256_hex: b_sha.as_ref().map(hex),
            }),
            after: Some(FileSide {
                volume,
                frn: b_frn as u64,
                path: a_path,
                size: a_size as u64,
                mtime: a_mtime,
                sha256_hex: a_sha.as_ref().map(hex),
            }),
        });
    }
    drop(it);
    drop(stmt);
    pb.set_message(format!("found {} modified / renamed", report.modified.len()));

    // -----------------------------------------------------------------------
    // 2) Added: NOT EXISTS in `before`. NOT EXISTS lets the planner do an
    //    indexed PK lookup per row of `after` — cheap.
    // -----------------------------------------------------------------------
    pb.set_message("scanning Added...");
    let q_add = format!(
        r#"
        SELECT a.volume, a.frn, a.path, a.size, a.mtime, a.sha256
        FROM files a
        WHERE a.snapshot_id = ?2 {dir_pred}
          AND NOT EXISTS (
              SELECT 1 FROM files b
              WHERE b.snapshot_id = ?1
                AND b.volume = a.volume
                AND b.frn    = a.frn
          )
        {limit}
        "#,
        dir_pred = if opts.include_dirs { "" } else { "AND a.is_dir = 0" },
        limit = limit_sql,
    );
    let mut stmt = conn.prepare(&q_add)?;
    let mut it = stmt.query(rusqlite::params![before_id, after_id])?;
    while let Some(r) = it.next()? {
        report.added.push(ChangeEntry {
            kind: ChangeKind::Added,
            before: None,
            after: Some(read_side(r)?),
        });
    }
    drop(it);
    drop(stmt);
    pb.set_message(format!("found {} added", report.added.len()));

    // -----------------------------------------------------------------------
    // 3) Removed: symmetric.
    // -----------------------------------------------------------------------
    pb.set_message("scanning Removed...");
    let q_rm = format!(
        r#"
        SELECT b.volume, b.frn, b.path, b.size, b.mtime, b.sha256
        FROM files b
        WHERE b.snapshot_id = ?1 {dir_pred}
          AND NOT EXISTS (
              SELECT 1 FROM files a
              WHERE a.snapshot_id = ?2
                AND a.volume = b.volume
                AND a.frn    = b.frn
          )
        {limit}
        "#,
        dir_pred = if opts.include_dirs { "" } else { "AND b.is_dir = 0" },
        limit = limit_sql,
    );
    let mut stmt = conn.prepare(&q_rm)?;
    let mut it = stmt.query(rusqlite::params![before_id, after_id])?;
    while let Some(r) = it.next()? {
        report.removed.push(ChangeEntry {
            kind: ChangeKind::Removed,
            before: Some(read_side(r)?),
            after: None,
        });
    }
    drop(it);
    drop(stmt);
    pb.set_message(format!("found {} removed", report.removed.len()));

    // -----------------------------------------------------------------------
    // 4) Replaced: same path, different FRN. Uses idx_files_path.
    // -----------------------------------------------------------------------
    pb.set_message("scanning Replaced...");
    let q_repl = format!(
        r#"
        SELECT
            b.volume, b.frn, b.path, b.size, b.mtime, b.sha256,
            a.frn,    a.size,  a.mtime,  a.sha256
        FROM files b
        INNER JOIN files a
            ON a.snapshot_id = ?2
           AND a.volume = b.volume
           AND a.path   = b.path
        WHERE b.snapshot_id = ?1
          AND a.frn <> b.frn
          {dir_pred_b}
          {dir_pred_a}
        {limit}
        "#,
        dir_pred_b = if opts.include_dirs { "" } else { "AND b.is_dir = 0" },
        dir_pred_a = if opts.include_dirs { "" } else { "AND a.is_dir = 0" },
        limit = limit_sql,
    );
    let mut stmt = conn.prepare(&q_repl)?;
    let mut it = stmt.query(rusqlite::params![before_id, after_id])?;
    while let Some(r) = it.next()? {
        let volume: String = r.get(0)?;
        let b_frn: i64 = r.get(1)?;
        let path: String = r.get(2)?;
        let b_size: i64 = r.get(3)?;
        let b_mtime: i64 = r.get(4)?;
        let b_sha: Option<Vec<u8>> = r.get(5)?;
        let a_frn: i64 = r.get(6)?;
        let a_size: i64 = r.get(7)?;
        let a_mtime: i64 = r.get(8)?;
        let a_sha: Option<Vec<u8>> = r.get(9)?;

        report.replaced.push(ChangeEntry {
            kind: ChangeKind::Replaced,
            before: Some(FileSide {
                volume: volume.clone(),
                frn: b_frn as u64,
                path: path.clone(),
                size: b_size as u64,
                mtime: b_mtime,
                sha256_hex: b_sha.as_ref().map(hex),
            }),
            after: Some(FileSide {
                volume,
                frn: a_frn as u64,
                path,
                size: a_size as u64,
                mtime: a_mtime,
                sha256_hex: a_sha.as_ref().map(hex),
            }),
        });
    }
    drop(it);
    drop(stmt);

    pb.finish_with_message(format!(
        "diff done: +{} -{} ~{} !{}",
        report.added.len(),
        report.removed.len(),
        report.modified.len(),
        report.replaced.len(),
    ));

    Ok(report)
}

fn read_side(r: &rusqlite::Row<'_>) -> rusqlite::Result<FileSide> {
    let volume: String = r.get(0)?;
    let frn: i64 = r.get(1)?;
    let path: String = r.get(2)?;
    let size: i64 = r.get(3)?;
    let mtime: i64 = r.get(4)?;
    let sha: Option<Vec<u8>> = r.get(5)?;
    Ok(FileSide {
        volume,
        frn: frn as u64,
        path,
        size: size as u64,
        mtime,
        sha256_hex: sha.as_ref().map(hex),
    })
}

fn hex(v: &Vec<u8>) -> String {
    let mut s = String::with_capacity(v.len() * 2);
    for b in v {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn snapshot_id(conn: &Connection, name: &str) -> Result<i64> {
    let id: Option<i64> = conn
        .query_row(
            "SELECT id FROM snapshots WHERE name = ?1",
            rusqlite::params![name],
            |r| r.get(0),
        )
        .optional()?;
    id.ok_or_else(|| anyhow!("snapshot '{name}' not found"))
}
