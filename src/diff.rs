//! Two-snapshot diff. Joins on `(volume, frn)` for primary identity tracking
//! and on `(volume, path)` to detect "Replaced" — same path but different FRN,
//! the classic DLL-hijack signature.

use anyhow::{anyhow, Result};
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Removed,
    Modified,
    Renamed,           // same FRN, different path
    Replaced,          // same path, different FRN — DLL hijack signal
    RenamedModified,   // same FRN, path + content both changed
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

pub fn diff(
    conn: &Connection,
    before_name: &str,
    after_name: &str,
) -> Result<DiffReport> {
    let before_id = snapshot_id(conn, before_name)?;
    let after_id = snapshot_id(conn, after_name)?;

    let mut report = DiffReport {
        before_snapshot: before_name.into(),
        after_snapshot: after_name.into(),
        ..Default::default()
    };

    // --- 1. FRN-based JOIN: classifies Added / Removed / Modified / Renamed ---
    //
    // We do FULL OUTER JOIN via UNION ALL of two LEFT JOINs.
    let q_frn = r#"
        SELECT
            b.volume AS b_volume, b.frn AS b_frn, b.path AS b_path,
            b.size AS b_size, b.mtime AS b_mtime, b.sha256 AS b_sha,
            a.volume AS a_volume, a.frn AS a_frn, a.path AS a_path,
            a.size AS a_size, a.mtime AS a_mtime, a.sha256 AS a_sha
        FROM (SELECT * FROM files WHERE snapshot_id = ?1) b
        LEFT JOIN (SELECT * FROM files WHERE snapshot_id = ?2) a
            ON a.volume = b.volume AND a.frn = b.frn
        UNION ALL
        SELECT
            b.volume, b.frn, b.path, b.size, b.mtime, b.sha256,
            a.volume, a.frn, a.path, a.size, a.mtime, a.sha256
        FROM (SELECT * FROM files WHERE snapshot_id = ?2) a
        LEFT JOIN (SELECT * FROM files WHERE snapshot_id = ?1) b
            ON a.volume = b.volume AND a.frn = b.frn
        WHERE b.frn IS NULL
    "#;

    let mut stmt = conn.prepare(q_frn)?;
    let mut it = stmt.query(rusqlite::params![before_id, after_id])?;

    while let Some(r) = it.next()? {
        let b_vol: Option<String> = r.get(0)?;
        let b_frn: Option<i64> = r.get(1)?;
        let b_path: Option<String> = r.get(2)?;
        let b_size: Option<i64> = r.get(3)?;
        let b_mtime: Option<i64> = r.get(4)?;
        let b_sha: Option<Vec<u8>> = r.get(5)?;

        let a_vol: Option<String> = r.get(6)?;
        let a_frn: Option<i64> = r.get(7)?;
        let a_path: Option<String> = r.get(8)?;
        let a_size: Option<i64> = r.get(9)?;
        let a_mtime: Option<i64> = r.get(10)?;
        let a_sha: Option<Vec<u8>> = r.get(11)?;

        let before = make_side(b_vol, b_frn, b_path, b_size, b_mtime, b_sha);
        let after = make_side(a_vol, a_frn, a_path, a_size, a_mtime, a_sha);

        match (&before, &after) {
            (Some(b), Some(a)) => {
                let path_changed = b.path != a.path;
                let content_changed = content_changed(b, a);
                let kind = match (path_changed, content_changed) {
                    (false, false) => continue, // identical, skip
                    (true, false) => ChangeKind::Renamed,
                    (false, true) => ChangeKind::Modified,
                    (true, true) => ChangeKind::RenamedModified,
                };
                report
                    .modified
                    .push(ChangeEntry { kind, before: Some(b.clone()), after: Some(a.clone()) });
            }
            (Some(b), None) => report.removed.push(ChangeEntry {
                kind: ChangeKind::Removed,
                before: Some(b.clone()),
                after: None,
            }),
            (None, Some(a)) => report.added.push(ChangeEntry {
                kind: ChangeKind::Added,
                before: None,
                after: Some(a.clone()),
            }),
            (None, None) => {}
        }
    }
    drop(it);
    drop(stmt);

    // --- 2. PATH-based JOIN: classifies Replaced (same path, FRN changed) ---
    let q_path = r#"
        SELECT
            b.volume, b.frn, b.path, b.size, b.mtime, b.sha256,
            a.frn,    a.size,  a.mtime,  a.sha256
        FROM (SELECT volume, frn, path, size, mtime, sha256 FROM files
              WHERE snapshot_id = ?1 AND is_dir = 0) b
        JOIN  (SELECT volume, frn, path, size, mtime, sha256 FROM files
              WHERE snapshot_id = ?2 AND is_dir = 0) a
            ON a.volume = b.volume AND a.path = b.path
        WHERE a.frn <> b.frn
    "#;
    let mut stmt = conn.prepare(q_path)?;
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

    Ok(report)
}

fn make_side(
    vol: Option<String>,
    frn: Option<i64>,
    path: Option<String>,
    size: Option<i64>,
    mtime: Option<i64>,
    sha: Option<Vec<u8>>,
) -> Option<FileSide> {
    match (vol, frn, path, size, mtime) {
        (Some(v), Some(f), Some(p), Some(s), Some(m)) => Some(FileSide {
            volume: v,
            frn: f as u64,
            path: p,
            size: s as u64,
            mtime: m,
            sha256_hex: sha.as_ref().map(hex),
        }),
        _ => None,
    }
}

fn content_changed(b: &FileSide, a: &FileSide) -> bool {
    match (&b.sha256_hex, &a.sha256_hex) {
        (Some(x), Some(y)) => x != y,
        // hash missing — fall back to size+mtime
        _ => b.size != a.size || b.mtime != a.mtime,
    }
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
