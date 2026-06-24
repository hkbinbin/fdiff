//! Snapshot DB facade: open, init schema, snapshot rows, file rows.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use rusqlite::{Connection, OptionalExtension};

pub mod schema;
pub mod writer;

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub id: i64,
    pub name: String,
    pub taken_at: i64,
    #[allow(dead_code)]
    pub host: Option<String>,
    pub note: Option<String>,
}

pub fn default_db_path() -> Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")
        .ok_or_else(|| anyhow!("LOCALAPPDATA env variable not set"))?;
    let mut p = PathBuf::from(local);
    p.push("fdiff");
    std::fs::create_dir_all(&p).context("create fdiff dir under LOCALAPPDATA")?;
    p.push("fdiff.db");
    Ok(p)
}

pub fn open(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let conn = Connection::open(path).with_context(|| format!("opening db at {:?}", path))?;
    schema::apply_pragmas(&conn)?;
    schema::create_schema(&conn)?;
    Ok(conn)
}

/// Insert a fresh snapshot row. Returns rowid. Fails if name already exists.
pub fn create_snapshot(conn: &Connection, name: &str, note: Option<&str>) -> Result<i64> {
    let host = hostname();
    let now = chrono::Utc::now().timestamp();
    conn.execute(
        "INSERT INTO snapshots (name, taken_at, host, note) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![name, now, host, note],
    )
    .with_context(|| format!("snapshot name '{name}' may already exist"))?;
    Ok(conn.last_insert_rowid())
}

pub fn delete_snapshot(conn: &Connection, name: &str) -> Result<u64> {
    let snap = find_snapshot(conn, name)?
        .ok_or_else(|| anyhow!("snapshot '{name}' not found"))?;
    let n1 = conn.execute(
        "DELETE FROM files WHERE snapshot_id = ?1",
        rusqlite::params![snap.id],
    )?;
    let _ = conn.execute(
        "DELETE FROM snapshots WHERE id = ?1",
        rusqlite::params![snap.id],
    )?;
    Ok(n1 as u64)
}

pub fn list_snapshots(conn: &Connection) -> Result<Vec<Snapshot>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, taken_at, host, note FROM snapshots ORDER BY taken_at DESC",
    )?;
    let it = stmt.query_map([], |r| {
        Ok(Snapshot {
            id: r.get(0)?,
            name: r.get(1)?,
            taken_at: r.get(2)?,
            host: r.get(3)?,
            note: r.get(4)?,
        })
    })?;
    Ok(it.filter_map(|x| x.ok()).collect())
}

pub fn find_snapshot(conn: &Connection, name: &str) -> Result<Option<Snapshot>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, taken_at, host, note FROM snapshots WHERE name = ?1",
    )?;
    let s = stmt
        .query_row(rusqlite::params![name], |r| {
            Ok(Snapshot {
                id: r.get(0)?,
                name: r.get(1)?,
                taken_at: r.get(2)?,
                host: r.get(3)?,
                note: r.get(4)?,
            })
        })
        .optional()?;
    Ok(s)
}

fn hostname() -> Option<String> {
    std::env::var("COMPUTERNAME").ok()
}
