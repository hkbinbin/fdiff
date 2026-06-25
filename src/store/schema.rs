//! Schema bootstrap and post-load index creation.

use anyhow::Result;
use rusqlite::Connection;

pub fn apply_pragmas(conn: &Connection) -> Result<()> {
    // page_size has to be set on a *fresh* DB before any table exists.
    conn.pragma_update(None, "page_size", 8192)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    // 256 MB page cache (negative = KiB).
    conn.pragma_update(None, "cache_size", -262_144)?;
    conn.pragma_update(None, "mmap_size", 268_435_456_i64)?;
    Ok(())
}

pub fn create_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS snapshots (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT NOT NULL UNIQUE,
            taken_at  INTEGER NOT NULL,
            host      TEXT,
            note      TEXT
        );

        CREATE TABLE IF NOT EXISTS files (
            snapshot_id INTEGER NOT NULL,
            volume      TEXT NOT NULL,
            frn         INTEGER NOT NULL,
            parent_frn  INTEGER NOT NULL,
            path        TEXT NOT NULL,
            name        TEXT NOT NULL,
            size        INTEGER NOT NULL,
            mtime       INTEGER NOT NULL,
            ctime       INTEGER NOT NULL,
            is_dir      INTEGER NOT NULL,
            sha256      BLOB,
            blake3      BLOB,
            PRIMARY KEY (snapshot_id, volume, frn)
        ) WITHOUT ROWID;
        "#,
    )?;
    Ok(())
}

/// Build query indices after a bulk insert. Doing this after-the-fact is much
/// faster than maintaining them during the loaders.
pub fn create_indexes(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE INDEX IF NOT EXISTS idx_files_path ON files(snapshot_id, volume, path);
        CREATE INDEX IF NOT EXISTS idx_files_sha  ON files(sha256);
        "#,
    )?;
    // Let the SQLite planner pick the right join order for diff queries.
    // Cheap on a fresh DB, dramatic effect on join cost.
    let _ = conn.execute_batch("ANALYZE;");
    Ok(())
}
