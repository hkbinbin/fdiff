//! Streaming SQLite writer: batch FileRecord -> INSERT in 50k-sized transactions.

use anyhow::Result;
use crossbeam_channel::Receiver;
use indicatif::{ProgressBar, ProgressStyle};
use rusqlite::Connection;

use crate::mft::FileRecord;

const BATCH: usize = 50_000;

pub fn drain_into_db(
    conn: &mut Connection,
    snapshot_id: i64,
    rx: Receiver<FileRecord>,
) -> Result<u64> {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner} {pos:>10} files written  {msg}")
            .unwrap()
            .tick_chars("⠁⠃⠇⡇⣇⣧⣷⣿"),
    );

    let mut total: u64 = 0;
    let mut buf: Vec<FileRecord> = Vec::with_capacity(BATCH);
    for rec in rx.iter() {
        buf.push(rec);
        if buf.len() >= BATCH {
            flush(conn, snapshot_id, &mut buf)?;
            total += BATCH as u64;
            pb.set_position(total);
        }
    }
    if !buf.is_empty() {
        let n = buf.len() as u64;
        flush(conn, snapshot_id, &mut buf)?;
        total += n;
    }
    pb.set_position(total);
    pb.finish_with_message("done");
    Ok(total)
}

fn flush(conn: &mut Connection, snapshot_id: i64, buf: &mut Vec<FileRecord>) -> Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare_cached(
            r#"
            INSERT OR REPLACE INTO files
              (snapshot_id, volume, frn, parent_frn, path, name,
               size, mtime, ctime, is_dir, sha256, blake3)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, NULL)
            "#,
        )?;
        for rec in buf.drain(..) {
            stmt.execute(rusqlite::params![
                snapshot_id,
                rec.volume,
                rec.frn as i64,
                rec.parent_frn as i64,
                rec.path,
                rec.name,
                rec.size as i64,
                rec.mtime,
                rec.ctime,
                rec.is_dir as i64,
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}
