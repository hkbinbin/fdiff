//! PE-aware hasher. Walks the just-written snapshot rows in the DB, filters to
//! PE-like files (extension OR `MZ` magic), hashes them in parallel with rayon
//! and bulk-updates the rows.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// Lowercased extensions we always hash without peeking at the header.
pub const PE_EXTS: &[&str] = &[
    "exe", "dll", "sys", "scr", "cpl", "ocx", "drv", "efi", "pyd", "com",
];

/// Skip files larger than this (default 200 MB) — payloads in malware-cheat
/// scenarios are virtually always far smaller.
pub const SIZE_LIMIT: u64 = 200 * 1024 * 1024;

pub struct HashOptions {
    pub with_blake3: bool,
}

#[derive(Default, Clone, Copy)]
pub struct HashStats {
    pub considered: u64,
    pub hashed: u64,
    pub failed: u64,
}

struct Row {
    volume: String,
    frn: i64,
    path: String,
    #[allow(dead_code)]
    size: u64,
}

pub fn hash_snapshot(conn: &mut Connection, snapshot_id: i64, opts: &HashOptions) -> Result<HashStats> {
    // 1. Collect candidate rows from DB.
    let rows: Vec<Row> = {
        let mut stmt = conn.prepare(
            "SELECT volume, frn, path, size FROM files
             WHERE snapshot_id = ?1 AND is_dir = 0 AND size > 0 AND size <= ?2",
        )?;
        let it = stmt.query_map(rusqlite::params![snapshot_id, SIZE_LIMIT as i64], |r| {
            Ok(Row {
                volume: r.get(0)?,
                frn: r.get(1)?,
                path: r.get(2)?,
                size: r.get::<_, i64>(3)? as u64,
            })
        })?;
        it.filter_map(|x| x.ok()).collect()
    };

    // 2. Pre-filter cheaply by extension; ambiguous ones (no PE ext) get a
    //    magic check inside the worker.
    let candidates: Vec<Row> = rows
        .into_iter()
        .filter(|r| ext_is_pe(&r.path) || true) // ext+magic both attempted in worker
        .collect();

    let considered = candidates.len() as u64;
    let pb = ProgressBar::new(considered);
    pb.set_style(
        ProgressStyle::with_template("[hash] {bar:40.cyan/blue} {pos}/{len}  {msg}")
            .unwrap()
            .progress_chars("=>-"),
    );

    // Parallelism = physical cores to avoid HDD thrash.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_cpus::get_physical().max(1))
        .build()
        .context("rayon pool")?;

    let results: Vec<HashResult> = pool.install(|| {
        candidates
            .par_iter()
            .map(|row| {
                pb.inc(1);
                hash_one(row, opts)
            })
            .collect()
    });
    pb.finish_and_clear();

    // 3. Bulk update the rows in one transaction.
    let mut hashed = 0u64;
    let mut failed = 0u64;
    {
        let tx = conn.transaction()?;
        {
            let mut up = tx.prepare_cached(
                "UPDATE files SET sha256 = ?1, blake3 = ?2 WHERE snapshot_id = ?3 AND volume = ?4 AND frn = ?5",
            )?;
            for r in results {
                match r {
                    HashResult::Hashed { sha, b3, volume, frn } => {
                        up.execute(rusqlite::params![sha, b3, snapshot_id, volume, frn])?;
                        hashed += 1;
                    }
                    HashResult::Skipped => {}
                    HashResult::Failed => {
                        failed += 1;
                    }
                }
            }
        }
        tx.commit()?;
    }

    Ok(HashStats {
        considered,
        hashed,
        failed,
    })
}

enum HashResult {
    Hashed {
        sha: Option<Vec<u8>>,
        b3: Option<Vec<u8>>,
        volume: String,
        frn: i64,
    },
    Skipped,
    Failed,
}

fn hash_one(row: &Row, opts: &HashOptions) -> HashResult {
    let path = Path::new(&row.path);
    let ext_match = ext_is_pe(&row.path);

    // Open with backup semantics-friendly defaults.
    let f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return HashResult::Failed,
    };

    let mut reader = BufReader::with_capacity(64 * 1024, f);

    // If extension doesn't match a PE-type, peek 2 bytes for "MZ".
    if !ext_match {
        let mut head = [0u8; 2];
        if reader.read(&mut head).unwrap_or(0) < 2 || &head != b"MZ" {
            return HashResult::Skipped;
        }
        // Reset state by re-opening — we already consumed 2 bytes and we want
        // the full file in the hash.
        let f2 = match File::open(path) {
            Ok(f) => f,
            Err(_) => return HashResult::Failed,
        };
        reader = BufReader::with_capacity(64 * 1024, f2);
    }

    let mut sha = Sha256::new();
    let mut b3 = if opts.with_blake3 {
        Some(blake3::Hasher::new())
    } else {
        None
    };

    let mut buf = [0u8; 64 * 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                sha.update(&buf[..n]);
                if let Some(h) = b3.as_mut() {
                    h.update(&buf[..n]);
                }
            }
            Err(_) => return HashResult::Failed,
        }
    }

    let sha_out: Vec<u8> = sha.finalize().to_vec();
    let b3_out = b3.map(|h| h.finalize().as_bytes().to_vec());

    HashResult::Hashed {
        sha: Some(sha_out),
        b3: b3_out,
        volume: row.volume.clone(),
        frn: row.frn,
    }
}

fn ext_is_pe(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if let Some(idx) = lower.rfind('.') {
        let ext = &lower[idx + 1..];
        return PE_EXTS.iter().any(|x| *x == ext);
    }
    false
}

/// Silence unused-import warning for Mutex pulled in for future expansion.
#[allow(dead_code)]
fn _shut_up(_: Mutex<()>) {}
