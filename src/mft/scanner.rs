//! MFT-driven scan. Iterates all in-use files on the given NTFS volume,
//! reconstructs their full path via the `ntfs-reader` `VecCache`, and emits
//! [`FileRecord`] structs to a channel.

use std::path::PathBuf;

use anyhow::{Context, Result};
use crossbeam_channel::Sender;
use ntfs_reader::file_info::{FileInfo, VecCache};
use ntfs_reader::mft::Mft;
use ntfs_reader::volume::Volume;

use crate::volume::NtfsVolume;

/// One filesystem record we persist per row.
#[derive(Debug, Clone)]
pub struct FileRecord {
    /// Volume label, e.g. "C:" — used as a key in DB.
    pub volume: String,
    /// MFT record number (low 48 bits of FRN).
    pub frn: u64,
    /// Parent MFT record number, looked up via FileInfo's path component logic.
    /// We don't get this directly from `ntfs-reader`; we reconstruct from path.
    pub parent_frn: u64,
    pub path: String,
    pub name: String,
    pub size: u64,
    pub mtime: i64, // unix epoch seconds
    pub ctime: i64,
    pub is_dir: bool,
}

pub struct ScanOptions {
    pub exclude: globset::GlobSet,
    /// Lowercased path prefixes; any file whose lowercased path starts with
    /// one of these is skipped. Paths are normalized to use backslashes and
    /// have no trailing separator.
    pub exclude_prefixes: Vec<String>,
    /// Compiled regexes to match against full path. Pre-compiled so the hot
    /// loop just does `re.is_match(path)`.
    pub exclude_regexes: Vec<regex::Regex>,
}

impl ScanOptions {
    /// Normalize a user-supplied path prefix for matching:
    /// - lowercased (Windows is case-insensitive)
    /// - forward slashes converted to backslashes
    /// - trailing backslash trimmed
    pub fn normalize_prefix(p: &str) -> String {
        let mut s = p.replace('/', "\\").to_ascii_lowercase();
        while s.ends_with('\\') {
            s.pop();
        }
        s
    }
}

pub fn scan_volume(
    vol: &NtfsVolume,
    opts: &ScanOptions,
    tx: &Sender<FileRecord>,
) -> Result<ScanStats> {
    let open_path = vol.open_path();
    let volume = Volume::new(&open_path)
        .with_context(|| format!("opening volume {open_path}"))?;
    let mft = Mft::new(volume).with_context(|| format!("loading MFT of {open_path}"))?;

    let mut cache = VecCache::default();
    let mut total = 0u64;
    let mut sent = 0u64;
    let mut skipped = 0u64;

    let vol_label = vol.label();

    // The library exposes `mft.files()` returning NtfsFile. For each, build
    // FileInfo with cache. parent_frn isn't directly exposed, but we can pull
    // it from get_best_file_name().parent() ourselves.
    for file in mft.files() {
        total += 1;

        let info = FileInfo::with_cache(&mft, &file, &mut cache);
        if info.path.as_os_str().is_empty() {
            // Couldn't reconstruct path; skip.
            skipped += 1;
            continue;
        }

        let path_str = path_to_string(&info.path);

        // 1) Path-prefix filter (cheap, case-insensitive).
        if !opts.exclude_prefixes.is_empty() {
            let lower = path_str.to_ascii_lowercase();
            if opts
                .exclude_prefixes
                .iter()
                .any(|p| starts_with_prefix(&lower, p))
            {
                skipped += 1;
                continue;
            }
        }

        // 2) Glob filter.
        if !opts.exclude.is_empty() && opts.exclude.is_match(&path_str) {
            skipped += 1;
            continue;
        }

        // 3) Regex filter.
        if !opts.exclude_regexes.is_empty()
            && opts.exclude_regexes.iter().any(|r| r.is_match(&path_str))
        {
            skipped += 1;
            continue;
        }

        let parent_frn = file
            .get_best_file_name(&mft)
            .map(|n| n.parent())
            .unwrap_or(0);

        let rec = FileRecord {
            volume: vol_label.clone(),
            frn: file.reference_number(),
            parent_frn,
            path: path_str,
            name: info.name,
            size: info.size,
            mtime: to_unix(info.modified),
            ctime: to_unix(info.created),
            is_dir: info.is_directory,
        };

        if tx.send(rec).is_err() {
            break; // receiver gone
        }
        sent += 1;
    }

    Ok(ScanStats {
        total,
        sent,
        skipped,
    })
}

fn to_unix(t: Option<time::OffsetDateTime>) -> i64 {
    t.map(|x| x.unix_timestamp()).unwrap_or(0)
}

fn path_to_string(p: &PathBuf) -> String {
    p.to_string_lossy().to_string()
}

/// True when `path` (already lowercased) begins with `prefix` at a path-component
/// boundary. Avoids spurious `C:\Foo` matching `C:\FooBar`.
fn starts_with_prefix(path: &str, prefix: &str) -> bool {
    if !path.starts_with(prefix) {
        return false;
    }
    match path.as_bytes().get(prefix.len()) {
        None => true,
        Some(b'\\') | Some(b'/') => true,
        _ => false,
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ScanStats {
    pub total: u64,
    pub sent: u64,
    pub skipped: u64,
}
