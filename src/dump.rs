//! `--dump` implementation: copy every changed PE file to a directory, also
//! emit a manifest.json that captures original paths + hashes.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::diff::{ChangeKind, DiffReport, FileSide};
use crate::hasher::PE_EXTS;

#[derive(Debug, Serialize)]
struct ManifestEntry {
    kind: String,
    side: &'static str, // "before" / "after"
    original_path: String,
    volume: String,
    frn: u64,
    size: u64,
    mtime: i64,
    sha256_hex: Option<String>,
    dumped_to: String,
}

pub fn dump_changes(rep: &DiffReport, out: &Path) -> Result<usize> {
    fs::create_dir_all(out).with_context(|| format!("create_dir_all {:?}", out))?;
    let mut manifest: Vec<ManifestEntry> = Vec::new();
    let mut used_names: BTreeSet<String> = BTreeSet::new();

    let mut dump = |side: &FileSide, side_tag: &'static str, kind: &ChangeKind| -> Result<()> {
        if !pe_like(&side.path) {
            return Ok(());
        }
        let src = Path::new(&side.path);
        let file_name = src
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unnamed.bin".into());
        let sha_prefix = side
            .sha256_hex
            .as_deref()
            .map(|s| &s[..s.len().min(16)])
            .unwrap_or("nohash");
        let mut target_name = format!("{}_{}_{}", sha_prefix, side_tag, file_name);
        // Disambiguate dupes (same hash + side + filename across volumes).
        let mut counter = 1u32;
        while used_names.contains(&target_name) {
            target_name = format!("{}_{}_{}_{}", sha_prefix, side_tag, counter, file_name);
            counter += 1;
        }
        used_names.insert(target_name.clone());

        let dst = out.join(&target_name);
        let copied = copy_file(src, &dst);
        let dumped_to = if copied.is_ok() {
            target_name.clone()
        } else {
            format!("<error: {}>", copied.unwrap_err())
        };

        manifest.push(ManifestEntry {
            kind: format!("{:?}", kind),
            side: side_tag,
            original_path: side.path.clone(),
            volume: side.volume.clone(),
            frn: side.frn,
            size: side.size,
            mtime: side.mtime,
            sha256_hex: side.sha256_hex.clone(),
            dumped_to,
        });
        Ok(())
    };

    for it in &rep.added {
        if let Some(a) = &it.after {
            dump(a, "after", &it.kind)?;
        }
    }
    for it in &rep.removed {
        if let Some(b) = &it.before {
            dump(b, "before", &it.kind)?;
        }
    }
    for it in &rep.modified {
        if let Some(b) = &it.before {
            dump(b, "before", &it.kind)?;
        }
        if let Some(a) = &it.after {
            dump(a, "after", &it.kind)?;
        }
    }
    for it in &rep.replaced {
        if let Some(b) = &it.before {
            dump(b, "before", &it.kind)?;
        }
        if let Some(a) = &it.after {
            dump(a, "after", &it.kind)?;
        }
    }

    let manifest_path = out.join("manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("writing {:?}", manifest_path))?;
    Ok(manifest.len())
}

fn pe_like(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if let Some(idx) = lower.rfind('.') {
        let ext = &lower[idx + 1..];
        if PE_EXTS.iter().any(|x| *x == ext) {
            return true;
        }
    }
    // Cheap MZ-header check for files lacking PE extensions.
    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        let mut head = [0u8; 2];
        if f.read(&mut head).unwrap_or(0) >= 2 && &head == b"MZ" {
            return true;
        }
    }
    false
}

fn copy_file(src: &Path, dst: &PathBuf) -> std::result::Result<(), String> {
    // std::fs::copy already wraps CopyFileW under the hood on Windows and
    // preserves the timestamps of the destination filename component fine for
    // our triage use case. We don't need ACL preservation here.
    fs::copy(src, dst).map(|_| ()).map_err(|e| e.to_string())
}
