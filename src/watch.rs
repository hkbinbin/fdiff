//! Real-time watch mode.
//!
//! Streams USN-Journal events from every (selected) NTFS volume and prints a
//! one-line summary per event. Stop with Ctrl-C.
//!
//! Implementation strategy:
//! - One blocking reader thread per volume; each owns a `ntfs_reader::Journal`.
//! - Threads push parsed events into a single MPMC channel.
//! - The main thread pulls events, applies filters, dedups noisy bursts,
//!   prints colored output, and (optionally) copies/hashes PE files to a
//!   sink directory + appends to manifest.json.
//! - A `running` AtomicBool flipped by the Ctrl-C handler tells the reader
//!   threads to stop polling and exit cleanly.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io::{Read, Write as _};
use std::mem::size_of;
use std::os::raw::c_void;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossbeam_channel::{bounded, Sender};
use ntfs_reader::journal::{Journal, JournalOptions, NextUsn};
use ntfs_reader::volume::Volume;
use serde::Serialize;
use sha2::{Digest, Sha256};
use windows::core::PCSTR;
use windows::Win32::{
    Foundation,
    Storage::FileSystem,
    System::{Ioctl, IO},
};

use crate::config::CompiledRules;
use crate::hasher::PE_EXTS;
use crate::volume::{enumerate_ntfs_volumes, NtfsVolume};

const REASON_FILE_CREATE: u32 = 0x0000_0100;
const REASON_FILE_DELETE: u32 = 0x0000_0200;
const REASON_DATA_EXTEND: u32 = 0x0000_0002;
const REASON_DATA_OVERWRITE: u32 = 0x0000_0001;
const REASON_DATA_TRUNCATION: u32 = 0x0000_0004;
const REASON_RENAME_NEW_NAME: u32 = 0x0000_2000;
const REASON_RENAME_OLD_NAME: u32 = 0x0000_1000;
const REASON_BASIC_INFO_CHANGE: u32 = 0x0000_8000;
const REASON_CLOSE: u32 = 0x8000_0000;

/// Events we actually surface to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum EventKind {
    /// File newly created.
    Created,
    /// File deleted.
    Deleted,
    /// File data changed (write / overwrite / truncate).
    Modified,
    /// File renamed (we surface the NEW name).
    Renamed,
}

impl EventKind {
    fn tag(&self) -> &'static str {
        match self {
            EventKind::Created => "[+]",
            EventKind::Deleted => "[-]",
            EventKind::Modified => "[M]",
            EventKind::Renamed => "[R]",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WatchEvent {
    pub timestamp: i64, // unix epoch seconds (local clock)
    pub volume: String,
    pub kind: EventKind,
    pub path: String,
    pub renamed_from: Option<String>,
    /// Hash filled in by the worker if --dump or hashing was requested.
    pub sha256_hex: Option<String>,
    pub size: Option<u64>,
}

#[derive(Debug)]
enum WatchMessage {
    Event(WatchEvent),
    ReaderError { volume: String, error: String },
}

#[derive(Default)]
pub struct WatchOptions {
    pub volumes: Vec<String>,
    pub ext_filter: Vec<String>,
    pub exclusions: CompiledRules,
    pub dump_dir: Option<PathBuf>,
    pub json: bool,
    #[allow(dead_code)]
    pub no_close_events: bool,
}

pub fn run_watch(opts: WatchOptions) -> Result<()> {
    // Select volumes.
    let mut vols = enumerate_ntfs_volumes()?;
    if !opts.volumes.is_empty() {
        let wanted: Vec<String> = opts
            .volumes
            .iter()
            .map(|v| {
                v.trim()
                    .trim_end_matches('\\')
                    .trim_end_matches(':')
                    .to_uppercase()
            })
            .collect();
        vols.retain(|v| {
            let lab = v.label().to_uppercase();
            wanted
                .iter()
                .any(|w| lab == *w || lab.trim_end_matches(':') == *w)
        });
    }
    if vols.is_empty() {
        anyhow::bail!("no matching NTFS volumes");
    }
    eprintln!(
        "fdiff watch on: {}",
        vols.iter()
            .map(|v| v.label())
            .collect::<Vec<_>>()
            .join(", ")
    );
    if !opts.ext_filter.is_empty() {
        eprintln!("  filter: .{}", opts.ext_filter.join(", ."));
    }
    if let Some(dir) = &opts.dump_dir {
        eprintln!("  dump dir: {}", dir.display());
        fs::create_dir_all(dir).with_context(|| format!("create dump dir {:?}", dir))?;
    }
    eprintln!("  press Ctrl-C to stop\n");

    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .context("installing Ctrl-C handler")?;
    }

    let (tx, rx) = bounded::<WatchMessage>(4096);
    let reader_count = vols.len();

    // Spawn one reader per volume.
    let mut handles = Vec::new();
    for v in vols {
        let label = v.label();
        let txc = tx.clone();
        let rc = running.clone();
        let handle = thread::Builder::new()
            .name(format!("fdiff-watch-{label}"))
            .spawn(move || {
                if let Err(e) = reader_loop(v, txc.clone(), rc) {
                    let _ = txc.send(WatchMessage::ReaderError {
                        volume: label,
                        error: format!("{e:#}"),
                    });
                }
            })?;
        handles.push(handle);
    }
    drop(tx); // we only hold receiver in this thread now

    // Cross-volume rename pairing buffer: NEW_NAME might arrive before
    // OLD_NAME's history is processed inside the library, but the library
    // already pairs them via match_rename when reading from the same Journal.
    // We also dedup quick repeated writes on the same path (1 second window).
    let mut last_emit: HashMap<(String, EventKind), Instant> = HashMap::new();
    let dedup_window = Duration::from_millis(800);

    let mut manifest_file = if let Some(dir) = &opts.dump_dir {
        Some(open_manifest(dir)?)
    } else {
        None
    };
    let mut reader_errors = Vec::new();

    // Drain channel until all readers exit OR ctrl-c.
    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(WatchMessage::ReaderError { volume, error }) => {
                let line = format!("[{volume}] reader failed: {error}");
                eprintln!("{line}");
                reader_errors.push(line);
            }
            Ok(WatchMessage::Event(mut ev)) => {
                if !should_emit_event(&ev, &opts) {
                    continue;
                }

                // Dedup very quick repeats.
                let key = (ev.path.clone(), ev.kind);
                let now = Instant::now();
                if let Some(prev) = last_emit.get(&key) {
                    if now.duration_since(*prev) < dedup_window {
                        continue;
                    }
                }
                last_emit.insert(key, now);

                // Optional: hash + copy to dump dir (only for Created / Modified,
                // and only PE-looking files we can still read).
                if let Some(dir) = &opts.dump_dir {
                    if matches!(
                        ev.kind,
                        EventKind::Created | EventKind::Modified | EventKind::Renamed
                    ) {
                        let _ = hash_and_dump(&mut ev, dir, manifest_file.as_mut());
                    }
                }

                print_event(&ev, opts.json);
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }

    // Wait for readers; they poll `running` every cycle.
    for h in handles {
        if h.join().is_err() {
            reader_errors.push("reader thread panicked".to_string());
        }
    }
    if running.load(Ordering::SeqCst)
        && !reader_errors.is_empty()
        && reader_errors.len() >= reader_count
    {
        anyhow::bail!("all watch readers failed");
    }
    eprintln!("\nfdiff watch: stopped.");
    Ok(())
}

fn reader_loop(vol: NtfsVolume, tx: Sender<WatchMessage>, running: Arc<AtomicBool>) -> Result<()> {
    // Open as Volume. For the journal we want the \\?\ form per the lib example.
    let path = match vol.mount.as_ref() {
        Some(m) => {
            let letter = m.trim_end_matches('\\').trim_end_matches(':');
            if letter.len() == 1 {
                format!("\\\\?\\{}:", letter)
            } else {
                vol.guid_path.trim_end_matches('\\').to_string()
            }
        }
        None => vol.guid_path.trim_end_matches('\\').to_string(),
    };
    let volume = Volume::new(&path).with_context(|| format!("opening volume {path}"))?;

    let mut journal = open_journal_or_create(&path, volume)
        .with_context(|| format!("opening USN journal of {path}"))?;

    let label = vol.label();
    let mount = vol.mount.clone();
    while running.load(Ordering::SeqCst) {
        let events = match journal.read() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[{}] journal.read error: {e:#}", label);
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        };
        if events.is_empty() {
            // Cheap throttle when idle.
            std::thread::sleep(Duration::from_millis(150));
            continue;
        }
        for rec in events {
            let kind = classify(rec.reason);
            let kind = match kind {
                Some(k) => k,
                None => continue,
            };

            // Pair RENAME_NEW_NAME with the matching old name from the
            // library's history buffer. We only ever surface the NEW-side.
            let renamed_from = if kind == EventKind::Renamed {
                journal
                    .match_rename(&rec)
                    .map(|p| format_record_path(&p, mount.as_deref()))
            } else if rec.reason & REASON_RENAME_OLD_NAME != 0 {
                // Drop the OLD half — we'll emit the NEW half instead.
                continue;
            } else {
                None
            };

            let ev = WatchEvent {
                timestamp: chrono::Utc::now().timestamp(),
                volume: label.clone(),
                kind,
                path: format_record_path(&rec.path, mount.as_deref()),
                renamed_from,
                sha256_hex: None,
                size: None,
            };
            if tx.send(WatchMessage::Event(ev)).is_err() {
                return Ok(()); // receiver gone
            }
        }
    }
    Ok(())
}

fn should_emit_event(ev: &WatchEvent, opts: &WatchOptions) -> bool {
    if opts.exclusions.excludes(&ev.path) {
        return false;
    }
    if !opts.ext_filter.is_empty() {
        let ext = ext_of(&ev.path);
        if !opts.ext_filter.iter().any(|e| e == &ext) {
            return false;
        }
    }
    true
}

fn open_journal_or_create(path: &str, volume: Volume) -> Result<Journal> {
    let options = JournalOptions {
        // Start from current end-of-journal so we only see live events.
        next_usn: NextUsn::Next,
        ..Default::default()
    };

    match Journal::new(volume, options.clone()) {
        Ok(journal) => Ok(journal),
        Err(first_err) => {
            create_usn_journal(path).with_context(|| {
                format!(
                    "USN journal was not usable and creating it failed; original open error: {first_err:#}"
                )
            })?;
            let volume = Volume::new(path)
                .with_context(|| format!("reopening volume {path} after creating USN journal"))?;
            Journal::new(volume, options)
                .with_context(|| format!("opening newly-created USN journal of {path}"))
        }
    }
}

fn create_usn_journal(path: &str) -> Result<()> {
    const DEFAULT_USN_MAX_SIZE: u64 = 32 * 1024 * 1024;
    const DEFAULT_USN_ALLOCATION_DELTA: u64 = 4 * 1024 * 1024;

    let c_path = CString::new(path).context("volume path contains an interior NUL byte")?;
    unsafe {
        let handle = FileSystem::CreateFileA(
            PCSTR::from_raw(c_path.as_bytes_with_nul().as_ptr()),
            (FileSystem::FILE_GENERIC_READ | FileSystem::FILE_GENERIC_WRITE).0,
            FileSystem::FILE_SHARE_READ
                | FileSystem::FILE_SHARE_WRITE
                | FileSystem::FILE_SHARE_DELETE,
            None,
            FileSystem::OPEN_EXISTING,
            FileSystem::FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .with_context(|| format!("opening volume {path} to create USN journal"))?;

        let data = Ioctl::CREATE_USN_JOURNAL_DATA {
            MaximumSize: DEFAULT_USN_MAX_SIZE,
            AllocationDelta: DEFAULT_USN_ALLOCATION_DELTA,
        };
        let mut bytes_returned = 0u32;
        let result = IO::DeviceIoControl(
            handle,
            Ioctl::FSCTL_CREATE_USN_JOURNAL,
            Some(&data as *const _ as *const c_void),
            size_of::<Ioctl::CREATE_USN_JOURNAL_DATA>() as u32,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        );
        let _ = Foundation::CloseHandle(handle);
        result.with_context(|| format!("FSCTL_CREATE_USN_JOURNAL on {path}"))?;
    }

    Ok(())
}

fn format_record_path(path: &Path, mount: Option<&str>) -> String {
    let s = path.to_string_lossy().to_string();

    if let Some(label) = mount.and_then(drive_label_from_mount) {
        let extended = format!("\\\\?\\{label}");
        if let Some(rest) = strip_prefix_ignore_ascii_case(&s, &extended) {
            return format!("{label}{rest}");
        }

        let device = format!("\\\\.\\{label}");
        if let Some(rest) = strip_prefix_ignore_ascii_case(&s, &device) {
            return format!("{label}{rest}");
        }

        if !is_windows_qualified_path(&s) {
            if s.starts_with('\\') || s.starts_with('/') {
                return format!("{label}{s}");
            }
            return format!("{label}\\{s}");
        }
    }

    if let Some(stripped) = strip_drive_extended_prefix(&s) {
        return stripped;
    }

    s
}

fn drive_label_from_mount(mount: &str) -> Option<String> {
    let label = mount.trim_end_matches('\\').trim_end_matches('/');
    let bytes = label.as_bytes();
    if bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        Some(label.to_string())
    } else {
        None
    }
}

fn strip_prefix_ignore_ascii_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

fn strip_drive_extended_prefix(s: &str) -> Option<String> {
    let rest = strip_prefix_ignore_ascii_case(s, "\\\\?\\")?;
    let bytes = rest.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        Some(rest.to_string())
    } else {
        None
    }
}

fn is_windows_qualified_path(s: &str) -> bool {
    let bytes = s.as_bytes();
    (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
        || s.starts_with("\\\\")
        || s.starts_with("//")
}

fn classify(reason: u32) -> Option<EventKind> {
    // Pick the most informative tag. We get many records per "logical change"
    // because USN emits one record per reason bit + a final one on CLOSE.
    // Strategy: only emit on CLOSE — by then all relevant bits are OR'd in.
    if reason & REASON_CLOSE == 0 {
        return None;
    }
    if reason & REASON_FILE_DELETE != 0 {
        return Some(EventKind::Deleted);
    }
    if reason & REASON_FILE_CREATE != 0 {
        return Some(EventKind::Created);
    }
    if reason & REASON_RENAME_NEW_NAME != 0 {
        return Some(EventKind::Renamed);
    }
    if reason & (REASON_DATA_EXTEND | REASON_DATA_OVERWRITE | REASON_DATA_TRUNCATION) != 0 {
        return Some(EventKind::Modified);
    }
    // Other reasons (security change, basic info etc.) → not interesting for forensics.
    let _ = REASON_BASIC_INFO_CHANGE;
    None
}

fn print_event(ev: &WatchEvent, json: bool) {
    if json {
        if let Ok(s) = serde_json::to_string(ev) {
            // jsonl: one event per line, flushed immediately.
            println!("{}", s);
            let _ = std::io::stdout().flush();
        }
        return;
    }
    use chrono::TimeZone;
    let ts = chrono::Local
        .timestamp_opt(ev.timestamp, 0)
        .single()
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "?".into());

    let sha = ev.sha256_hex.as_deref().unwrap_or("");
    let sha_short = if sha.len() >= 16 { &sha[..16] } else { sha };
    let size = ev
        .size
        .map(|s| format!("{:>10}", s))
        .unwrap_or_else(|| "          ".into());

    match ev.kind {
        EventKind::Renamed => {
            let from = ev.renamed_from.as_deref().unwrap_or("?");
            println!(
                "{}  {}  {}  {}  {}  <- {}",
                ts,
                ev.kind.tag(),
                size,
                sha_short,
                ev.path,
                from
            );
        }
        _ => {
            println!(
                "{}  {}  {}  {}  {}",
                ts,
                ev.kind.tag(),
                size,
                sha_short,
                ev.path
            );
        }
    }
    let _ = std::io::stdout().flush();
}

fn hash_and_dump(
    ev: &mut WatchEvent,
    dir: &Path,
    mut manifest: Option<&mut fs::File>,
) -> Result<()> {
    let p = Path::new(&ev.path);
    if !pe_like(&ev.path) {
        return Ok(());
    }
    let mut f = match fs::File::open(p) {
        Ok(f) => f,
        Err(_) => return Ok(()), // file might already be gone; ignore
    };
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    if size == 0 || size > 200 * 1024 * 1024 {
        return Ok(());
    }

    let mut sha = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => sha.update(&buf[..n]),
            Err(_) => return Ok(()),
        }
    }
    let digest = sha.finalize();
    let hex = digest_to_hex(&digest);
    ev.sha256_hex = Some(hex.clone());
    ev.size = Some(size);

    // Copy the file once per (sha256, basename). If we already have it, skip.
    let name = p
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "unnamed.bin".into());
    let prefix: String = hex.chars().take(16).collect();
    let target_name = format!("{}_{}", prefix, name);
    let target = dir.join(&target_name);
    if !target.exists() {
        // Best-effort copy; never crash watch on failure.
        let _ = fs::copy(p, &target);
    }

    if let Some(m) = manifest.as_mut() {
        let entry = serde_json::json!({
            "timestamp": ev.timestamp,
            "kind": format!("{:?}", ev.kind),
            "volume": ev.volume,
            "original_path": ev.path,
            "renamed_from": ev.renamed_from,
            "size": size,
            "sha256_hex": hex,
            "dumped_to": target_name,
        });
        let _ = writeln!(m, "{}", entry);
    }
    Ok(())
}

fn open_manifest(dir: &Path) -> Result<fs::File> {
    let p = dir.join("watch_manifest.jsonl");
    let f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)
        .with_context(|| format!("opening manifest {:?}", p))?;
    Ok(f)
}

fn digest_to_hex(d: &impl AsRef<[u8]>) -> String {
    let mut s = String::with_capacity(d.as_ref().len() * 2);
    for b in d.as_ref() {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn ext_of(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    let start = lower
        .rfind(|c| c == '\\' || c == '/')
        .map(|i| i + 1)
        .unwrap_or(0);
    let name = &lower[start..];
    match name.rfind('.') {
        Some(i) if i > 0 && i + 1 < name.len() => name[i + 1..].to_string(),
        _ => String::new(),
    }
}

fn pe_like(path: &str) -> bool {
    let ext = ext_of(path);
    if PE_EXTS.iter().any(|e| *e == ext) {
        return true;
    }
    // MZ-magic peek for un/odd-extensioned PEs.
    if let Ok(mut f) = fs::File::open(path) {
        let mut head = [0u8; 2];
        if f.read(&mut head).unwrap_or(0) >= 2 && &head == b"MZ" {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_extended_drive_paths_for_mount() {
        assert_eq!(
            format_record_path(Path::new(r"\\?\X:\dir\file.txt"), Some("X:\\")),
            r"X:\dir\file.txt"
        );
    }

    #[test]
    fn prefixes_rooted_paths_with_mount() {
        assert_eq!(
            format_record_path(Path::new(r"\dir\file.txt"), Some("X:\\")),
            r"X:\dir\file.txt"
        );
    }

    #[test]
    fn keeps_guid_paths_extended() {
        let path = r"\\?\Volume{f083cf4e-4827-4258-9e8b-80073c25a5c5}\dir\file.txt";
        assert_eq!(format_record_path(Path::new(path), None), path);
    }

    #[test]
    fn config_regex_exclusions_suppress_watch_events() {
        let cfg = crate::config::Config {
            exclude_paths: vec![crate::config::ExcludeRule::regex(r"X:\Noise\.*")],
        };
        let opts = WatchOptions {
            exclusions: crate::config::compile(&cfg).unwrap(),
            ..Default::default()
        };
        let ev = WatchEvent {
            timestamp: 0,
            volume: "X:".to_string(),
            kind: EventKind::Created,
            path: r"X:\Noise\file.tmp".to_string(),
            renamed_from: None,
            sha256_hex: None,
            size: None,
        };

        assert!(!should_emit_event(&ev, &opts));
    }
}
