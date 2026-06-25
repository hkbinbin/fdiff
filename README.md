# fdiff — Windows full-disk snapshot & diff (forensic CLI)

> Everything-style speed, made for **cheat / DLL-hijack post-mortem**:
> snapshot the whole disk before and after running a suspect program,
> then diff to see exactly what files it dropped.

Built in Rust. Reads `$MFT` directly through the [`ntfs-reader`](https://crates.io/crates/ntfs-reader) crate — millions of files in a few seconds.

---

## Download

Pre-built Windows binaries are published on the
[Releases page](https://github.com/hkbinbin/fdiff/releases) — grab the latest
`fdiff-vX.Y.Z-x86_64-windows.zip` (or the raw `fdiff.exe` for a single-file
install). Every asset is published alongside its SHA-256.

---

## Build

```bash
cargo build --release
```

Release binary: `target/release/fdiff.exe` (≈ 4 MB).
It embeds a `requireAdministrator` manifest, so launching it triggers a UAC prompt.

> **Need admin** — `fdiff` opens `\\.\C:` as raw block device to parse MFT.

## Quick start

```cmd
:: 1) take "before" snapshot of all NTFS volumes
fdiff scan before

:: 2) run the suspect program (cheat / dropper / installer) ...

:: 3) take "after" snapshot
fdiff scan after

:: 4) diff and dump every changed PE to a triage folder
fdiff diff before after --dump out\
```

`out\manifest.json` will contain — for every Added / Removed / Modified /
Renamed / **Replaced** PE — the original full path, volume, FRN, size, mtime,
**SHA-256**, and the file copied next to it for static analysis.

## Commands

```
fdiff volumes                      # list NTFS volumes
fdiff scan <name>                  # snapshot all NTFS volumes
fdiff scan <name> --volumes C,D    # whitelist volumes (only scan C and D)
fdiff scan <name> --exclude-volumes D,E
                                   # blacklist volumes (scan everything except D and E)
fdiff scan <name> --exclude-path "C:\Windows\WinSxS" --exclude-path "C:\Users\me\Downloads"
                                   # skip any file whose path starts with these prefixes (case-insensitive)
fdiff scan <name> --exclude '**/$Recycle.Bin/**' --exclude '**/Windows/SoftwareDistribution/**'
                                   # glob-based exclusion (matched against full path)
fdiff scan <name> --no-hash        # skip SHA-256 stage (fastest)
fdiff scan <name> --blake3         # also compute BLAKE3
fdiff watch                        # NEW: real-time monitor (USN journal). Ctrl-C to stop
fdiff watch --ext pe --dump live\  # only PE files; copy each to live\ with manifest
fdiff list                         # list stored snapshots
fdiff rm <name>                    # delete a snapshot
fdiff diff <before> <after>        # console summary (skips directories by default)
fdiff diff <before> <after> --json # JSON for downstream scripts
fdiff diff <before> <after> --dump out\
                                   # console + copy all changed PEs + manifest.json
fdiff diff <before> <after> --ext exe,dll,sys
                                   # only show files with these extensions
fdiff diff <before> <after> --ext pe
                                   # shortcut: expands to the full PE set
                                   # (exe, dll, sys, scr, cpl, ocx, drv, efi, pyd, com)
fdiff diff <before> <after> --exclude-path "C:\Users\me\Downloads"
                                   # hide a path prefix from this diff run
fdiff diff <before> <after> --include-dirs
                                   # also report directory changes (noisy)
fdiff diff <before> <after> --limit 200
                                   # cap each category to 200 rows (fast triage)
fdiff diff <before> <after> --include-self
                                   # don't auto-hide fdiff's own DB folder
```

> **Auto-hide of fdiff's own files.** Both `scan` and `diff` automatically
> drop anything inside fdiff's database directory (`%LOCALAPPDATA%\fdiff` plus
> whatever you pass with `--db`). Otherwise every snapshot would pick up its
> own SQLite WAL writes and the diff would be full of self-noise. Pass
> `--include-self` (diff) or just point `--db` outside the scanned volumes if
> you really want to see those rows.

### Filtering cheatsheet

* `--volumes C,D` — only scan these drive letters (whitelist).
* `--exclude-volumes D,E` — never scan these drive letters (blacklist).
  Applied after `--volumes`; the two compose naturally.
* `--exclude-path "<prefix>"` — drop any file whose full path **starts with**
  the given prefix. Forward slashes and trailing backslashes are normalized,
  comparison is case-insensitive, and matching only happens at path-component
  boundaries (so `--exclude-path C:\Foo` will not accidentally exclude
  `C:\FooBar`). Repeatable.
* `--exclude '<glob>'` — full-path glob exclusion. Use this when you need
  wildcards (`**/$Recycle.Bin/**`).

All three filters are applied during `scan` and the excluded files never
enter the snapshot. To restore them later, re-scan without the filter.

## Watch mode (real-time)

`fdiff watch` opens the NTFS USN journal on every selected volume and prints
a colored line for each file event in real time. Stop with **Ctrl-C**.

```cmd
:: monitor every NTFS volume (admin required)
fdiff watch

:: only watch system drive, only PE files, dump them out as they appear
fdiff watch --volumes C --ext pe --dump live\

:: tail-like JSONL for downstream tooling (one event per line)
fdiff watch --json | jq -c '. | select(.kind=="Created")'
```

Output (text mode):
```
2026-06-25 11:02:14  [+]      245760  a3f9c8721b58e90c  C:\Users\X\AppData\Local\Temp\loader.dll
2026-06-25 11:02:14  [M]       92160  d12fe1aa776c8e1b  C:\Windows\System32\version.dll
2026-06-25 11:02:15  [R]       17 408  -                 C:\Game\bin\d3d9.dll <- C:\Game\bin\d3d9.dll.bak
2026-06-25 11:02:16  [-]            -  -                 C:\Game\bin\old.dll
```

Tags: `[+]` Created, `[M]` Modified, `[R]` Renamed (`new <- old`), `[-]` Deleted.

What it does well:
* Zero polling — reads NTFS's own change journal, the same mechanism Everything
  uses for live updates.
* Picks up every change made by every process (user or system).
* `--dump <dir>` will copy each Created / Modified / Renamed **PE file** (by
  extension or by `MZ` magic) into the dir, prefixed by the first 16 hex
  characters of its SHA-256, and append a JSONL row per event to
  `watch_manifest.jsonl` in the same dir.
* `--ext`, `--exclude-path` and the automatic "skip fdiff's own directory"
  behave exactly like in `scan` / `diff`.

Caveats:
* NTFS only (no FAT32 / exFAT / ReFS).
* USN doesn't tell us **which** process caused a change. The hashes plus
  timestamps let you correlate with Process Monitor / ETW if you really need
  the PID.
* Rapid bursts of writes from a single process get coalesced (events on the
  same path + same kind within 800 ms are emitted only once).

Default DB: `%LOCALAPPDATA%\fdiff\fdiff.db`. Override with `--db <path>`.

## What you'll see in `diff`

* **Added**     — new files (likely the dropper's payload).
* **Removed**   — deleted files.
* **Modified**  — same file (FRN), but size / mtime / hash changed.
* **Renamed**   — same FRN, different path. Same content moved.
* **RenamedModified** — same FRN, moved + content changed.
* **Replaced**  — **path is identical but FRN changed**. Original was deleted and a new file took its name. This is the classic DLL-hijack signature; it gets its own section in the report.

### Diff performance

`fdiff diff` pushes nearly all filtering into SQLite. On a million-row snapshot
expect roughly:

| Phase                | Time (NVMe SSD) |
|----------------------|-----------------|
| Modified / Renamed   | 1–3 s |
| Added                | 1–2 s |
| Removed              | 1–2 s |
| Replaced             | 1–2 s |
| **Total**            | **~5–8 s** |

If your last diff was much slower than this, two likely causes:

1. **DB created before v0.3** — the indexes (`idx_files_path`, `idx_files_sha`)
   may be missing. `fdiff diff` now rebuilds them automatically on first run,
   then `ANALYZE` is invoked so the query planner picks merge joins. The
   first run after upgrade rebuilds them once; subsequent runs are fast.
2. **Comparing across millions of files including directories** — pass
   `--limit 500` for a triage view, or omit `--include-dirs` (default).

## Hash policy

PE files (`*.exe *.dll *.sys *.scr *.cpl *.ocx *.drv *.efi *.pyd *.com`) and
any file starting with the `MZ` magic ≤ 200 MB are hashed.

Default: **SHA-256** (so output is directly searchable on VirusTotal / threat
intel feeds). Pass `--blake3` to also record BLAKE3 in the same row.

## Performance notes (SSD, 100 W class CPU)

| Pass | Files | Time |
|---|---|---|
| MFT scan + DB insert | 1 000 000 | ≈ 5–10 s |
| SHA-256 of all PE files (≈ 30 k typical Windows install) | 30 000 | ≈ 30–60 s |

Hash parallelism is capped to physical cores to avoid HDD thrash.

## DB schema

```sql
CREATE TABLE snapshots (id, name UNIQUE, taken_at, host, note);
CREATE TABLE files (
    snapshot_id, volume, frn, parent_frn, path, name,
    size, mtime, ctime, is_dir, sha256 BLOB, blake3 BLOB,
    PRIMARY KEY (snapshot_id, volume, frn)
) WITHOUT ROWID;
```

You can also query the SQLite directly — e.g. `find every snapshot with the
same SHA-256` is a single `JOIN` on `idx_files_sha`.

## Source layout

```
src/
├── main.rs              entry + subcommand dispatch
├── cli.rs               clap structs
├── privilege.rs         admin check + SeBackupPrivilege
├── volume.rs            FindFirstVolumeW NTFS enumeration
├── mft/scanner.rs       ntfs-reader -> FileRecord stream
├── store/{mod,schema,writer}.rs
├── hasher.rs            rayon-parallel SHA-256/BLAKE3 with MZ-magic filter
├── diff.rs              FRN-join + path-join classifier
├── report.rs            console + JSON renderers
└── dump.rs              --dump out\ + manifest.json
```

## Limitations (out of scope this release)

* NTFS only. ReFS, FAT32, exFAT are intentionally skipped.
* No realtime/USN-incremental mode. Always two full snapshots.
* No Authenticode trust filtering — you'll see noise from Windows Update; use
  `--exclude '**/Windows/SoftwareDistribution/**'` etc. as a workaround.
