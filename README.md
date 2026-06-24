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
fdiff scan <name> --volumes C,D    # limit volumes
fdiff scan <name> --no-hash        # skip SHA-256 stage (fastest)
fdiff scan <name> --blake3         # also compute BLAKE3
fdiff scan <name> --exclude '**/$Recycle.Bin/**' --exclude '**/Windows/WinSxS/**'
fdiff list                         # list stored snapshots
fdiff rm <name>                    # delete a snapshot
fdiff diff <before> <after>        # console summary
fdiff diff <before> <after> --json # JSON for downstream scripts
fdiff diff <before> <after> --dump out\
                                   # console + copy all changed PEs + manifest.json
```

Default DB: `%LOCALAPPDATA%\fdiff\fdiff.db`. Override with `--db <path>`.

## What you'll see in `diff`

* **Added**     — new files (likely the dropper's payload).
* **Removed**   — deleted files.
* **Modified**  — same file (FRN), but size / mtime / hash changed.
* **Renamed**   — same FRN, different path. Same content moved.
* **RenamedModified** — same FRN, moved + content changed.
* **Replaced**  — **path is identical but FRN changed**. Original was deleted and a new file took its name. This is the classic DLL-hijack signature; it gets its own section in the report.

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
