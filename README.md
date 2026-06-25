# fdiff — Windows full-disk snapshot, diff & live watch (forensic CLI)

> Everything-style speed, made for **cheat / DLL-hijack / dropper post-mortem**.
> Snapshot the whole disk before and after running a suspect program,
> diff to see exactly what files it dropped — or `watch` in real time and
> just let it tell you as it happens.

Built in Rust. Reads NTFS `$MFT` and the USN change journal directly through
[`ntfs-reader`](https://crates.io/crates/ntfs-reader) — million-file scans in
a few seconds, monitoring is push-based (zero polling).

---

## Highlights

* **Whole-disk snapshot in seconds** — direct `$MFT` read, not directory walk.
* **Diff that catches DLL hijacks** — joins on NTFS file reference number to
  flag *Replaced* (same path, new FRN), not just Added/Modified.
* **Live watch mode** — subscribes to NTFS USN journal, prints one colored
  line per file event. Stops cleanly on Ctrl-C.
* **PE-aware hashing** — SHA-256 (optionally BLAKE3) for executables and
  anything with the `MZ` magic; skips bulk data.
* **`--dump <dir>`** — auto-collect every changed PE into a triage folder
  alongside a `manifest.json` / `watch_manifest.jsonl`.
* **Persistent exclusion config** — save your `--exclude-path` /
  `--exclude-regex` rules once; reused by every subsequent run.
* **Single static binary, no install** — ~4 MB, embeds an
  `requireAdministrator` manifest.

---

## Download

Pre-built Windows binaries are published on the
[Releases page](https://github.com/hkbinbin/fdiff/releases) — grab the latest
`fdiff-vX.Y.Z-x86_64-windows.zip` (or the raw `fdiff.exe` for a single-file
install). Every asset is published with its SHA-256.

You'll see a UAC prompt on launch: `fdiff` opens `\\.\C:` as a raw block
device, which requires administrator.

## Build from source

```bash
cargo build --release
```

Produces `target/release/fdiff.exe`.

---

## Quick start — "what did this program drop?"

```cmd
:: 1) snapshot all NTFS volumes
fdiff scan before

:: 2) run the suspect program (cheat / dropper / installer) ...

:: 3) snapshot again
fdiff scan after

:: 4) diff and dump every changed PE to a triage folder
fdiff diff before after --ext pe --dump triage\
```

`triage\manifest.json` will contain — for every Added / Removed / Modified /
Renamed / **Replaced** PE — the original full path, volume, FRN, size, mtime,
**SHA-256**, and the file copied next to it for static analysis.

## Quick start — "tell me as it happens"

```cmd
fdiff watch --volumes C --ext pe --dump live\
:: now launch the suspect program; events stream to the console
:: each new PE is copied into live\ as <sha16>_<filename>
:: Ctrl-C to stop
```

---

## Commands at a glance

```
fdiff volumes                                # list NTFS volumes
fdiff scan <name>                            # whole-disk snapshot
fdiff list                                   # list stored snapshots
fdiff rm   <name>                            # delete a snapshot
fdiff diff <before> <after>                  # compare two snapshots
fdiff watch                                  # real-time USN-journal monitor
fdiff config show | add | rm | reset | path  # manage persistent exclusion rules
```

Default DB: `%LOCALAPPDATA%\fdiff\fdiff.db`. Override anywhere with `--db <path>`.

### `scan`

```
fdiff scan <name>
fdiff scan <name> --volumes C,D              # whitelist drive letters
fdiff scan <name> --exclude-volumes D,E      # blacklist drive letters
fdiff scan <name> --exclude-path "<prefix>"  # prefix exclusion (repeatable)
fdiff scan <name> --exclude '<glob>'         # glob exclusion (repeatable)
fdiff scan <name> --exclude-regex '<regex>'  # regex exclusion (repeatable)
fdiff scan <name> --no-hash                  # skip the SHA-256 pass (fastest)
fdiff scan <name> --blake3                   # also compute BLAKE3
fdiff scan <name> --note "before cheat"      # free-form note
fdiff scan <name> --no-config                # ignore saved exclusion rules
```

### `diff`

```
fdiff diff <before> <after>
fdiff diff <before> <after> --ext exe,dll,sys     # only show these extensions
fdiff diff <before> <after> --ext pe              # shortcut for full PE set
fdiff diff <before> <after> --exclude-path <pfx>  # one-shot prefix hide
fdiff diff <before> <after> --exclude-regex <re>  # one-shot regex hide
fdiff diff <before> <after> --exclude <glob>      # one-shot glob hide
fdiff diff <before> <after> --include-dirs        # also report directory changes (noisy)
fdiff diff <before> <after> --include-self        # don't auto-hide fdiff's own DB folder
fdiff diff <before> <after> --limit 200           # cap each category (fast triage)
fdiff diff <before> <after> --json                # machine-readable
fdiff diff <before> <after> --dump triage\        # console + copy PEs + manifest.json
fdiff diff <before> <after> --no-config           # ignore saved exclusion rules
```

`diff` reports five kinds of change:

* **Added**     — new files (likely the dropper's payload).
* **Removed**   — deleted files.
* **Modified**  — same file (FRN), but size / mtime / hash changed.
* **Renamed**   — same FRN, different path. Content moved.
* **RenamedModified** — same FRN, moved + content changed.
* **Replaced**  — **path identical but FRN changed.** Original was deleted and a new file took its name — the classic DLL-hijack signature.

### `watch`

```
fdiff watch                              # monitor every NTFS volume
fdiff watch --volumes C                  # just the system drive
fdiff watch --ext pe --dump live\        # only PE files, auto-collect to live\
fdiff watch --exclude-path <pfx>
fdiff watch --exclude-regex <re>
fdiff watch --json | jq -c '.'           # JSONL stream
fdiff watch --include-self               # don't auto-hide fdiff's own DB folder
fdiff watch --no-config                  # ignore saved exclusion rules
```

Text-mode output:

```
2026-06-25 11:02:14  [+]      245760  a3f9c8721b58e90c  C:\Users\X\AppData\Local\Temp\loader.dll
2026-06-25 11:02:14  [M]       92160  d12fe1aa776c8e1b  C:\Windows\System32\version.dll
2026-06-25 11:02:15  [R]       17408  -                 C:\Game\bin\d3d9.dll <- C:\Game\bin\d3d9.dll.bak
2026-06-25 11:02:16  [-]            -  -                 C:\Game\bin\old.dll
```

`[+]` Created · `[M]` Modified · `[R]` Renamed (`new <- old`) · `[-]` Deleted.

What watch is good at:

* Zero polling — uses NTFS's own change journal, same mechanism Everything uses.
* Picks up every change made by every process (user-mode or kernel).
* `--dump <dir>` copies each Created / Modified / Renamed PE (by extension or
  `MZ` magic) into the dir, prefixed by 16 hex chars of SHA-256, and appends
  a JSONL row to `watch_manifest.jsonl`.

Caveats:

* NTFS only (no FAT32 / exFAT / ReFS).
* USN doesn't tell us which process caused the change. The hashes plus
  timestamps let you correlate with Process Monitor / ETW if you really need
  the PID.
* Rapid bursts get coalesced (same path + same kind within 800 ms → one event).

---

## Filters (cheatsheet)

| Flag | Where | Match |
|---|---|---|
| `--volumes C,D`           | `scan`               | drive-letter whitelist |
| `--exclude-volumes D,E`   | `scan`               | drive-letter blacklist |
| `--exclude-path "<pfx>"`  | `scan` / `diff` / `watch` | path prefix at component boundary, case-insensitive |
| `--exclude '<glob>'`      | `scan` / `diff`      | full-path glob (globset) |
| `--exclude-regex '<re>'`  | `scan` / `diff` / `watch` | full-path regex, case-insensitive by default |
| `--ext exe,dll,sys`       | `diff` / `watch`     | only these extensions (`--ext pe` expands to the full PE set) |
| `--include-dirs`          | `diff`               | also report directory entries |
| `--include-self`          | `diff` / `watch`     | don't auto-hide `%LOCALAPPDATA%\fdiff` |
| `--no-config`             | `scan` / `diff` / `watch` | ignore saved rules in `config.json` for this run |

### Auto-hide of fdiff's own files

By default `scan`, `diff` and `watch` automatically drop anything inside
fdiff's database directory (`%LOCALAPPDATA%\fdiff` plus whatever you pass with
`--db`). Otherwise every snapshot would pick up its own SQLite WAL writes and
the diff would be full of self-noise. Pass `--include-self` to see them.

---

## Persistent exclusion config (`fdiff config`)

Tired of typing the same `--exclude-path` every time? Save your rules once:

```cmd
fdiff config show                                          :: list current rules
fdiff config path                                          :: print config file location
fdiff config add "C:\Users\me\AppData\Local\Microsoft\Edge"
fdiff config add "**/$Recycle.Bin/**"            --kind glob
fdiff config add ".*\\ContentDeliveryManager.*"  --kind regex
fdiff config rm 2                                          :: remove rule #2
fdiff config rm "C:\Users\me\AppData\Local\Microsoft\Edge"
fdiff config reset                                         :: restore the shipped defaults
```

Rules live in `%LOCALAPPDATA%\fdiff\config.json` and are auto-applied by every
subsequent `scan`, `diff`, and `watch` run. Pass `--no-config` to disable for
a single invocation.

### Rule kinds

| Kind     | Match | Example |
|----------|-------|---------|
| `prefix` *(default)* | full path starts with this string at a component boundary, case-insensitive | `C:\Users\me\AppData\Local\Microsoft\Edge` |
| `glob`   | full-path glob (globset) | `${LOCALAPPDATA}\Packages\Microsoft.Windows.ContentDeliveryManager*` |
| `regex`  | full-path regex (Rust regex flavor), case-insensitive by default — prepend `(?-i)` to override | `.*\\AppData\\Local\\Temp\\.*\.tmp$` |

### Variables

You can embed `${LOCALAPPDATA}` or `%LOCALAPPDATA%` and they get expanded at
runtime, so the same config works across machines and accounts:

```json
{
  "exclude_paths": [
    { "kind": "prefix", "pattern": "${LOCALAPPDATA}\\Microsoft\\Edge" },
    { "kind": "prefix", "pattern": "${LOCALAPPDATA}\\Microsoft\\Windows" },
    { "kind": "glob",   "pattern": "${LOCALAPPDATA}\\Packages\\Microsoft.Windows.ContentDeliveryManager*" }
  ]
}
```

### Shipped defaults

On first run, fdiff seeds three rules to mute typical Windows-Update / Edge
noise:

* `${LOCALAPPDATA}\Microsoft\Edge`                                            *(prefix)*
* `${LOCALAPPDATA}\Microsoft\Windows`                                         *(prefix — WebCache etc.)*
* `${LOCALAPPDATA}\Packages\Microsoft.Windows.ContentDeliveryManager*`        *(glob)*

`fdiff config show` always prints the live set (including expanded paths).

---

## Hash policy

PE files (`*.exe *.dll *.sys *.scr *.cpl *.ocx *.drv *.efi *.pyd *.com`) and
anything starting with the `MZ` magic — up to 200 MB each — are hashed.

Default: **SHA-256** (so output is directly searchable on VirusTotal /
threat-intel feeds). Pass `--blake3` to also record BLAKE3 in the same row.

Hash parallelism is capped to physical cores to avoid HDD thrash.

---

## Performance (NVMe SSD, modern CPU)

| Operation | Workload | Time |
|---|---|---|
| `scan` (MFT + DB insert) | 1 000 000 files | ≈ 5–10 s |
| `scan` (hash pass)       | ≈ 30 000 PE files | ≈ 30–60 s |
| `diff` (Modified phase)  | 1 M / 1 M snapshot | 1–3 s |
| `diff` (Added/Removed)   | 1 M / 1 M snapshot | 1–2 s each |
| `diff` (Replaced)        | 1 M / 1 M snapshot | 1–2 s |
| `diff` **total**         | 1 M / 1 M snapshot | **~5–8 s** |
| `watch`                  | live | event latency well under 1 s |

`fdiff diff` pushes nearly all filtering into SQLite (`NOT EXISTS` for
Added/Removed, indexed PK merge join for Modified, `idx_files_path` for
Replaced). Indexes are rebuilt automatically on first diff if a DB was created
by an older version — and `ANALYZE` is run so the planner picks merge joins.

If a diff is much slower than the table above, two likely causes:

1. **DB created before v0.3** — indexes missing. `fdiff diff` now rebuilds
   them on first run; subsequent runs are fast.
2. **`--include-dirs` is on** — Windows constantly rewrites directory mtimes,
   producing thousands of noise rows. Drop the flag or pass `--limit 500`.

---

## DB schema

```sql
CREATE TABLE snapshots (id, name UNIQUE, taken_at, host, note);
CREATE TABLE files (
    snapshot_id, volume, frn, parent_frn, path, name,
    size, mtime, ctime, is_dir, sha256 BLOB, blake3 BLOB,
    PRIMARY KEY (snapshot_id, volume, frn)
) WITHOUT ROWID;
CREATE INDEX idx_files_path ON files(snapshot_id, volume, path);
CREATE INDEX idx_files_sha  ON files(sha256);
```

You can query the SQLite directly — e.g. *"find every file with the same
SHA-256 across all snapshots"* is a single JOIN on `idx_files_sha`.

---

## Source layout

```
src/
├── main.rs              entry + subcommand dispatch
├── cli.rs               clap structs
├── config.rs            persistent exclusion rules (config.json)
├── privilege.rs         admin check + SeBackupPrivilege
├── volume.rs            FindFirstVolumeW NTFS enumeration
├── mft/scanner.rs       ntfs-reader -> FileRecord stream
├── store/{mod,schema,writer}.rs  SQLite layer (WAL + batched inserts + ANALYZE)
├── hasher.rs            rayon-parallel SHA-256/BLAKE3 with MZ-magic filter
├── diff.rs              FRN-join + path-join classifier, runtime filters
├── watch.rs             USN-journal monitor (one reader thread per volume)
├── report.rs            console + JSON renderers
└── dump.rs              --dump out\ + manifest.json
```

---

## Limitations

* NTFS only. ReFS, FAT32, exFAT are intentionally skipped.
* `watch` doesn't carry process / PID info — USN doesn't expose it.
  Correlate with Process Monitor / ETW if you need that.
* No Authenticode trust filtering yet — you'll see noise from Windows Update.
  Use the persistent exclusion config (see above) to mute the typical sources.

---

## License

MIT — see [LICENSE](LICENSE).
