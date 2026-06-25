//! Persistent user config: a list of path-exclusion rules saved as JSON
//! under %LOCALAPPDATA%\fdiff\config.json. Read by scan / diff / watch.
//!
//! Three rule kinds:
//!   - `prefix`  : case-insensitive path-prefix match at component boundary
//!                 (same rules as --exclude-path).
//!   - `glob`    : `globset` glob (e.g. `**\$Recycle.Bin\**`).
//!   - `regex`   : Rust `regex` crate. Matched against the full path; we
//!                 disable case sensitivity by injecting `(?i)`.
//!
//! Special variable: `${LOCALAPPDATA}` is expanded at load time.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use globset::{Glob, GlobMatcher};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::mft::ScanOptions;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    Prefix,
    Glob,
    Regex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExcludeRule {
    pub kind: RuleKind,
    /// Raw pattern as the user typed it. Stored verbatim so editing
    /// config.json by hand is friendly.
    pub pattern: String,
}

impl ExcludeRule {
    pub fn prefix(p: impl Into<String>) -> Self {
        Self {
            kind: RuleKind::Prefix,
            pattern: p.into(),
        }
    }
    pub fn glob(p: impl Into<String>) -> Self {
        Self {
            kind: RuleKind::Glob,
            pattern: p.into(),
        }
    }
    pub fn regex(p: impl Into<String>) -> Self {
        Self {
            kind: RuleKind::Regex,
            pattern: p.into(),
        }
    }
}

/// On-disk schema.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Persistent path exclusion rules, applied (in addition to CLI flags) by
    /// `scan`, `diff` and `watch` unless `--no-config` is passed.
    #[serde(default)]
    pub exclude_paths: Vec<ExcludeRule>,
}

/// Live, expanded set of compiled matchers for fast path matching.
#[derive(Default)]
pub struct CompiledRules {
    pub prefixes: Vec<String>, // already lowercase, normalized
    pub globs: Vec<GlobMatcher>,
    pub regexes: Vec<Regex>,
    /// Pretty-printed form for the "Hiding N path prefix(es)" banner.
    pub display: Vec<String>,
}

impl CompiledRules {
    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty() && self.globs.is_empty() && self.regexes.is_empty()
    }

    /// Returns true if `path` matches any rule and should be excluded.
    pub fn excludes(&self, path: &str) -> bool {
        if !self.prefixes.is_empty() {
            let lower = path.to_ascii_lowercase();
            for p in &self.prefixes {
                if starts_with(&lower, p) {
                    return true;
                }
            }
        }
        for g in &self.globs {
            if g.is_match(path) {
                return true;
            }
        }
        for r in &self.regexes {
            if r.is_match(path) {
                return true;
            }
        }
        false
    }

    /// Borrow prefixes as `Vec<String>`, useful for code paths that only need
    /// the prefix slice (mft scanner).
    pub fn prefix_vec(&self) -> Vec<String> {
        self.prefixes.clone()
    }
}

pub fn default_config_path() -> Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")
        .ok_or_else(|| anyhow!("LOCALAPPDATA env variable not set"))?;
    let mut p = PathBuf::from(local);
    p.push("fdiff");
    fs::create_dir_all(&p).ok();
    p.push("config.json");
    Ok(p)
}

pub fn load_or_default() -> Result<Config> {
    let p = default_config_path()?;
    if p.exists() {
        let data = fs::read_to_string(&p)
            .with_context(|| format!("reading config {:?}", p))?;
        let cfg: Config = serde_json::from_str(&data)
            .with_context(|| format!("parsing config {:?}", p))?;
        Ok(cfg)
    } else {
        Ok(seed_defaults())
    }
}

pub fn save(cfg: &Config) -> Result<PathBuf> {
    let p = default_config_path()?;
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).ok();
    }
    let json = serde_json::to_string_pretty(cfg)?;
    fs::write(&p, json).with_context(|| format!("writing config {:?}", p))?;
    Ok(p)
}

/// Sensible defaults shipped with the tool. Use ${LOCALAPPDATA} so we don't
/// hard-code "user01".
fn seed_defaults() -> Config {
    Config {
        exclude_paths: vec![
            ExcludeRule::prefix("${LOCALAPPDATA}\\Microsoft\\Edge"),
            ExcludeRule::prefix("${LOCALAPPDATA}\\Microsoft\\Windows"),
            ExcludeRule::glob("${LOCALAPPDATA}\\Packages\\Microsoft.Windows.ContentDeliveryManager*"),
        ],
    }
}

/// Take a Config + extra CLI rules and return compiled matchers.
/// Extra rules from CLI are merged as `prefix` rules (same as the existing
/// --exclude-path semantics).
pub fn compile(
    cfg: &Config,
    extra_prefixes: &[String],
    extra_globs: &[String],
    extra_regexes: &[String],
) -> Result<CompiledRules> {
    let mut out = CompiledRules::default();
    let local = std::env::var("LOCALAPPDATA").unwrap_or_default();

    for r in &cfg.exclude_paths {
        let expanded = expand_vars(&r.pattern, &local);
        out.display
            .push(format!("[{:?}] {}", r.kind, expanded).to_ascii_lowercase().replace("\"", ""));
        match r.kind {
            RuleKind::Prefix => {
                let p = ScanOptions::normalize_prefix(&expanded);
                if !p.is_empty() {
                    out.prefixes.push(p);
                }
            }
            RuleKind::Glob => {
                let g = Glob::new(&expanded)
                    .with_context(|| format!("bad glob in config: {expanded}"))?
                    .compile_matcher();
                out.globs.push(g);
            }
            RuleKind::Regex => {
                let with_flags = if expanded.starts_with("(?") {
                    expanded.clone()
                } else {
                    format!("(?i){}", expanded)
                };
                let r = Regex::new(&with_flags)
                    .with_context(|| format!("bad regex in config: {expanded}"))?;
                out.regexes.push(r);
            }
        }
    }

    for p in extra_prefixes {
        let p = ScanOptions::normalize_prefix(p);
        if !p.is_empty() {
            out.display.push(format!("[Prefix] {}", p));
            out.prefixes.push(p);
        }
    }
    for raw in extra_globs {
        let g = Glob::new(raw)
            .with_context(|| format!("bad glob: {raw}"))?
            .compile_matcher();
        out.display.push(format!("[Glob] {}", raw));
        out.globs.push(g);
    }
    for raw in extra_regexes {
        let with_flags = if raw.starts_with("(?") {
            raw.clone()
        } else {
            format!("(?i){}", raw)
        };
        let r = Regex::new(&with_flags)
            .with_context(|| format!("bad regex: {raw}"))?;
        out.display.push(format!("[Regex] {}", raw));
        out.regexes.push(r);
    }

    out.prefixes.sort();
    out.prefixes.dedup();
    Ok(out)
}

fn expand_vars(input: &str, localappdata: &str) -> String {
    let mut s = input.replace("${LOCALAPPDATA}", localappdata);
    // Also expand the more common shell-style %LOCALAPPDATA%.
    s = s.replace("%LOCALAPPDATA%", localappdata);
    s
}

fn starts_with(lower_path: &str, prefix: &str) -> bool {
    if !lower_path.starts_with(prefix) {
        return false;
    }
    match lower_path.as_bytes().get(prefix.len()) {
        None => true,
        Some(b'\\') | Some(b'/') => true,
        _ => false,
    }
}

/// Append a rule to the in-memory config (used by `fdiff config add`).
pub fn add_rule(cfg: &mut Config, rule: ExcludeRule) {
    // Skip exact duplicates.
    if !cfg
        .exclude_paths
        .iter()
        .any(|r| r.kind == rule.kind && r.pattern == rule.pattern)
    {
        cfg.exclude_paths.push(rule);
    }
}

/// Remove rules by 1-based index or by matching pattern verbatim.
pub fn remove_rule(cfg: &mut Config, key: &str) -> Result<usize> {
    if let Ok(idx1) = key.parse::<usize>() {
        if idx1 == 0 || idx1 > cfg.exclude_paths.len() {
            return Err(anyhow!(
                "index {idx1} out of range (1..={})",
                cfg.exclude_paths.len()
            ));
        }
        cfg.exclude_paths.remove(idx1 - 1);
        return Ok(1);
    }
    let before = cfg.exclude_paths.len();
    cfg.exclude_paths.retain(|r| r.pattern != key);
    Ok(before - cfg.exclude_paths.len())
}

/// Convenience for printing.
pub fn config_path_for_display() -> String {
    default_config_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<unknown>".to_string())
}

/// `path` is just for completion of the docs.
pub fn show(cfg: &Config) {
    println!("# config file: {}", config_path_for_display());
    if cfg.exclude_paths.is_empty() {
        println!("  (no exclude rules)");
        return;
    }
    let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
    for (i, r) in cfg.exclude_paths.iter().enumerate() {
        let expanded = expand_vars(&r.pattern, &local);
        if expanded == r.pattern {
            println!("  {:>3}.  [{:?}]  {}", i + 1, r.kind, r.pattern);
        } else {
            println!(
                "  {:>3}.  [{:?}]  {}\n           = {}",
                i + 1,
                r.kind,
                r.pattern,
                expanded
            );
        }
    }
}

/// Helper for `fdiff config reset` — writes the seeded defaults to disk.
pub fn reset_to_defaults() -> Result<(PathBuf, Config)> {
    let cfg = seed_defaults();
    let p = save(&cfg)?;
    Ok((p, cfg))
}

#[allow(dead_code)]
pub fn _ensure_unused_path(_: &Path) {}
