//! Persistent user config: a list of path-exclusion rules saved as JSON
//! under %LOCALAPPDATA%\fdiff\config.json. Read by scan / diff / watch.
//!
//! Three rule kinds:
//!   - `prefix`  : case-insensitive path-prefix match at component boundary.
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
    /// Persistent path exclusion rules, applied by `scan`, `diff` and `watch`.
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
        if regexes_match_path(&self.regexes, path) {
            return true;
        }
        false
    }

    pub fn add_prefix(&mut self, p: &str) {
        let p = ScanOptions::normalize_prefix(p);
        if !p.is_empty() {
            self.prefixes.push(p);
            self.prefixes.sort();
            self.prefixes.dedup();
        }
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
        let data = fs::read_to_string(&p).with_context(|| format!("reading config {:?}", p))?;
        let cfg: Config =
            serde_json::from_str(&data).with_context(|| format!("parsing config {:?}", p))?;
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

/// Sensible defaults shipped with the tool. Use ${LOCALAPPDATA} so config stays
/// portable across machines.
fn seed_defaults() -> Config {
    Config {
        exclude_paths: vec![
            ExcludeRule::prefix("${LOCALAPPDATA}\\Microsoft\\Edge"),
            ExcludeRule::prefix("${LOCALAPPDATA}\\Microsoft\\Windows"),
            ExcludeRule::regex(
                "^${LOCALAPPDATA}\\Packages\\Microsoft\\.Windows\\.ContentDeliveryManager",
            ),
        ],
    }
}

/// Take a Config and return compiled matchers.
pub fn compile(cfg: &Config) -> Result<CompiledRules> {
    let mut out = CompiledRules::default();
    let local = std::env::var("LOCALAPPDATA").unwrap_or_default();

    for r in &cfg.exclude_paths {
        let expanded = expand_vars(&r.pattern, &local);
        out.display.push(
            format!("[{:?}] {}", r.kind, expanded)
                .to_ascii_lowercase()
                .replace("\"", ""),
        );
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
                let r = compile_regex_rule(&expanded)
                    .with_context(|| format!("bad regex in config: {expanded}"))?;
                out.regexes.push(r);
            }
        }
    }

    out.prefixes.sort();
    out.prefixes.dedup();
    Ok(out)
}

fn compile_regex_rule(expanded: &str) -> Result<Regex> {
    let raw = with_case_insensitive(expanded);
    match Regex::new(&raw) {
        Ok(r) => Ok(r),
        Err(raw_err) => {
            let normalized = regex_path_pattern(expanded);
            if normalized == expanded {
                return Err(raw_err.into());
            }
            Regex::new(&with_case_insensitive(&normalized)).with_context(|| {
                format!(
                    "also failed after normalizing Windows path separators; original regex error: {raw_err}"
                )
            })
        }
    }
}

fn with_case_insensitive(pattern: &str) -> String {
    if pattern.starts_with("(?") {
        pattern.to_string()
    } else {
        format!("(?i){}", pattern)
    }
}

fn regex_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn regex_path_pattern(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }

        match chars.peek().copied() {
            Some('.') => {
                let mut clone = chars.clone();
                let _ = clone.next();
                if clone.peek() == Some(&'*') {
                    out.push('/');
                } else {
                    out.push('\\');
                    out.push('.');
                    let _ = chars.next();
                }
            }
            Some('^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|') => {
                out.push('\\');
                out.push(chars.next().unwrap());
            }
            Some(_) => out.push('/'),
            None => out.push('/'),
        }
    }
    out
}

pub fn regexes_match_path(regexes: &[Regex], path: &str) -> bool {
    if regexes.is_empty() {
        return false;
    }
    let normalized = regex_path(path);
    regexes
        .iter()
        .any(|r| r.is_match(path) || (normalized != path && r.is_match(&normalized)))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_rule_matches_at_component_boundary() {
        let cfg = Config {
            exclude_paths: vec![ExcludeRule::prefix(r"X:\Noise")],
        };
        let compiled = compile(&cfg).unwrap();

        assert!(compiled.excludes(r"X:\Noise\file.tmp"));
        assert!(!compiled.excludes(r"X:\NoiseButReal\file.tmp"));
    }

    #[test]
    fn regex_rule_matches_watch_paths() {
        let cfg = Config {
            exclude_paths: vec![ExcludeRule::regex(r".*\\Noise\\.*")],
        };
        let compiled = compile(&cfg).unwrap();

        assert!(compiled.excludes(r"X:\Noise\file.tmp"));
        assert!(!compiled.excludes(r"X:\Important\file.tmp"));
    }

    #[test]
    fn regex_rule_accepts_plain_windows_path_separators() {
        let cfg = Config {
            exclude_paths: vec![ExcludeRule::regex(r"X:\Noise\.*")],
        };
        let compiled = compile(&cfg).unwrap();

        assert!(compiled.excludes(r"X:\Noise\file.tmp"));
    }

    #[test]
    fn regex_rule_preserves_escaped_dots_when_normalizing_paths() {
        let cfg = Config {
            exclude_paths: vec![ExcludeRule::regex(
                r"^C:\Users\me\AppData\Local\Packages\Microsoft\.Windows\.ContentDeliveryManager",
            )],
        };
        let compiled = compile(&cfg).unwrap();

        assert!(compiled.excludes(
            r"C:\Users\me\AppData\Local\Packages\Microsoft.Windows.ContentDeliveryManager_abc\file.tmp"
        ));
        assert!(!compiled.excludes(
            r"C:\Users\me\AppData\Local\Packages\MicrosoftXWindowsXContentDeliveryManager_abc\file.tmp"
        ));
    }
}
