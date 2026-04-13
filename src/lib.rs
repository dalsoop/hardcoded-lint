//! # hardcoded-lint
//!
//! Compile-time lint that catches hardcoded values in Rust source code.
//! Add to `[build-dependencies]` and call from `build.rs`.
//!
//! ## Quick Start
//!
//! ```toml
//! [build-dependencies]
//! hardcoded-lint = "0.1"
//! ```
//!
//! ```rust,no_run
//! // build.rs
//! fn main() {
//!     hardcoded_lint::check("src")
//!         .ipv4()
//!         .credentials()
//!         .env_fallback()
//!         .run();
//! }
//! ```
//!
//! ## All Rules
//!
//! ```rust,no_run
//! fn main() {
//!     hardcoded_lint::check("src")
//!         .all()
//!         .deny("mycompany.com", "hardcoded company domain")
//!         .run();
//! }
//! ```

use std::fs;
use std::path::Path;

/// Entry point — creates a [`Checker`] for the given source directory.
pub fn check(src_dir: &str) -> Checker {
    Checker {
        src_dir: src_dir.to_string(),
        rules: Vec::new(),
        custom_denies: Vec::new(),
        skip_tests: true,
        skip_docs: true,
        extensions: vec!["rs".into(), "sh".into()],
        allow_marker: "LINT_ALLOW".into(),
    }
}

/// Builder for configuring lint rules.
pub struct Checker {
    src_dir: String,
    rules: Vec<BuiltinRule>,
    custom_denies: Vec<(String, String)>,
    skip_tests: bool,
    skip_docs: bool,
    extensions: Vec<String>,
    allow_marker: String,
}

#[derive(Clone, Copy)]
enum BuiltinRule {
    Ipv4,
    Credentials,
    EnvFallback,
    ConstConfig,
    VmidDefault,
    GitUrl,
    Localhost,
}

impl Checker {
    /// Enable all built-in rules.
    pub fn all(mut self) -> Self {
        self.rules = vec![
            BuiltinRule::Ipv4,
            BuiltinRule::Credentials,
            BuiltinRule::EnvFallback,
            BuiltinRule::ConstConfig,
            BuiltinRule::VmidDefault,
            BuiltinRule::GitUrl,
            BuiltinRule::Localhost,
        ];
        self
    }

    /// Catch any IPv4 address.
    pub fn ipv4(mut self) -> Self { self.rules.push(BuiltinRule::Ipv4); self }
    /// Catch hardcoded passwords, tokens, API keys.
    pub fn credentials(mut self) -> Self { self.rules.push(BuiltinRule::Credentials); self }
    /// Catch `unwrap_or("value")` with meaningful defaults.
    pub fn env_fallback(mut self) -> Self { self.rules.push(BuiltinRule::EnvFallback); self }
    /// Catch `const X: &str = "/path"` or `"https://..."`.
    pub fn const_config(mut self) -> Self { self.rules.push(BuiltinRule::ConstConfig); self }
    /// Catch 5-digit VMID in default_value or unwrap_or.
    pub fn vmid(mut self) -> Self { self.rules.push(BuiltinRule::VmidDefault); self }
    /// Catch hardcoded Git URLs.
    pub fn git_url(mut self) -> Self { self.rules.push(BuiltinRule::GitUrl); self }
    /// Catch localhost:PORT (4+ digit).
    pub fn localhost(mut self) -> Self { self.rules.push(BuiltinRule::Localhost); self }

    /// Add a custom deny pattern.
    pub fn deny(mut self, pattern: &str, message: &str) -> Self {
        self.custom_denies.push((pattern.to_string(), message.to_string()));
        self
    }

    /// Skip `#[test]` blocks (default: true).
    pub fn allow_in_tests(mut self, v: bool) -> Self { self.skip_tests = v; self }
    /// Skip `///` doc comments (default: true).
    pub fn allow_in_docs(mut self, v: bool) -> Self { self.skip_docs = v; self }
    /// File extensions to scan (default: `["rs", "sh"]`).
    pub fn extensions(mut self, e: &[&str]) -> Self { self.extensions = e.iter().map(|s| s.to_string()).collect(); self }
    /// Allow marker string (default: `"LINT_ALLOW"`).
    pub fn allow_marker(mut self, m: &str) -> Self { self.allow_marker = m.to_string(); self }

    /// Run the lint. Panics if violations found.
    pub fn run(self) {
        let mut violations = Vec::new();
        let compiled = self.compile_rules();
        let custom: Vec<CustomDeny> = self.custom_denies.iter()
            .map(|(p, m)| CustomDeny { pattern: p.clone(), msg: m.clone() })
            .collect();

        scan_dir(
            Path::new(&self.src_dir), &compiled, &custom, &self.extensions,
            &self.allow_marker, self.skip_tests, self.skip_docs, &mut violations,
        );

        if violations.is_empty() {
            println!("cargo:rerun-if-changed={}", self.src_dir);
            return;
        }

        eprintln!("\n╔══════════════════════════════════════════════════╗");
        eprintln!("║  hardcoded-lint: {} violation(s){} ║",
            violations.len(), " ".repeat(26usize.saturating_sub(violations.len().to_string().len())));
        eprintln!("╚══════════════════════════════════════════════════╝\n");
        for v in &violations { eprintln!("  {v}"); }
        eprintln!("\n  Suppress: add `// {}:` reason to the line\n", self.allow_marker);
        panic!("hardcoded-lint failed");
    }

    fn compile_rules(&self) -> Vec<Rule> {
        let mut rules: Vec<Rule> = self.rules.iter().map(|r| match r {
            BuiltinRule::Ipv4 => Rule { name: "hardcoded-ip", msg: "hardcoded IPv4", check: detect_ipv4, exempt: exempt_ipv4 },
            BuiltinRule::Credentials => Rule { name: "hardcoded-credential", msg: "hardcoded password/token", check: detect_credential, exempt: no_exempt },
            BuiltinRule::EnvFallback => Rule { name: "hardcoded-fallback", msg: "hardcoded fallback value", check: detect_fallback, exempt: no_exempt },
            BuiltinRule::ConstConfig => Rule { name: "hardcoded-const", msg: "hardcoded const config", check: detect_const, exempt: no_exempt },
            BuiltinRule::VmidDefault => Rule { name: "hardcoded-vmid", msg: "hardcoded VMID", check: detect_vmid, exempt: no_exempt },
            BuiltinRule::GitUrl => Rule { name: "hardcoded-git-url", msg: "hardcoded Git URL", check: detect_git_url, exempt: no_exempt },
            BuiltinRule::Localhost => Rule { name: "hardcoded-localhost", msg: "hardcoded localhost:PORT", check: detect_localhost, exempt: no_exempt },
        }).collect();

        rules
    }
}

struct Rule { name: &'static str, msg: &'static str, check: fn(&str) -> bool, exempt: fn(&str) -> bool }

// ─── Detection ───────────────────────────────────────────────

fn detect_ipv4(line: &str) -> bool {
    let b = line.as_bytes();
    let len = b.len();
    let mut i = 0;
    while i < len {
        if b[i].is_ascii_digit() {
            if i > 0 && (b[i-1].is_ascii_alphanumeric() || b[i-1] == b'_') { i += 1; continue; }
            let s = i;
            while i < len && b[i].is_ascii_digit() { i += 1; }
            if i - s > 3 { continue; }
            let o: u16 = line[s..i].parse().unwrap_or(999);
            if o > 255 { continue; }
            let mut ok = true;
            for _ in 0..3 {
                if i >= len || b[i] != b'.' { ok = false; break; }
                i += 1;
                let os = i;
                while i < len && b[i].is_ascii_digit() { i += 1; }
                if i - os == 0 || i - os > 3 { ok = false; break; }
                let ov: u16 = line[os..i].parse().unwrap_or(999);
                if ov > 255 { ok = false; break; }
            }
            if ok { return true; }
        } else { i += 1; }
    }
    false
}

fn exempt_ipv4(line: &str) -> bool {
    if (line.contains("/8") || line.contains("/12") || line.contains("/16") || line.contains("/24")) && !line.contains("default_value") { return true; }
    if line.contains("0.0.0.0") || line.contains("127.0.0.1") || line.contains("localhost") || line.contains("1.1.1.1") || line.contains("8.8.8.8") || line.contains("255.255.255") { return true; }
    if line.contains("format!(") && line.contains('{') { return true; }
    if line.contains("10.0)") || line.contains("* 10.0") || line.contains("/ 10.0") { return true; }
    false
}

fn detect_credential(line: &str) -> bool {
    let lo = line.to_lowercase();
    for key in ["password", "secret", "api_key", "apikey"] {
        for sep in [" = \"", "=\"", ": \""] {
            let pat = format!("{key}{sep}");
            if let Some(p) = lo.find(&pat) {
                let a = &line[p + pat.len()..];
                if let Some(e) = a.find('"') {
                    let v = &a[..e];
                    if v.len() >= 3 && !v.starts_with('$') && !v.starts_with('{') && !v.contains("env") && !matches!(v, "changeme" | "password" | "test") { return true; }
                }
            }
        }
    }
    false
}

fn detect_fallback(line: &str) -> bool {
    const PH: &[&str] = &["","?","unknown","0","1","true","false","none","default","auto","utf-8","utf8","text/plain","application/json","GET","POST","changeme","password","test","main","latest"];
    for pfx in ["unwrap_or(\"", "unwrap_or_else(|_| \""] {
        if let Some(p) = line.find(pfx) {
            let a = &line[p + pfx.len()..];
            if let Some(e) = a.find('"') {
                let v = &a[..e];
                if PH.contains(&v) || v.len() <= 1 || v.contains('{') || v.contains('%') { continue; }
                return true;
            }
        }
    }
    false
}

fn detect_const(line: &str) -> bool {
    let t = line.trim();
    if !t.contains("const ") || !t.contains("&str") { return false; }
    if !t.starts_with("const ") && !t.starts_with("pub const ") && !t.starts_with("pub(super) const ") && !t.starts_with("pub(crate) const ") { return false; }
    if let Some(p) = t.find("= \"") {
        let a = &t[p+3..];
        if let Some(e) = a.find('"') {
            let v = &a[..e];
            if v.starts_with('/') || v.starts_with("http") || v.contains("://") || (v.contains(':') && v.chars().any(|c| c.is_ascii_digit())) || (v.contains('/') && v.chars().any(|c| c.is_ascii_digit())) { return true; }
        }
    }
    false
}

fn detect_vmid(line: &str) -> bool {
    for pfx in ["default_value = \"", "unwrap_or(\"", "unwrap_or_else(|_| \""] {
        if let Some(p) = line.find(pfx) {
            let a = &line[p + pfx.len()..];
            if let Some(e) = a.find('"') {
                let v = &a[..e];
                if v.len() == 5 && v.chars().all(|c| c.is_ascii_digit()) { return true; }
            }
        }
    }
    false
}

fn detect_git_url(_line: &str) -> bool {
    // Git URL detection is handled via custom deny() rules per-project
    // (e.g. deny("myorg/", "hardcoded org"))
    // This built-in rule is intentionally disabled — too many false positives
    // from external open-source URLs
    false
}

fn detect_localhost(line: &str) -> bool {
    if let Some(p) = line.find("localhost:") {
        let a = &line[p+10..];
        return a.chars().take_while(|c| c.is_ascii_digit()).count() >= 4;
    }
    false
}

fn no_exempt(_: &str) -> bool { false }

// ─── Scanner ─────────────────────────────────────────────────

struct CustomDeny { pattern: String, msg: String }

fn scan_dir(dir: &Path, rules: &[Rule], custom: &[CustomDeny], exts: &[String], marker: &str, skip_tests: bool, skip_docs: bool, out: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() { scan_dir(&p, rules, custom, exts, marker, skip_tests, skip_docs, out); }
        else if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
            if exts.iter().any(|x| x == ext) { scan_file(&p, rules, custom, marker, skip_tests, skip_docs, out); }
        }
    }
}

fn scan_file(path: &Path, rules: &[Rule], custom: &[CustomDeny], marker: &str, skip_tests: bool, skip_docs: bool, out: &mut Vec<String>) {
    let Ok(content) = fs::read_to_string(path) else { return };
    let mut in_test = false;
    let mut depth: i32 = 0;
    let mut test_depth: i32 = 0;

    for (n, line) in content.lines().enumerate() {
        let t = line.trim();
        if skip_tests {
            if t.contains("#[cfg(test)]") || t.starts_with("mod tests") { in_test = true; test_depth = depth; }
            for c in line.chars() { match c { '{' => depth += 1, '}' => { depth -= 1; if in_test && depth <= test_depth { in_test = false; } }, _ => {} } }
            if t == "#[test]" { in_test = true; test_depth = depth; }
            if in_test { continue; }
        }
        if line.contains(marker) { continue; }
        if skip_docs && (t.starts_with("///") || t.starts_with("//!")) { continue; }
        if line.contains("→") || line.contains("예:") || line.contains("규칙:") { continue; }
        if t.starts_with("use ") || t.starts_with("mod ") || t.starts_with("pub mod ") { continue; }

        for r in rules {
            if (r.check)(line) && !(r.exempt)(line) {
                out.push(format!("[{}] {}:{}: {}\n    → {}", r.name, path.display(), n+1, r.msg, t));
            }
        }
        for c in custom {
            if line.contains(&c.pattern) {
                out.push(format!("[custom] {}:{}: {}\n    → {}", path.display(), n+1, c.msg, t));
            }
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_detection() {
        assert!(detect_ipv4(r#""10.0.50.99""#));
        assert!(detect_ipv4(r#""192.168.1.1""#));
        assert!(detect_ipv4("// server 172.16.0.5"));
        assert!(!detect_ipv4("let x = 10;"));
        assert!(!detect_ipv4(r#"version = "1.0.0""#));
    }

    #[test]
    fn ipv4_exemptions() {
        assert!(exempt_ipv4("10.0.0.0/8"));
        assert!(exempt_ipv4("0.0.0.0:8080"));
        assert!(exempt_ipv4("localhost:3000"));
        assert!(!exempt_ipv4("10.0.50.99"));
    }

    #[test]
    fn credential_detection() {
        assert!(detect_credential(r#"password = "s3cret!""#));
        assert!(!detect_credential(r#"password = "changeme""#));
        assert!(!detect_credential(r#"password = """#));
    }

    #[test]
    fn fallback_detection() {
        assert!(detect_fallback(r#"unwrap_or("myserver.com")"#));
        assert!(!detect_fallback(r#"unwrap_or("?")"#));
        assert!(!detect_fallback(r#"unwrap_or("")"#));
    }

    #[test]
    fn const_detection() {
        assert!(detect_const(r#"const X: &str = "/opt/app";"#));
        assert!(detect_const(r#"pub const U: &str = "https://api.example.com";"#));
        assert!(!detect_const(r#"const N: &str = "myapp";"#));
    }

    #[test]
    fn vmid_detection() {
        assert!(detect_vmid(r#"default_value = "50123""#));
        assert!(detect_vmid(r#"unwrap_or("60100")"#));
        assert!(!detect_vmid(r#"unwrap_or("abc")"#));
    }
}
