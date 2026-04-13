# hardcoded-lint

Compile-time lint that catches hardcoded IPs, secrets, and config values in Rust source code.

Runs in `build.rs` — violations fail the build. No nightly required.

## Install

```toml
[build-dependencies]
hardcoded-lint = { git = "https://github.com/dalsoop/hardcoded-lint" }
```

## Usage

```rust
// build.rs
fn main() {
    hardcoded_lint::check("src")
        .ipv4()           // any IPv4 address (X.X.X.X)
        .credentials()    // password, secret, api_key values
        .env_fallback()   // unwrap_or("meaningful_value")
        .const_config()   // const &str = "/path" or "https://..."
        .vmid()           // 5-digit VMID in defaults
        .run();
}
```

## All Rules

```rust
fn main() {
    hardcoded_lint::check("src")
        .all()  // enable all 7 built-in rules
        .deny("mycompany.com", "hardcoded company domain")
        .deny("myorg/", "hardcoded GitHub org")
        .run();
}
```

## Built-in Rules

| Rule | Catches | Auto-Exempt |
|------|---------|-------------|
| `ipv4()` | Any IPv4 address | CIDR (`/8`), `0.0.0.0`, `127.0.0.1`, `localhost`, `format!()`, arithmetic `10.0` |
| `credentials()` | `password = "value"`, `secret = "..."`, `api_key = "..."` | Empty, `changeme`, `$ENV`, `{template}` |
| `env_fallback()` | `unwrap_or("server.com")`, `unwrap_or_else(\|_\| "value")` | `""`, `"?"`, `"unknown"`, `"default"`, `"true"/"false"`, single char |
| `const_config()` | `const X: &str = "/opt/..."` or `"https://..."` | Simple names without paths/URLs/ports |
| `vmid()` | `default_value = "50123"`, `unwrap_or("60100")` | Non-5-digit values |
| `git_url()` | GitHub/GitLab URLs (use via `deny()` for org-specific) | `format!()` |
| `localhost()` | `localhost:8080` (4+ digit port) | — |

## Suppressing Violations

Add `// LINT_ALLOW: reason` to the line:

```rust
const BIND_ADDR: &str = "0.0.0.0:8080"; // LINT_ALLOW: bind address constant
```

## Auto-Skipped

- `#[test]` blocks and `#[cfg(test)]` modules
- `///` and `//!` doc comments
- `use` / `mod` declarations
- Lines with `→`, `예:`, `규칙:` (rule descriptions)

## Custom Deny

```rust
hardcoded_lint::check("src")
    .ipv4()
    .deny("production-db", "hardcoded DB name")
    .deny("mycompany.com", "hardcoded domain")
    .run();
```

## License

MIT
