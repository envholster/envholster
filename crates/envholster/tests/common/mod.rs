//! Black-box end-to-end harness for the `envholster` binary (ported from the
//! earlier daemon-era `envholster-e2e` crate).
//!
//! OWNED BY THE INDEPENDENT VERIFIER AGENT (plan/08-delivery §8.3): tests are
//! written from the frozen contracts and specs alone; the verifier never reads
//! implementation source, and implementers never edit this crate. Its pass IS
//! the phase gate.
//!
//! No dependencies, by rule: tests use std only — `std::process::Command`
//! against the built binaries, `std::env::temp_dir()` with unique per-test
//! subdirectories.
//!
//! Binary resolution: `ENVHOLSTER_BIN` env var, else
//! `<workspace>/target/release/envholster`, else
//! `<workspace>/target/debug/envholster`. There is deliberately NO build.rs
//! building the binary for you — build it first
//! (`cargo build --release -p envholster`) or set `ENVHOLSTER_BIN`.

#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::collections::hash_map::RandomState;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::hash::{BuildHasher, Hasher};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Binary + external tool resolution
// ---------------------------------------------------------------------------

/// Path to the `envholster` binary under test.
///
/// `ENVHOLSTER_BIN` wins; otherwise `target/release/envholster` relative to
/// the workspace root, falling back to `target/debug/envholster`
/// (`CARGO_TARGET_DIR` honored). No build.rs builds it — build first or set
/// the env var.
pub fn bin_path() -> PathBuf {
    if let Ok(p) = env::var("ENVHOLSTER_BIN") {
        return PathBuf::from(p);
    }
    // Cargo builds the binary for integration tests and hands its path over.
    PathBuf::from(env!("CARGO_BIN_EXE_envholster"))
}

/// Locate the standalone `age` CLI (RECOVERY-SPEC §4/§7: the recovery blob
/// must decrypt with vanilla age and zero envholster code).
pub fn find_age() -> Option<PathBuf> {
    for cand in [
        "/opt/homebrew/bin/age",
        "/usr/local/bin/age",
        "/usr/bin/age",
    ] {
        let p = Path::new(cand);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    if let Some(paths) = env::var_os("PATH") {
        for dir in env::split_paths(&paths) {
            let p = dir.join("age");
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Entropy-ish helpers (std only — RandomState carries OS-random SipHash keys)
// ---------------------------------------------------------------------------

/// `n_bytes * 2` lowercase hex chars, unique per call and unpredictable
/// across processes (RandomState is seeded from OS randomness).
pub fn unique_hex(n_bytes: usize) -> String {
    let rs = RandomState::new();
    let mut out = String::new();
    let mut round: u64 = 0;
    while out.len() < n_bytes * 2 {
        let mut h = rs.build_hasher();
        h.write_u64(round);
        h.write_u64(u64::from(std::process::id()));
        h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
        h.write_u128(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_nanos(),
        );
        out.push_str(&format!("{:016x}", h.finish()));
        round += 1;
    }
    out.truncate(n_bytes * 2);
    out
}

/// A high-entropy sentinel secret value. Long and structured enough that any
/// occurrence in a file or output is unambiguous.
pub fn sentinel(tag: &str) -> String {
    format!("EHSENTINEL-{}-{}", tag, unique_hex(24))
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let b = hex.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    let val = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("not hex: {c}"),
        }
    };
    let mut i = 0;
    while i + 1 < b.len() {
        out.push(val(b[i]) << 4 | val(b[i + 1]));
        i += 2;
    }
    out
}

// ---------------------------------------------------------------------------
// bech32 (BIP-173, std only) — used to mint syntactically valid `age1…`
// recipient strings for enrollment-refusal tests without needing a second
// machine identity.
// ---------------------------------------------------------------------------

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk: u32 = 1;
    for &v in values {
        let b = (chk >> 25) as u8;
        chk = (chk & 0x1ff_ffff) << 5 ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|b| b & 31));
    v
}

fn to_base32(data: &[u8]) -> Vec<u8> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

pub fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    let d5 = to_base32(data);
    let mut values = bech32_hrp_expand(hrp);
    values.extend(&d5);
    values.extend([0u8; 6]);
    let plm = bech32_polymod(&values) ^ 1;
    let mut s = String::from(hrp);
    s.push('1');
    for &v in &d5 {
        s.push(BECH32_CHARSET[v as usize] as char);
    }
    for i in 0..6 {
        s.push(BECH32_CHARSET[((plm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    s
}

/// A syntactically valid, freshly minted X25519 `age1…` recipient string
/// (32 random bytes bech32-encoded with HRP `age`). Any 32-byte string is an
/// acceptable X25519 public key for wrapping purposes.
pub fn fake_age_recipient() -> String {
    bech32_encode("age", &hex_to_bytes(&unique_hex(32)))
}

// ---------------------------------------------------------------------------
// base64 (standard alphabet, padded) — ENVELOPE-SPEC §3.1 / RECOVERY-SPEC §3
// ---------------------------------------------------------------------------

pub fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(T[(b0 >> 2) as usize] as char);
        out.push(T[((b0 << 4 | b1 >> 4) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(T[((b1 << 2 | b2 >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(T[(b2 & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decoded byte length of a padded standard-base64 string.
pub fn base64_decoded_len(s: &str) -> usize {
    let pad = s.bytes().rev().take_while(|&b| b == b'=').count();
    s.len() / 4 * 3 - pad
}

// ---------------------------------------------------------------------------
// Text scanning helpers
// ---------------------------------------------------------------------------

/// All standalone 16-lowercase-hex tokens (recipient ids / fingerprints,
/// ENVELOPE-SPEC §2.3) in text order. Boundaries: neighbors must not be
/// ASCII alphanumeric, and the hex run must be exactly 16 chars.
pub fn hex16_tokens(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let is_hex = |c: u8| matches!(c, b'0'..=b'9' | b'a'..=b'f');
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if is_hex(b[i]) {
            let start = i;
            while i < b.len() && is_hex(b[i]) {
                i += 1;
            }
            let before_ok = start == 0 || !b[start - 1].is_ascii_alphanumeric();
            let after_ok = i >= b.len() || !b[i].is_ascii_alphanumeric();
            if i - start == 16 && before_ok && after_ok {
                out.push(s[start..i].to_string());
            }
        } else {
            i += 1;
        }
    }
    out
}

/// First `age1…` bech32-looking recipient token in the text.
pub fn extract_age_recipient(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut i = 0;
    while let Some(pos) = s[i..].find("age1") {
        let start = i + pos;
        let before_ok = start == 0 || !b[start - 1].is_ascii_alphanumeric();
        let mut end = start;
        while end < b.len() && (b[end].is_ascii_lowercase() || b[end].is_ascii_digit()) {
            end += 1;
        }
        if before_ok && end - start >= 30 {
            return Some(s[start..end].to_string());
        }
        i = start + 4;
    }
    None
}

pub fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Recursively list every regular file under `root` (symlinks not followed).
pub fn walk_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let meta = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                out.push(path);
            }
        }
    }
    out
}

/// Scan every file under `root` for any of the needles; returns
/// `"path (matched: needle-prefix…)"` hit descriptions (empty = clean).
pub fn scan_tree_for(root: &Path, needles: &[&str]) -> Vec<String> {
    let mut hits = Vec::new();
    for file in walk_files(root) {
        // File NAME check too — a sentinel must not leak anywhere.
        let name = file.to_string_lossy().into_owned();
        for n in needles {
            if name.contains(n) {
                hits.push(format!("{} (file name contains sentinel)", file.display()));
            }
        }
        let Ok(bytes) = fs::read(&file) else { continue };
        for n in needles {
            if contains_subslice(&bytes, n.as_bytes()) {
                hits.push(format!(
                    "{} (contents contain {}…)",
                    file.display(),
                    &n[..n.len().min(24)]
                ));
            }
        }
    }
    hits
}

pub fn find_file_containing(root: &Path, needle: &str) -> Option<PathBuf> {
    walk_files(root).into_iter().find(|f| {
        fs::read(f)
            .map(|b| contains_subslice(&b, needle.as_bytes()))
            .unwrap_or(false)
    })
}

/// `chmod`-style permission bits of a path (unix only, which is the entire
/// supported platform matrix at P0).
pub fn unix_mode(p: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p)
        .unwrap_or_else(|e| panic!("stat {}: {e}", p.display()))
        .permissions()
        .mode()
        & 0o7777
}

// ---------------------------------------------------------------------------
// dotenv parsing (for fixture bookkeeping and export round-trip comparison)
// ---------------------------------------------------------------------------

/// Minimal dotenv reader: `KEY=value`, optional `export ` prefix, optional
/// surrounding single/double quotes, `#` comments and blank lines skipped.
/// Fixture values are chosen escape-free so this is lossless for them.
pub fn parse_dotenv(s: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in s.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let t = t.strip_prefix("export ").unwrap_or(t);
        if let Some(eq) = t.find('=') {
            let key = t[..eq].trim().to_string();
            let mut val = t[eq + 1..].trim().to_string();
            if val.len() >= 2
                && ((val.starts_with('"') && val.ends_with('"'))
                    || (val.starts_with('\'') && val.ends_with('\'')))
            {
                val = val[1..val.len() - 1].to_string();
            }
            map.insert(key, val);
        }
    }
    map
}

// ---------------------------------------------------------------------------
// Vault header parsing (ENVELOPE-SPEC §3–§4 — the header is plaintext)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RecipientBlock {
    pub id: String,
    pub class: String,
    pub kind: String,
    pub label: String,
    pub encoding: Option<String>,
    pub enroll: String,
}

#[derive(Debug, Clone)]
pub struct CellBlock {
    pub env: String,
    pub tier: u8,
    pub commitment: String,
    pub nonce: String,
    pub ct_len: u64,
    /// (recipient id, base64 wrap blob) in file order.
    pub wraps: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct VaultFile {
    pub schema: String,
    pub generation: u64,
    pub uuid: String,
    pub recipients: Vec<RecipientBlock>,
    pub cells: Vec<CellBlock>,
    /// (env, tier, 32-hex tag) in file order.
    pub tags: Vec<(String, u8, String)>,
    /// (env, tier, base64 lines) in file order.
    pub bodies: Vec<(String, u8, Vec<String>)>,
}

impl VaultFile {
    pub fn cell(&self, env: &str, tier: u8) -> Option<&CellBlock> {
        self.cells.iter().find(|c| c.env == env && c.tier == tier)
    }
    pub fn tag(&self, env: &str, tier: u8) -> Option<&str> {
        self.tags
            .iter()
            .find(|(e, t, _)| e == env && *t == tier)
            .map(|(_, _, h)| h.as_str())
    }
    pub fn body_lines(&self, env: &str, tier: u8) -> Option<&[String]> {
        self.bodies
            .iter()
            .find(|(e, t, _)| e == env && *t == tier)
            .map(|(_, _, l)| l.as_slice())
    }
    pub fn body_b64(&self, env: &str, tier: u8) -> Option<String> {
        self.body_lines(env, tier).map(|l| l.concat())
    }
    pub fn recovery_recipients(&self) -> Vec<&RecipientBlock> {
        self.recipients
            .iter()
            .filter(|r| r.class == "recovery")
            .collect()
    }
}

fn parse_cell_heading(rest: &str, kind: &str) -> Result<(String, u8), String> {
    // rest is what follows `[cell "` or `[body "`: `<env>" <tier>]`
    let q = rest
        .find('"')
        .ok_or_else(|| format!("{kind} heading missing closing quote: {rest}"))?;
    let env = rest[..q].to_string();
    let tail = rest[q + 1..]
        .trim()
        .strip_suffix(']')
        .ok_or_else(|| format!("{kind} heading missing ']': {rest}"))?;
    let tier: u8 = tail
        .trim()
        .parse()
        .map_err(|_| format!("{kind} heading tier not a digit: {rest}"))?;
    Ok((env, tier))
}

pub fn parse_vault_text(text: &str) -> Result<VaultFile, String> {
    let lines: Vec<&str> = text.split('\n').collect();
    if lines.first().copied() != Some("ENVHOLSTERv1") {
        return Err(format!(
            "vault magic line missing; first line = {:?}",
            lines.first()
        ));
    }
    let mut vf = VaultFile {
        schema: String::new(),
        generation: 0,
        uuid: String::new(),
        recipients: Vec::new(),
        cells: Vec::new(),
        tags: Vec::new(),
        bodies: Vec::new(),
    };
    let mut i = 1;
    // Preamble
    while i < lines.len() {
        let l = lines[i];
        if let Some(v) = l.strip_prefix("schema = ") {
            vf.schema = v.to_string();
        } else if let Some(v) = l.strip_prefix("generation = ") {
            vf.generation = v
                .parse()
                .map_err(|e| format!("generation not u64 ({v:?}): {e}"))?;
        } else if let Some(v) = l.strip_prefix("vault-uuid = ") {
            vf.uuid = v.to_string();
        } else {
            break;
        }
        i += 1;
    }
    // Header core blocks
    while i < lines.len() {
        let l = lines[i];
        if l.is_empty() {
            i += 1;
            continue;
        }
        if l == "-----ENVHOLSTER CORE END-----" {
            i += 1;
            break;
        }
        if let Some(rest) = l.strip_prefix("[recipient \"") {
            let id = rest
                .strip_suffix("\"]")
                .ok_or_else(|| format!("bad recipient heading: {l}"))?
                .to_string();
            let mut rb = RecipientBlock {
                id,
                class: String::new(),
                kind: String::new(),
                label: String::new(),
                encoding: None,
                enroll: String::new(),
            };
            i += 1;
            while i < lines.len() && !lines[i].is_empty() {
                let kl = lines[i];
                if let Some(v) = kl.strip_prefix("class = ") {
                    rb.class = v.to_string();
                } else if let Some(v) = kl.strip_prefix("kind = ") {
                    rb.kind = v.to_string();
                } else if let Some(v) = kl.strip_prefix("label = ") {
                    rb.label = v.to_string();
                } else if let Some(v) = kl.strip_prefix("encoding = ") {
                    rb.encoding = Some(v.to_string());
                } else if let Some(v) = kl.strip_prefix("enroll = ") {
                    rb.enroll = v.to_string();
                } else {
                    return Err(format!("unexpected recipient line: {kl}"));
                }
                i += 1;
            }
            vf.recipients.push(rb);
        } else if let Some(rest) = l.strip_prefix("[cell \"") {
            let (env, tier) = parse_cell_heading(rest, "cell")?;
            let mut cb = CellBlock {
                env,
                tier,
                commitment: String::new(),
                nonce: String::new(),
                ct_len: 0,
                wraps: Vec::new(),
            };
            i += 1;
            while i < lines.len() && !lines[i].is_empty() {
                let kl = lines[i];
                if let Some(v) = kl.strip_prefix("commitment = ") {
                    cb.commitment = v.to_string();
                } else if let Some(v) = kl.strip_prefix("nonce = ") {
                    cb.nonce = v.to_string();
                } else if let Some(v) = kl.strip_prefix("ct-len = ") {
                    cb.ct_len = v
                        .parse()
                        .map_err(|e| format!("ct-len not u32 ({v:?}): {e}"))?;
                } else if let Some(v) = kl.strip_prefix("wrap ") {
                    let (id, blob) = v
                        .split_once(" = ")
                        .ok_or_else(|| format!("bad wrap line: {kl}"))?;
                    cb.wraps.push((id.to_string(), blob.to_string()));
                } else {
                    return Err(format!("unexpected cell line: {kl}"));
                }
                i += 1;
            }
            vf.cells.push(cb);
        } else {
            return Err(format!("unexpected header line: {l}"));
        }
    }
    // Tag section (immediately after core end, no blank line — §3.1)
    if i >= lines.len() || lines[i] != "[tags]" {
        return Err(format!(
            "expected [tags] immediately after core end, got {:?}",
            lines.get(i)
        ));
    }
    i += 1;
    while i < lines.len() {
        let Some(v) = lines[i].strip_prefix("tag ") else {
            break;
        };
        let (cell, hex) = v
            .split_once(" = ")
            .ok_or_else(|| format!("bad tag line: {}", lines[i]))?;
        let (env, tier) = cell
            .rsplit_once(':')
            .ok_or_else(|| format!("bad tag cell key: {cell}"))?;
        let tier: u8 = tier.parse().map_err(|_| format!("bad tag tier: {cell}"))?;
        vf.tags.push((env.to_string(), tier, hex.to_string()));
        i += 1;
    }
    // Body blocks
    while i < lines.len() {
        let l = lines[i];
        if l.is_empty() {
            i += 1;
            continue;
        }
        if let Some(rest) = l.strip_prefix("[body \"") {
            let (env, tier) = parse_cell_heading(rest, "body")?;
            i += 1;
            let mut body_lines = Vec::new();
            while i < lines.len() && !lines[i].is_empty() && !lines[i].starts_with('[') {
                body_lines.push(lines[i].to_string());
                i += 1;
            }
            vf.bodies.push((env, tier, body_lines));
        } else {
            return Err(format!("unexpected line after tags: {l}"));
        }
    }
    Ok(vf)
}

// ---------------------------------------------------------------------------
// Process running: bounded, deadlock-free capture
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct CmdResult {
    /// `None` means the process was killed after the timeout.
    pub status: Option<ExitStatus>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl CmdResult {
    pub fn success(&self) -> bool {
        self.status.map(|s| s.success()).unwrap_or(false)
    }
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
    pub fn combined(&self) -> String {
        format!("{}{}", self.stdout_str(), self.stderr_str())
    }
    fn render(&self) -> String {
        format!(
            "status: {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.status,
            self.stdout_str(),
            self.stderr_str()
        )
    }
    #[track_caller]
    pub fn assert_success(&self, what: &str) -> &Self {
        assert!(
            self.success(),
            "expected `{what}` to succeed (timeout if status is None)\n{}",
            self.render()
        );
        self
    }
    #[track_caller]
    pub fn assert_failure(&self, what: &str) -> &Self {
        assert!(
            self.status.is_some(),
            "`{what}` timed out — expected a prompt-free hard refusal\n{}",
            self.render()
        );
        assert!(
            !self.success(),
            "expected `{what}` to be refused (non-zero exit)\n{}",
            self.render()
        );
        self
    }
}

fn spawn_or_die(cmd: &mut Command) -> Child {
    cmd.spawn().unwrap_or_else(|e| {
        panic!(
            "failed to spawn {:?}: {e}\nBuild the binary first (`cargo build --release -p envholster`) \
             or point ENVHOLSTER_BIN at it — envholster-e2e has no build.rs and never builds it for you.",
            cmd.get_program()
        )
    })
}

/// Run to completion with all of stdin supplied up front; kill at `timeout`.
pub fn run_with_timeout(mut cmd: Command, stdin_bytes: &[u8], timeout: Duration) -> CmdResult {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = spawn_or_die(&mut cmd);
    if let Some(mut si) = child.stdin.take() {
        let _ = si.write_all(stdin_bytes);
        // dropped: stdin closes (EOF)
    }
    let mut so = child.stdout.take().expect("stdout piped");
    let mut se = child.stderr.take().expect("stderr piped");
    let h_out = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = so.read_to_end(&mut b);
        b
    });
    let h_err = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = se.read_to_end(&mut b);
        b
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                thread::sleep(Duration::from_millis(25));
            }
            Err(_) => break None,
        }
    };
    CmdResult {
        status,
        stdout: h_out.join().unwrap_or_default(),
        stderr: h_err.join().unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------
// Interactive driver (expect-style, for the init ceremony)
// ---------------------------------------------------------------------------

pub struct Interactive {
    child: Child,
    stdin: Option<ChildStdin>,
    buf: Arc<Mutex<Vec<u8>>>,
}

impl Interactive {
    pub fn spawn(mut cmd: Command) -> Self {
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = spawn_or_die(&mut cmd);
        let stdin = child.stdin.take();
        let buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        for stream in [
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>),
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let buf = Arc::clone(&buf);
            thread::spawn(move || {
                let mut stream = stream;
                let mut chunk = [0u8; 4096];
                loop {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.lock().unwrap().extend_from_slice(&chunk[..n]),
                    }
                }
            });
        }
        Interactive { child, stdin, buf }
    }

    /// Write to the child's stdin; errors (e.g. child already exited) are
    /// deliberately ignored — the exit status is the source of truth.
    pub fn send(&mut self, s: &str) {
        if let Some(si) = self.stdin.as_mut() {
            let _ = si.write_all(s.as_bytes());
            let _ = si.flush();
        }
    }

    pub fn close_stdin(&mut self) {
        self.stdin = None;
    }

    /// Combined stdout+stderr seen so far.
    pub fn snapshot(&self) -> String {
        String::from_utf8_lossy(&self.buf.lock().unwrap()).into_owned()
    }

    pub fn try_status(&mut self) -> Option<ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    pub fn wait_exit(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(st) = self.try_status() {
                return Some(st);
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return None;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Interactive {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

// ---------------------------------------------------------------------------
// Sandbox: fresh HOME/TMPDIR/project per test (hermetic harness, 08 §8.3)
// ---------------------------------------------------------------------------

pub struct Sandbox {
    pub root: PathBuf,
    pub home: PathBuf,
    pub tmp: PathBuf,
    pub project: PathBuf,
    pub removable: PathBuf,
}

pub struct InitOutcome {
    /// Everything init printed (stdout + stderr interleaved).
    pub output: String,
    /// The recovery identity file as stored on the "removable media" path.
    pub recovery_identity: PathBuf,
    /// The recovery recipient's 16-hex fingerprint (from the vault header).
    pub fingerprint: String,
    /// The machine recipient (`age1…`) enrolled at init.
    pub machine_recipient: String,
}

impl Sandbox {
    pub fn new(tag: &str) -> Self {
        let root = env::temp_dir().join(format!(
            "envholster-e2e-{}-{}-{tag}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        let sb = Sandbox {
            home: root.join("home"),
            tmp: root.join("tmp"),
            project: root.join("project"),
            removable: root.join("removable"),
            root,
        };
        for d in [&sb.home, &sb.tmp, &sb.project, &sb.removable] {
            fs::create_dir_all(d).unwrap_or_else(|e| panic!("mkdir {}: {e}", d.display()));
        }
        sb
    }

    /// Best-effort removal; call at the end of a passing test (a panic skips
    /// it, leaving the sandbox behind for debugging).
    pub fn cleanup(&self) {
        let _ = fs::remove_dir_all(&self.root);
    }

    pub fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(bin_path());
        c.args(args)
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env("TMPDIR", &self.tmp)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("NO_COLOR", "1")
            .env_remove("ENVHOLSTER_ENV")
            .env_remove("ENVHOLSTER_IDENTITY")
            .env_remove("ENVHOLSTER_IDENTITY_FILE");
        c
    }

    pub fn run(&self, args: &[&str], stdin: &[u8]) -> CmdResult {
        run_with_timeout(self.command(args), stdin, Duration::from_secs(180))
    }

    pub fn vault_path(&self) -> PathBuf {
        self.project.join("secrets.holster")
    }
    pub fn recovery_blob_path(&self) -> PathBuf {
        self.project.join("secrets.holster.recovery.age")
    }
    pub fn manifest_path(&self) -> PathBuf {
        self.project.join("envholster.toml")
    }

    #[track_caller]
    pub fn read_vault(&self) -> VaultFile {
        let text = fs::read_to_string(self.vault_path())
            .unwrap_or_else(|e| panic!("read {}: {e}", self.vault_path().display()));
        parse_vault_text(&text).unwrap_or_else(|e| {
            panic!(
                "vault header failed to parse per ENVELOPE-SPEC §3 grammar: {e}\n--- vault ---\n{text}"
            )
        })
    }

    /// `identity generate` and return the printed `age1…` public recipient.
    #[track_caller]
    pub fn generate_identity(&self, label: &str) -> String {
        let r = self.run(&["identity", "generate", "--label", label], b"n\n");
        r.assert_success("identity generate");
        if let Some(k) = extract_age_recipient(&r.combined()) {
            return k;
        }
        let r2 = self.run(&["identity", "list"], b"");
        extract_age_recipient(&r2.combined()).unwrap_or_else(|| {
            panic!(
                "no age1… recipient printed by `identity generate` or `identity list`\n\
                 generate:\n{}\nlist:\n{}",
                r.render_public(),
                r2.render_public()
            )
        })
    }

    /// `init --recipient <machine>` (no prompts), then `recovery create --to
    /// <removable path>` (the ceremony that moves the parked recovery
    /// identity off the machine and proves the stored copy). Both run with
    /// no stdin; the combined output is returned.
    #[track_caller]
    pub fn init_vault(&self) -> InitOutcome {
        let machine_recipient = self.generate_identity("machine-one");
        let ident_path = self.removable.join("recovery.identity");
        let r_init = self.run(&["init", "--recipient", &machine_recipient], b"");
        r_init.assert_success("init");
        let ident_arg = ident_path.to_string_lossy().into_owned();
        // The sandbox's "removable media" is a directory on the same disk as
        // HOME, which `recovery create` refuses without the explicit flag.
        let r_create = self.run(
            &[
                "recovery",
                "create",
                "--to",
                &ident_arg,
                "--allow-same-disk",
            ],
            b"",
        );
        r_create.assert_success("recovery create --to <removable>");
        let output = format!("{}\n{}", r_init.combined(), r_create.combined());

        // The identity must exist as stored on the removable path.
        let recovery_identity = if ident_path.is_file()
            && fs::read_to_string(&ident_path)
                .map(|s| s.contains("AGE-SECRET-KEY-1"))
                .unwrap_or(false)
        {
            ident_path
        } else {
            find_file_containing(&self.removable, "AGE-SECRET-KEY-1").unwrap_or_else(|| {
                panic!(
                    "no AGE-SECRET-KEY-1 identity found under the removable-media path after init\n\
                     --- init output ---\n{output}"
                )
            })
        };

        // Structural post-conditions from ENVELOPE-SPEC / RECOVERY-SPEC.
        assert!(
            self.vault_path().is_file(),
            "init must create secrets.holster"
        );
        assert!(
            self.recovery_blob_path().is_file(),
            "init must create secrets.holster.recovery.age in lockstep (D6)"
        );
        assert!(
            self.manifest_path().is_file(),
            "init must create envholster.toml (07 §7.6)"
        );
        let vault = self.read_vault();
        assert_eq!(vault.schema, "1", "schema must be 1");
        assert_eq!(
            vault.generation, 1,
            "a fresh vault's first on-disk generation is 1 (ENVELOPE-SPEC A.5)"
        );
        let recovery = vault.recovery_recipients();
        assert_eq!(
            recovery.len(),
            1,
            "exactly one recovery-class recipient (ENVELOPE-SPEC §2.2)"
        );
        assert_eq!(
            recovery[0].enroll, "*:3",
            "recovery recipient must be enrolled *:3 (ENVELOPE-SPEC §4.5)"
        );
        assert_eq!(recovery[0].kind, "x25519");
        let fingerprint = recovery[0].id.clone();
        assert!(
            output.contains(&fingerprint),
            "init must display the recovery fingerprint {fingerprint} (RECOVERY-SPEC §5.3)\n\
             --- init output ---\n{output}"
        );
        InitOutcome {
            output,
            recovery_identity,
            fingerprint,
            machine_recipient,
        }
    }
}

impl CmdResult {
    fn render_public(&self) -> String {
        self.render()
    }
}

// ---------------------------------------------------------------------------
// Self-tests for the harness helpers (run without the binary)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod self_tests {
    use super::*;

    #[test]
    fn base64_matches_recovery_spec_example() {
        // RECOVERY-SPEC §3.1: "golden-api-key-value" ⇒ "Z29sZGVuLWFwaS1rZXktdmFsdWU="
        assert_eq!(
            base64_encode(b"golden-api-key-value"),
            "Z29sZGVuLWFwaS1rZXktdmFsdWU="
        );
        assert_eq!(
            base64_encode(b"golden-alpha-value"),
            "Z29sZGVuLWFscGhhLXZhbHVl"
        );
        assert_eq!(base64_decoded_len("Z29sZGVuLWFwaS1rZXktdmFsdWU="), 20);
    }

    #[test]
    fn bech32_matches_bip173_vector() {
        // BIP-173 valid vector: hrp "a", empty data => "a12uel5l"
        assert_eq!(bech32_encode("a", &[]), "a12uel5l");
        let r = fake_age_recipient();
        assert!(r.starts_with("age1"), "{r}");
        assert_eq!(r.len(), "age1".len() + 52 + 6, "{r}");
    }

    #[test]
    fn hex16_token_boundaries() {
        let toks = hex16_tokens(
            "fingerprint: 1c9a2b3d4e5f6071\nuuid 3f2a9c10-88e2-4c5b-9d41-6b7f0a2c9e55 \
             commitment 9f86d081884c7d659f86d081884c7d659f86d081884c7d659f86d081884c7d65 \
             word deadbeefdeadbeefX",
        );
        assert_eq!(toks, vec!["1c9a2b3d4e5f6071".to_string()]);
    }

    #[test]
    fn dotenv_parse_variants() {
        let m = parse_dotenv(
            "# c\nPORT=3000\nexport DATABASE_URL=\"postgres://u:p@h/db\"\nTOKEN='abc'\n\nX = spaced\n",
        );
        assert_eq!(m["PORT"], "3000");
        assert_eq!(m["DATABASE_URL"], "postgres://u:p@h/db");
        assert_eq!(m["TOKEN"], "abc");
        assert_eq!(m["X"], "spaced");
    }

    #[test]
    fn vault_parser_accepts_spec_example_shape() {
        let text = "ENVHOLSTERv1\nschema = 1\ngeneration = 7\nvault-uuid = 3f2a9c10-88e2-4c5b-9d41-6b7f0a2c9e55\n\n[recipient \"1c9a2b3d4e5f6071\"]\nclass = software\nkind = x25519\nlabel = alice laptop\nencoding = age1qqpszry9\nenroll = *:1\n\n[recipient \"8b1e2f3a4c5d6e7f\"]\nclass = recovery\nkind = x25519\nlabel = paper kit 2026-07\nencoding = age1u7fz2\nenroll = *:3\n\n[cell \"base\" 1]\ncommitment = 9f86d081884c7d65\nnonce = 24f1b60c9d2e7a5583c0\nct-len = 137\nwrap 1c9a2b3d4e5f6071 = YWdlLQ==\nwrap 8b1e2f3a4c5d6e7f = YWdlLg==\n\n-----ENVHOLSTER CORE END-----\n[tags]\ntag base:1 = 0f1e2d3c4b5a69788796a5b4c3d2e1f0\n\n[body \"base\" 1]\nq0svMBQok0T7GdWALRy0Yc2rjcVLYD9nJZWavPKMSk6mS1Uj0Q2LmyfSFO0jRPeq\nCk52aXBhc3M=\n";
        let v = parse_vault_text(text).expect("parse");
        assert_eq!(v.generation, 7);
        assert_eq!(v.recipients.len(), 2);
        assert_eq!(v.recovery_recipients().len(), 1);
        let c = v.cell("base", 1).expect("cell");
        assert_eq!(c.ct_len, 137);
        assert_eq!(c.wraps.len(), 2);
        assert_eq!(v.tag("base", 1), Some("0f1e2d3c4b5a69788796a5b4c3d2e1f0"));
        assert_eq!(v.body_lines("base", 1).unwrap().len(), 2);
    }
}
