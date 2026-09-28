//! Dotenv parsing/writing and the import classifier (plan/07 §7.4).
//!
//! The parser accepts the common dotenv variants: comments, blank lines,
//! `export ` prefixes, unquoted values (with ` #` inline comments), single
//! quotes (literal), and double quotes (escapes, multiline). The writer emits
//! a form this parser round-trips byte-for-value — the import→export
//! semantic round-trip gate depends on that inverse property.
//!
//! The classifier is BIASED TOWARD SECRET (c40) and only ever SUGGESTS —
//! every assignment is confirmed interactively or by explicit flag; there is
//! no silent default (c27).

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DotenvEntry {
    pub name: String,
    pub value: String,
    pub line: usize,
    /// The value was backtick-quoted. Node and npm dotenv read that as a
    /// quote (and so does this parser); python-dotenv and Compose keep the
    /// backticks, so `import` says so when it happens.
    pub backtick_quoted: bool,
}

pub fn parse_dotenv(text: &str) -> Result<Vec<DotenvEntry>, String> {
    parse_with_comments(text, false)
}

/// Setup accepts only literal values and requires ambiguous comment syntax to be
/// reviewed explicitly so a migration cannot silently change a credential.
pub fn parse_setup_dotenv(text: &str) -> Result<Vec<DotenvEntry>, String> {
    parse_with_comments(text, true)
}

fn parse_with_comments(text: &str, strict: bool) -> Result<Vec<DotenvEntry>, String> {
    let mut entries: Vec<DotenvEntry> = Vec::new();
    let mut lines = text.lines().enumerate().peekable();
    while let Some((idx, raw)) = lines.next() {
        let lineno = idx + 1;
        let line = raw.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let eq = line
            .find('=')
            .ok_or_else(|| format!("line {lineno}: expected KEY=VALUE"))?;
        let name = line[..eq].trim_end().to_owned();
        if !is_valid_var_name(&name) {
            return Err(format!("line {lineno}: invalid variable name {name:?}"));
        }
        let rest = line[eq + 1..].trim_start();
        let mut backtick_quoted = false;

        let value = if let Some(after) = rest.strip_prefix('"') {
            // Double-quoted: escapes; may span lines.
            let mut buf = String::new();
            let mut cur = after.to_owned();
            loop {
                match take_dquoted(&mut buf, &cur) {
                    Some(remainder) => {
                        if strict && !valid_remainder(&remainder) {
                            return Err(format!("line {lineno}: text after closing quote"));
                        }
                        break;
                    }
                    None => {
                        buf.push('\n');
                        match lines.next() {
                            Some((_, next)) => cur = next.to_owned(),
                            None => {
                                return Err(format!("line {lineno}: unterminated double quote"))
                            }
                        }
                    }
                }
            }
            buf
        } else if let Some((quote, after)) = rest
            .strip_prefix('\'')
            .map(|a| ('\'', a))
            .or_else(|| rest.strip_prefix('`').map(|a| ('`', a)))
        {
            // Single- or backtick-quoted: literal; may span lines; no escapes.
            // Backticks follow Node's --env-file and npm dotenv, the readers
            // a file imported from a JavaScript project was written for.
            backtick_quoted = quote == '`';
            let mut buf = String::new();
            let mut cur = after.to_owned();
            loop {
                if let Some(end) = cur.find(quote) {
                    if strict && !valid_remainder(&cur[end + quote.len_utf8()..]) {
                        return Err(format!("line {lineno}: text after closing quote"));
                    }
                    buf.push_str(&cur[..end]);
                    break;
                }
                buf.push_str(&cur);
                buf.push('\n');
                match lines.next() {
                    Some((_, next)) => cur = next.to_owned(),
                    None => return Err(format!("line {lineno}: unterminated {quote} quote")),
                }
            }
            buf
        } else {
            // Unquoted: trim, strip an inline ` #` comment.
            let mut v = rest;
            if strict
                && v.find('#')
                    .is_some_and(|i| i != 0 && !v.as_bytes()[i - 1].is_ascii_whitespace())
            {
                return Err(format!("line {lineno}: ambiguous unquoted hash"));
            }
            if strict && v.starts_with('#') {
                v = "";
            }
            if let Some(pos) = find_inline_comment(v) {
                v = &v[..pos];
            }
            v.trim().to_owned()
        };

        // Later assignments win, mirroring shell/dotenv semantics.
        entries.retain(|e| e.name != name);
        entries.push(DotenvEntry {
            name,
            value,
            line: lineno,
            backtick_quoted,
        });
    }
    Ok(entries)
}

fn valid_remainder(remainder: &str) -> bool {
    let rest = remainder.trim_start();
    rest.is_empty() || rest.starts_with('#')
}

/// Consumes double-quoted content from `cur` into `buf`. Returns
/// `Some(remainder)` when the closing quote was found on this line, `None`
/// when the value continues on the next line.
fn take_dquoted(buf: &mut String, cur: &str) -> Option<String> {
    let mut chars = cur.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(chars.as_str().to_owned()),
            '\\' => match chars.next() {
                Some('n') => buf.push('\n'),
                Some('r') => buf.push('\r'),
                Some('t') => buf.push('\t'),
                Some('"') => buf.push('"'),
                Some('\\') => buf.push('\\'),
                Some('$') => buf.push('$'),
                Some(other) => {
                    buf.push('\\');
                    buf.push(other);
                }
                None => {
                    // Trailing backslash: literal, value continues next line.
                    buf.push('\\');
                    return None;
                }
            },
            c => buf.push(c),
        }
    }
    None
}

/// An unquoted inline comment starts at ` #` (whitespace then hash).
fn find_inline_comment(v: &str) -> Option<usize> {
    let bytes = v.as_bytes();
    (1..bytes.len()).find(|&i| bytes[i] == b'#' && (bytes[i - 1] == b' ' || bytes[i - 1] == b'\t'))
}

pub fn is_valid_var_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && matches!(bytes[0], b'A'..=b'Z' | b'a'..=b'z' | b'_')
        && bytes[1..]
            .iter()
            .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

/// Why `value` cannot be written in a form every dotenv reader this tool
/// names (Node's `--env-file`, npm dotenv, python-dotenv, Docker Compose,
/// and this crate's `parse_dotenv`) reads back identically, or `None` when
/// it can. Three shapes are refused rather than written wrong:
///
///   * a carriage return anywhere: the double-quoted form needs `\r`, and
///     Node keeps that as two characters;
///   * a single quote or line feed together with `$`, `\`, `"` or a tab: the
///     double-quoted form needs an escape readers disagree on (Node keeps
///     the backslash, or ends the value at `\"`);
///   * two consecutive backslashes, or a trailing backslash: the
///     single-quoted form is literal to Node, Compose and this crate, but
///     python-dotenv unescapes `\\` inside single quotes and drops a line
///     that ends in `\'`.
///
/// Bare values are safe by construction (the writer never leaves a value
/// bare that starts with a quote character or holds a special character),
/// and every other single-quoted value reads alike everywhere. Both fuzzed
/// against the real readers by review; the three rules above are the exact
/// boundary.
pub fn readers_disagree_reason(value: &str) -> Option<&'static str> {
    if value.contains('\r') {
        return Some("it holds a carriage return (CRLF line endings)");
    }
    if value.contains(['\'', '\n']) && value.contains(['$', '\\', '"', '\t']) {
        return Some("it holds a single quote or a line break together with $, \\, \" or a tab");
    }
    if value.contains("\\\\") || value.ends_with('\\') {
        return Some("it holds two backslashes in a row, or ends with a backslash");
    }
    None
}

/// See [`readers_disagree_reason`].
pub fn readers_agree(value: &str) -> bool {
    readers_disagree_reason(value).is_none()
}

/// Append one `NAME=VALUE` line in the form the widest set of dotenv readers
/// agree on. A value that needs no quoting is written bare. Otherwise it is
/// SINGLE-quoted whenever it contains no single quote and no line break, so
/// a dollar sign or a double quote cannot be read two different ways. Only a
/// value holding a single quote or a newline falls back to double quotes
/// with escapes. Callers that promise reader agreement check
/// [`readers_agree`] first and refuse the shapes readers disagree on (an
/// escape in the double-quoted form; a doubled or trailing backslash, which
/// python-dotenv unescapes even inside single quotes).
pub fn write_dotenv_line(out: &mut String, name: &str, value: &str) {
    out.push_str(name);
    out.push('=');
    let needs_quotes = value.is_empty()
        // A leading quote of any kind, backtick included: Node's --env-file
        // and npm dotenv read a backtick as an opening quote.
        || value.starts_with(['"', '\'', '`'])
        || value.starts_with(char::is_whitespace)
        || value.ends_with(char::is_whitespace)
        || value
            .chars()
            .any(|c| matches!(c, '\n' | '\r' | '\t' | '#' | '"' | '\\' | '$' | '\'' | ' '));
    if !needs_quotes {
        out.push_str(value);
    } else if !value.contains(['\'', '\n', '\r']) {
        out.push('\'');
        out.push_str(value);
        out.push('\'');
    } else {
        out.push('"');
        for c in value.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '$' => out.push_str("\\$"),
                c => out.push(c),
            }
        }
        out.push('"');
    }
    out.push('\n');
}

// ---------------------------------------------------------------------------
// Classifier (c40): {not-a-secret, tier1..3}, biased toward secret
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    Var,
    Secret(u8),
}

#[derive(Debug, Clone, Copy)]
pub struct Suggestion {
    pub class: Classification,
    /// False = ambiguous — flagged for confirmation emphasis (the prompt
    /// happens either way; nothing is ever classified silently, c27).
    pub confident: bool,
}

const SECRET_NAME_MARKERS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "APIKEY",
    "PRIVATE",
    "CREDENTIAL",
    "ACCESS_KEY",
    "AUTH",
    "SIGNING",
    "DSN",
    "SALT",
    "LICENSE_KEY",
];

const VAR_NAME_PREFIXES: &[&str] = &[
    "NEXT_PUBLIC_",
    "PUBLIC_",
    "VITE_",
    "REACT_APP_",
    "EXPO_PUBLIC_",
];

/// These suffixes suggest configuration only after credential values and
/// secret-marker names have been excluded. A timeout or host label cannot
/// establish that a value is safe for plaintext storage. `_KEY`, `_ID`, and
/// `_NAME` are deliberately excluded because they often name credentials.
const VAR_NAME_SUFFIXES: &[&str] = &[
    "_HOST",
    "_HOSTNAME",
    "_PORT",
    "_BUCKET",
    "_REGION",
    "_ZONE",
    "_ENV",
    "_MODE",
    "_LEVEL",
    "_TIMEOUT",
    "_TIMEOUT_MS",
    "_LIMIT",
    "_ENABLED",
    "_DISABLED",
    "_VERSION",
    "_ORIGIN",
    "_DOMAIN",
];

const VAR_EXACT_NAMES: &[&str] = &[
    "PORT",
    "HOST",
    "HOSTNAME",
    "NODE_ENV",
    "RUST_LOG",
    "LOG_LEVEL",
    "DEBUG",
    "ENV",
    "ENVIRONMENT",
    "TZ",
    "LANG",
    "REGION",
    "AWS_REGION",
];

pub fn classify(name: &str, value: &str) -> Suggestion {
    let upper = name.to_ascii_uppercase();

    // Strong secret signals from the value.
    if value.contains("PRIVATE KEY-----") {
        return Suggestion {
            class: Classification::Secret(2),
            confident: true,
        };
    }
    if url_with_password(value) {
        return Suggestion {
            class: Classification::Secret(1),
            confident: true,
        };
    }
    // Familiar key prefixes should be encrypted even under a public-looking name.
    let known_prefix = [
        "sk-",
        "ghp_",
        "github_pat_",
        "AKIA",
        "gho_",
        "xoxb-",
        "xoxp-",
        "AIza",
    ]
    .iter()
    .any(|p| value.starts_with(p));
    if known_prefix {
        return Suggestion {
            class: Classification::Secret(1),
            confident: true,
        };
    }

    // Secret-marker names.
    if SECRET_NAME_MARKERS.iter().any(|m| upper.contains(m)) || upper.ends_with("_KEY") {
        return Suggestion {
            class: Classification::Secret(1),
            confident: true,
        };
    }

    // Paths and query strings can be bearer credentials. A URL's shape is
    // not evidence that it is safe to put in version-controlled plaintext.
    if value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .is_some_and(|rest| rest.trim_end_matches('/').contains(['/', '?', '#', '@']))
    {
        return Suggestion {
            class: Classification::Secret(1),
            confident: false,
        };
    }

    // Public-by-convention names.
    if VAR_NAME_PREFIXES.iter().any(|p| upper.starts_with(p)) {
        return Suggestion {
            class: Classification::Var,
            confident: true,
        };
    }

    // Remaining URL-like configuration is only a suggestion. Import still
    // requires explicit consent before writing any proposed plaintext.
    if value.starts_with("${")
        || value.starts_with("http://")
        || value.starts_with("https://")
        || value.starts_with("redis://") && !url_with_password(value)
        || value.starts_with("postgres://") && !url_with_password(value)
        || value.starts_with("postgresql://") && !url_with_password(value)
        || value.starts_with("mysql://") && !url_with_password(value)
        || value.starts_with("mongodb://") && !url_with_password(value)
        || value.starts_with("mongodb+srv://") && !url_with_password(value)
        || value.starts_with("amqp://") && !url_with_password(value)
    {
        return Suggestion {
            class: Classification::Var,
            confident: true,
        };
    }
    if VAR_NAME_SUFFIXES.iter().any(|s| upper.ends_with(s)) {
        return Suggestion {
            class: Classification::Var,
            confident: true,
        };
    }

    // Plainly-config names and values.
    if VAR_EXACT_NAMES.contains(&upper.as_str()) {
        return Suggestion {
            class: Classification::Var,
            confident: true,
        };
    }
    let lower = value.to_ascii_lowercase();
    if value.is_empty()
        || lower == "true"
        || lower == "false"
        || value.chars().all(|c| c.is_ascii_digit())
        || value.starts_with("http://")
        || value.starts_with("https://")
    {
        return Suggestion {
            class: Classification::Var,
            confident: true,
        };
    }

    // Long opaque blobs read as credentials.
    if value.len() >= 24
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+/=_-.".contains(c))
    {
        return Suggestion {
            class: Classification::Secret(1),
            confident: false,
        };
    }

    // Ambiguous: biased toward secret (c40) and flagged for confirmation.
    Suggestion {
        class: Classification::Secret(1),
        confident: false,
    }
}

/// `scheme://user:password@host` — credentials embedded in a URL.
fn url_with_password(value: &str) -> bool {
    let Some(scheme_end) = value.find("://") else {
        return false;
    };
    let rest = &value[scheme_end + 3..];
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    match authority.rfind('@') {
        Some(at) => authority[..at].contains(':'),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_dotenv_variants() {
        let text = "\
# comment
export API_KEY=abc123
PORT=8080
EMPTY=
QUOTED=\"line1\\nline2 with \\\"quotes\\\" and \\$dollar\"
SINGLE='raw $VALUE # not comment'
INLINE=value # trailing comment
HASH_IN_VALUE=va#lue
SPACED =  padded value
";
        let entries = parse_dotenv(text).unwrap();
        let get = |n: &str| entries.iter().find(|e| e.name == n).unwrap().value.clone();
        assert_eq!(get("API_KEY"), "abc123");
        assert_eq!(get("PORT"), "8080");
        assert_eq!(get("EMPTY"), "");
        assert_eq!(get("QUOTED"), "line1\nline2 with \"quotes\" and $dollar");
        assert_eq!(get("SINGLE"), "raw $VALUE # not comment");
        assert_eq!(get("INLINE"), "value");
        assert_eq!(get("HASH_IN_VALUE"), "va#lue");
        assert_eq!(get("SPACED"), "padded value");
    }

    #[test]
    fn multiline_quoted_values() {
        let entries =
            parse_dotenv("CERT=\"-----BEGIN X-----\nabc\ndef\n-----END X-----\"\nNEXT=1\n")
                .unwrap();
        assert_eq!(
            entries[0].value,
            "-----BEGIN X-----\nabc\ndef\n-----END X-----"
        );
        assert_eq!(entries[1].name, "NEXT");
    }

    #[test]
    fn later_assignment_wins_and_errors_are_positioned() {
        let entries = parse_dotenv("A=1\nA=2\n").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].value, "2");
        assert!(parse_dotenv("no_equals_here\n").is_err());
        assert!(parse_dotenv("1BAD=x\n").is_err());
        assert!(parse_dotenv("A=\"unterminated\n").is_err());
    }

    #[test]
    fn writer_round_trips_through_parser() {
        let cases = [
            ("PLAIN", "simple-value_123"),
            ("EMPTY", ""),
            ("NEWLINES", "a\nb\r\nc"),
            ("QUOTES", "say \"hi\" \\ back"),
            ("DOLLAR", "pre$var post"),
            ("HASHY", "x # y"),
            ("SPACES", "  padded  "),
            ("TABS", "a\tb"),
            ("UNICODE", "héllo 日本"),
            ("SINGLEQ", "it's"),
        ];
        let mut out = String::new();
        for (k, v) in &cases {
            write_dotenv_line(&mut out, k, v);
        }
        let parsed = parse_dotenv(&out).unwrap();
        assert_eq!(parsed.len(), cases.len());
        for ((k, v), entry) in cases.iter().zip(parsed.iter()) {
            assert_eq!(&entry.name, k);
            assert_eq!(&entry.value, v, "round-trip failed for {k}");
        }
    }

    #[test]
    fn classifier_is_biased_toward_secret() {
        assert!(matches!(
            classify("DB_PASSWORD", "hunter2").class,
            Classification::Secret(_)
        ));
        assert!(matches!(
            classify("STRIPE_KEY", "sk-live-abc").class,
            Classification::Secret(1)
        ));
        assert!(matches!(
            classify("SOMETHING", "postgres://u:p@h/db").class,
            Classification::Secret(_)
        ));
        assert!(matches!(
            classify("TLS_CERT", "-----BEGIN PRIVATE KEY-----").class,
            Classification::Secret(2)
        ));
        // Plain config leans var.
        assert_eq!(classify("PORT", "8080").class, Classification::Var);
        assert_eq!(classify("NEXT_PUBLIC_URL", "x").class, Classification::Var);
        assert_eq!(
            classify("API_URL", "https://api.example.com").class,
            Classification::Var
        );
        // Unknown = secret suggestion, flagged ambiguous.
        let s = classify("MYSTERY", "opaque-ish");
        assert!(matches!(s.class, Classification::Secret(1)));
        assert!(!s.confident);
    }

    /// NOTHING is approval-gated by default. Every well-known credential shape
    /// is a confident tier-1 secret; the approval-gated posture is reachable
    /// only by an explicit choice (`a` at the prompt / "approval-gated" in a
    /// decisions file). Accepting the defaults must never leave a `run`
    /// blocking on a hardware tap.
    #[test]
    fn known_credential_shapes_are_confident_tier1_never_approval_gated() {
        for (name, value) in [
            ("OPENAI_API_KEY", "sk-proj-abc123"),
            ("ANTHROPIC_API_KEY", "sk-ant-api03-abc"),
            ("GITHUB_TOKEN", "ghp_abc123"),
            ("GITHUB_TOKEN", "github_pat_abc123"),
            ("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"),
            ("GITHUB_OAUTH", "gho_abc123"),
            ("SLACK_BOT_TOKEN", "xoxb-abc123"),
            ("SLACK_USER_TOKEN", "xoxp-abc123"),
            ("GEMINI_API_KEY", "AIzaSyExample"),
        ] {
            let s = classify(name, value);
            assert_eq!(
                s.class,
                Classification::Secret(1),
                "classification for {name}"
            );
            assert!(s.confident, "classification for {name}");
        }
        // Private keys still outrank everything (stored tier 2).
        assert_eq!(
            classify("TLS_CERT", "-----BEGIN PRIVATE KEY-----").class,
            Classification::Secret(2)
        );
    }

    #[test]
    fn secret_markers_remain_conservative_under_config_and_public_names() {
        for (name, value) in [
            ("AUTH_TIMEOUT_MS", "30000"),
            ("NEXTAUTH_URL", "http://localhost:3000"),
            ("NEXT_PUBLIC_API_KEY", "synthetic-credential"),
            ("VITE_AUTH_TOKEN", "synthetic-credential"),
        ] {
            let suggestion = classify(name, value);
            assert_eq!(
                suggestion.class,
                Classification::Secret(1),
                "classification for {name}"
            );
            assert!(suggestion.confident, "name marker for {name}");
        }
        assert_eq!(
            classify("REQUEST_TIMEOUT_MS", "30000").class,
            Classification::Var
        );
        assert_eq!(
            classify("NEXT_PUBLIC_APP_URL", "http://localhost:3000").class,
            Classification::Var
        );
    }

    /// Configuration suggestions apply only after stronger secret signals.
    /// Explicit plaintext review remains necessary for these shapes too.
    #[test]
    fn plain_config_suggestions_do_not_override_secret_names() {
        for (name, value) in [
            ("UPSTASH_REDIS_REST_URL", "https://us1-example.upstash.io"),
            ("S3_BUCKET", "my-app-uploads"),
            ("SMTP_HOST", "smtp.example.com"),
            ("SMTP_PORT", "587"),
            ("API_BASE", "${NEXT_PUBLIC_APP_URL}/api"),
            ("DATABASE_URL", "postgres://localhost:5432/dev"),
            ("REDIS_URL", "redis://localhost:6379"),
        ] {
            let s = classify(name, value);
            assert_eq!(s.class, Classification::Var, "classification for {name}");
            assert!(s.confident, "classification for {name}");
        }
        // ...while the SAME names with credentials in the value stay secret.
        for (name, value) in [
            (
                "DATABASE_URL",
                "postgresql://app:s3cretpw@localhost:5432/mydb",
            ),
            ("REDIS_URL", "redis://:hunter2@host:6379"),
            (
                "NEXTAUTH_SECRET",
                "Zq8vN2mLp4RsT6uWxYzA1bC3dE5fG7hJ9kM0nP2qR4s=",
            ),
            (
                "AWS_SECRET_ACCESS_KEY",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            ),
        ] {
            let s = classify(name, value);
            assert!(
                matches!(s.class, Classification::Secret(_)),
                "{name} must stay a secret, got {:?}",
                s.class
            );
        }
    }

    /// `readers_agree` admits exactly the shapes every named reader parses
    /// alike: bare, single-quoted, and double-quoted needing only `\n`.
    #[test]
    fn readers_agree_matches_the_writer_forms() {
        for ok in [
            "plain",
            "p$ssw0rd",
            "a\\b",
            "val with space # hash \"q\" $x",
            "  padded  ",
            "don't panic",
            "line one\nline two",
            "-----BEGIN KEY-----\nabc\n-----END KEY-----\n",
            "it's\ntwo lines",
            "`abc123`",
            "`tick",
            "C:\\Users\\app",
            "a\\b",
        ] {
            assert!(readers_agree(ok), "{ok:?} should be writable");
            let mut line = String::new();
            write_dotenv_line(&mut line, "K", ok);
            let back = parse_dotenv(&line).unwrap();
            assert_eq!(back[0].value, ok, "{ok:?} must round-trip");
        }
        for bad in [
            "it's a $5 bill",
            "it's \"quoted\"",
            "it's a back\\slash",
            "it's\ttabbed",
            "a\rb",
            "-----BEGIN KEY-----\r\nabc\r\n-----END KEY-----\r\n",
            "line\nwith $dollar",
            "a\\\\b",
            "\\\\server\\share",
            "secret\\",
            "C:\\Users\\me\\",
        ] {
            assert!(!readers_agree(bad), "{bad:?} must be refused");
            assert!(readers_disagree_reason(bad).is_some());
        }
    }
}
