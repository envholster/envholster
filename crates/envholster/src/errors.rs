//! Machine-actionable CLI errors (plan/07 §7.10, normative P0).
//!
//! Every user-facing failure names its likely cause and the EXACT next
//! command. Stable error codes + a JSON error line on stderr: agents act on
//! stderr, so machine-actionable errors are a feature, not polish.
//!
//! Exit-code classes (stable): 0 success · 1 generic failure · 2 usage/argv
//! (clap) · 3 not-found · 4 denied · 5 locked/no-identity · 6 parse/format ·
//! 7 check/doctor findings.
//!
//! Display strings never contain secret material — CoreError displays are
//! value-free by contract, and nothing here adds values.

use envholster_core::{CoreError, ManifestError};

pub const EXIT_OK: i32 = 0;
pub const EXIT_FAILURE: i32 = 1;
// 2 is clap's usage-error exit, kept as the argv/usage class.
pub const EXIT_NOT_FOUND: i32 = 3;
pub const EXIT_DENIED: i32 = 4;
pub const EXIT_LOCKED: i32 = 5;
pub const EXIT_PARSE: i32 = 6;
pub const EXIT_FINDINGS: i32 = 7;

#[derive(Debug)]
pub struct CliError {
    /// Stable machine code, SCREAMING_SNAKE.
    pub code: &'static str,
    pub exit: i32,
    pub message: String,
    /// The exact next command (plan/07 §7.10) — present on every error we
    /// can name one for.
    pub next: Option<String>,
}

impl CliError {
    pub fn new(
        code: &'static str,
        exit: i32,
        message: impl Into<String>,
        next: Option<String>,
    ) -> Self {
        CliError {
            code,
            exit,
            message: message.into(),
            next,
        }
    }

    pub fn failure(message: impl Into<String>, next: Option<String>) -> Self {
        Self::new("FAILURE", EXIT_FAILURE, message, next)
    }

    pub fn not_found(message: impl Into<String>, next: Option<String>) -> Self {
        Self::new("NOT_FOUND", EXIT_NOT_FOUND, message, next)
    }

    pub fn denied(message: impl Into<String>, next: Option<String>) -> Self {
        Self::new("DENIED", EXIT_DENIED, message, next)
    }

    pub fn parse(message: impl Into<String>, next: Option<String>) -> Self {
        Self::new("PARSE", EXIT_PARSE, message, next)
    }

    /// A prompt was required but stdin is not a TTY (plan/07 §7.7/§7.10:
    /// interactive fallback in non-TTY contexts is a hard machine-readable
    /// error).
    pub fn interactive_required(what: &str, next: impl Into<String>) -> Self {
        Self::new(
            "INTERACTIVE_REQUIRED",
            EXIT_FAILURE,
            format!("{what} requires an interactive terminal (no TTY on stdin)"),
            Some(next.into()),
        )
    }

    /// Attach/replace the next-command hint.
    pub fn with_next(mut self, next: impl Into<String>) -> Self {
        self.next = Some(next.into());
        self
    }

    /// Human lines + one JSON line, all on stderr (plan/07 §7.10).
    pub fn emit(&self) {
        let message = strip_bidi_isolates(&self.message);
        let next = self.next.as_deref().map(strip_bidi_isolates);
        eprintln!("error[{}]: {}", self.code, message);
        if let Some(next) = &next {
            eprintln!("next: {next}");
        }
        let mut json = String::from("{\"code\":");
        json_escape_into(&mut json, self.code);
        json.push_str(",\"message\":");
        json_escape_into(&mut json, &message);
        if let Some(next) = &next {
            json.push_str(",\"next\":");
            json_escape_into(&mut json, next);
        }
        json.push('}');
        eprintln!("{json}");
    }
}

/// Drop U+2066..=U+2069 (the Unicode bidi ISOLATE controls) from error text.
///
/// The age crate's fluent i18n layer wraps every interpolated value in
/// FSI/PDI (U+2068/U+2069), so a message like "could not find
/// \u{2068}age-plugin-yubikey\u{2069} on the PATH" carries invisible
/// formatting characters that are pure rendering noise here. The app's
/// display sanitizer rightly refuses to render bidi controls and shows them
/// as visible `\uXXXX` escapes instead — turning a real, actionable error
/// into apparent mojibake. Stripping the isolate class at the emit seam is
/// as neutralizing as escaping (an absent control reorders nothing) and it
/// is done ONLY for this closed four-character class the i18n layer injects
/// — every other scalar, including the rest of the bidi controls, passes
/// through untouched for the renderer to judge.
fn strip_bidi_isolates(s: &str) -> String {
    s.chars()
        .filter(|c| !('\u{2066}'..='\u{2069}').contains(c))
        .collect()
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<CoreError> for CliError {
    fn from(error: CoreError) -> Self {
        let message = error.to_string();
        match &error {
            CoreError::SecretNotFound(_) => CliError::new(
                "SECRET_NOT_FOUND",
                EXIT_NOT_FOUND,
                message,
                Some("envholster list".to_owned()),
            ),
            CoreError::RecipientNotFound(_) => CliError::new(
                "RECIPIENT_NOT_FOUND",
                EXIT_NOT_FOUND,
                message,
                Some("envholster recipient list".to_owned()),
            ),
            CoreError::ForbiddenWrap { .. } => CliError::new(
                "FORBIDDEN_WRAP",
                EXIT_DENIED,
                message,
                Some(
                    "enroll a hardware recipient for tier >= 2 cells: \
                     envholster recipient add <age1yubikey1...> --class hardware --label <label>"
                        .to_owned(),
                ),
            ),
            CoreError::PluginNotAllowed(_) => CliError::new(
                "PLUGIN_NOT_ALLOWED",
                EXIT_DENIED,
                message,
                Some("supported plugins: yubikey, se — see envholster doctor".to_owned()),
            ),
            CoreError::CellLocked { env, tier } => CliError::new(
                "VAULT_LOCKED",
                EXIT_LOCKED,
                message,
                Some(format!(
                    "supply an identity that can unwrap cell {env}:{tier}: \
                     --identity <path> or ENVHOLSTER_IDENTITY"
                )),
            ),
            CoreError::NoMatchingIdentity { .. } | CoreError::WrongPassphrase => CliError::new(
                "NO_MATCHING_IDENTITY",
                EXIT_LOCKED,
                message,
                Some(
                    "supply an identity via --identity <path>, ENVHOLSTER_IDENTITY, or \
                     ENVHOLSTER_IDENTITY_FILE; enroll a new one with \
                     'envholster identity generate --label <label>' then ask a vault holder \
                     to run 'envholster recipient add <your age1... public key> --class software \
                     --label <label>'"
                        .to_owned(),
                ),
            ),
            CoreError::HeaderParse { .. }
            | CoreError::UnknownRecipientKind { .. }
            | CoreError::InvalidName { .. }
            | CoreError::ExcessiveWork { .. } => CliError::new("PARSE", EXIT_PARSE, message, None),
            CoreError::UnsupportedSchema { .. } => CliError::new(
                "UNSUPPORTED_SCHEMA",
                EXIT_PARSE,
                message,
                Some("install a newer envholster release".to_owned()),
            ),
            CoreError::AeadFailed { .. } | CoreError::AgeDecrypt(_) => CliError::new(
                "DECRYPT_FAILED",
                EXIT_LOCKED,
                message,
                Some(
                    "the vault file may be corrupted or from a mismatched generation; \
                     check 'git status' / 'envholster doctor'"
                        .to_owned(),
                ),
            ),
            CoreError::RecoveryLockstep { .. } => CliError::new(
                "RECOVERY_LOCKSTEP",
                EXIT_FAILURE,
                message,
                Some("envholster recovery verify".to_owned()),
            ),
            CoreError::RecoveryRecipientCount { .. } => CliError::new(
                "RECOVERY_RECIPIENT",
                EXIT_DENIED,
                message,
                Some(
                    "exactly one recovery recipient must stay enrolled; \
                     see docs/RECOVERY-SPEC.md"
                        .to_owned(),
                ),
            ),
            CoreError::Io(io) if io.kind() == std::io::ErrorKind::WouldBlock => {
                // Design-deck item 6, CLI-side wording ONLY: core's contract
                // string ("vault {path} is locked by another envholster
                // process; serialize vault edits") is re-voiced here into the
                // deck's copy, naming the two real-world holders — the Env
                // Holster app serving the project, or another envholster
                // command — without teaching flock/process internals. The
                // suffix swap preserves the interpolated path (a user with
                // several projects needs to know WHICH vault is contended);
                // an unrecognized shape passes through untouched rather than
                // guessing. Core keeps its own wording.
                let message = message
                    .strip_suffix("is locked by another envholster process; serialize vault edits")
                    .map(|kept| {
                        format!(
                            "{kept}is in use by another \
             envholster command"
                        )
                    })
                    .unwrap_or(message);
                CliError::new(
                    "VAULT_BUSY",
                    EXIT_LOCKED,
                    message,
                    // `run` releases the vault before its child starts, so a
                    // running app is never the holder; a command waiting at a
                    // prompt is.
                    Some(
                        "another envholster command is still using the vault (for example, \
                         one waiting for you to answer a prompt); finish it, then retry"
                            .to_owned(),
                    ),
                )
            }
            CoreError::Io(_)
            | CoreError::Mem(_)
            | CoreError::Entropy(_)
            | CoreError::AgeEncrypt(_) => CliError::new("FAILURE", EXIT_FAILURE, message, None),
        }
    }
}

impl From<ManifestError> for CliError {
    fn from(error: ManifestError) -> Self {
        CliError::new("MANIFEST_PARSE", EXIT_PARSE, error.to_string(), None)
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        CliError::failure(error.to_string(), None)
    }
}

/// Minimal JSON string escaping (RFC 8259): `"`, `\`, and control chars.
pub fn json_escape_into(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    json_escape_into(&mut out, s);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact shape the age crate's fluent layer produces: interpolated
    /// values wrapped in FSI/PDI. Only the isolate class disappears — other
    /// bidi controls (e.g. U+202E RLO) pass through for the renderer to
    /// neutralize visibly.
    #[test]
    fn bidi_isolates_are_stripped_and_nothing_else() {
        assert_eq!(
            strip_bidi_isolates(
                "could not find \u{2068}age-plugin-yubikey\u{2069} on the PATH.\nHave you \
                 installed the plugin?"
            ),
            "could not find age-plugin-yubikey on the PATH.\nHave you installed the plugin?"
        );
        assert_eq!(
            strip_bidi_isolates("\u{2066}a\u{2067}b\u{2068}c\u{2069}"),
            "abc"
        );
        let rlo = "name\u{202E}evil";
        assert_eq!(strip_bidi_isolates(rlo), rlo);
    }

    #[test]
    fn exit_classes_are_distinct() {
        let codes = [
            EXIT_OK,
            EXIT_FAILURE,
            2,
            EXIT_NOT_FOUND,
            EXIT_DENIED,
            EXIT_LOCKED,
            EXIT_PARSE,
            EXIT_FINDINGS,
        ];
        for (i, a) in codes.iter().enumerate() {
            for b in &codes[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn core_error_classes_map_to_distinct_exits() {
        assert_eq!(
            CliError::from(CoreError::SecretNotFound("X".into())).exit,
            EXIT_NOT_FOUND
        );
        assert_eq!(
            CliError::from(CoreError::CellLocked {
                env: "prod".into(),
                tier: 2
            })
            .exit,
            EXIT_LOCKED
        );
        assert_eq!(
            CliError::from(CoreError::ForbiddenWrap {
                recipient: "id".into(),
                class: envholster_core::RecipientClass::Software,
                env: "prod".into(),
                tier: 2
            })
            .exit,
            EXIT_DENIED
        );
        assert_eq!(
            CliError::from(CoreError::HeaderParse { reason: "x".into() }).exit,
            EXIT_PARSE
        );
    }

    #[test]
    fn every_mapped_error_names_a_next_command_where_defined() {
        let e = CliError::from(CoreError::NoMatchingIdentity {
            env: "prod".into(),
            tier: 2,
            saw_wrong_passphrase: false,
        });
        assert_eq!(e.code, "NO_MATCHING_IDENTITY");
        assert!(e.next.as_deref().unwrap().contains("--identity"));
    }

    /// Design-deck contract (item 6): the lock-contention error names the two
    /// real-world holder — another
    /// envholster command — and the remedy, without teaching internals
    /// (flock/process/serialize). The reword happens HERE, CLI-side, from
    /// core's unchanged contract string; the interpolated vault path survives
    /// so a multi-project user knows which vault is contended. Same code path,
    /// same code/exit class as ever.
    #[test]
    fn vault_busy_copy_names_the_app_or_another_command_not_internals() {
        // EXACTLY what core's acquire_lock produces on a held lock: an Io
        // error with WouldBlock kind carrying core's own message verbatim.
        let e = CliError::from(CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "vault /p/secrets.holster is locked by another envholster process; \
             serialize vault edits",
        )));
        assert_eq!(e.code, "VAULT_BUSY");
        assert_eq!(e.exit, EXIT_LOCKED);
        assert_eq!(
            e.message,
            "vault /p/secrets.holster is in use by another \
             envholster command"
        );
        // The remedy names the likely holder and the one action that helps.
        assert_eq!(
            e.next.as_deref().unwrap(),
            "another envholster command is still using the vault (for example, one waiting for \
             you to answer a prompt); finish it, then retry"
        );
        for banned in ["flock", "process", "serialize"] {
            assert!(!e.message.contains(banned), "message teaches '{banned}'");
            assert!(
                !e.next.as_deref().unwrap().contains(banned),
                "next teaches '{banned}'"
            );
        }
    }

    /// A WouldBlock message the CLI does not recognize (a future core wording,
    /// or a non-lock WouldBlock) passes through untouched — the reword is a
    /// suffix swap, never a guess.
    #[test]
    fn vault_busy_unrecognized_shape_passes_through() {
        let e = CliError::from(CoreError::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "something else would block",
        )));
        assert_eq!(e.code, "VAULT_BUSY");
        assert_eq!(e.message, "something else would block");
    }

    #[test]
    fn json_escaping() {
        assert_eq!(json_string("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
        assert_eq!(json_string("\u{1}"), "\"\\u0001\"");
    }
}
