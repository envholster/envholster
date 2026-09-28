//! Import-time recognition of well-known provider API keys.
//!
//! When `import` recognizes one of these, it records the secret with mode
//! `api-key` instead of `env-var`. In this release that is a label only:
//! `run` delivers the value as a plain environment variable. The earlier
//! daemon-era proxy layer keyed on it to hand a child a
//! placeholder instead of the real key, and a future opt-in proxy will again.
//!
//! Recognition is deliberately CONSERVATIVE: a provider matches only when the
//! variable NAME is one the provider's SDK actually reads AND the VALUE carries the provider's
//! well-known prefix. Either signal alone is not enough — a gateway key parked
//! under `OPENAI_API_KEY`, or a random value in a look-alike name, must never
//! get a wrong upstream pinned (a wrong pin silently breaks the tool at run
//! time). Ambiguous names (`GOOGLE_API_KEY` serves Maps as readily as Gemini)
//! are excluded on purpose; the user can pin those by hand in the manifest.
//!
//! ADMIN keys (c8: `sk-ant-admin…`, `sk-admin-…`) are never recognized as
//! brokerable; a proxy layer must refuse them again on its own.

/// One brokerable provider: the manifest facts `import` writes so the
/// a proxy layer would key on this.
pub struct BrokeredProvider {
    /// Short id for human output ("anthropic").
    pub id: &'static str,
    /// Variable names the provider's SDK reads (must match exactly).
    pub names: &'static [&'static str],
    /// Value prefixes that identify this provider's keys.
    pub value_prefixes: &'static [&'static str],
    /// Upstream host pins (bare hostnames; the proxy originates TLS on :443).
    pub hosts: &'static [&'static str],
    /// Starter "METHOD /path-prefix" allow rules. The proxy default-denies
    /// anything not explicitly allowed, so pins without allow rules would
    /// block every request. These cover the provider's normal inference
    /// surface; the manifest block is plain TOML the user can widen or narrow.
    pub allow: &'static [&'static str],
    /// Extra deny path prefixes on top of the proxy's frozen admin deny list.
    pub deny: &'static [&'static str],
}

/// Admin-key value prefixes (c8): forced away from brokering — an admin key
/// must never get an upstream pinned by import.
const ADMIN_VALUE_PREFIXES: &[&str] = &["sk-ant-admin", "sk-admin-"];

/// Value prefixes that identify a DIFFERENT provider riding a compatible
/// name (an OpenRouter key parked in `OPENAI_API_KEY` for SDK compatibility):
/// recognized-name-but-foreign-value is refused rather than mis-pinned.
const OPENAI_FOREIGN_PREFIXES: &[&str] = &["sk-ant-", "sk-or-"];

const PROVIDERS: &[BrokeredProvider] = &[
    BrokeredProvider {
        id: "anthropic",
        names: &["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"],
        value_prefixes: &["sk-ant-"],
        hosts: &["api.anthropic.com"],
        allow: &["POST /v1/messages", "GET /v1/models"],
        deny: &[],
    },
    BrokeredProvider {
        id: "openai",
        names: &["OPENAI_API_KEY"],
        value_prefixes: &["sk-"],
        hosts: &["api.openai.com"],
        allow: &[
            "POST /v1/chat/completions",
            "POST /v1/responses",
            "POST /v1/completions",
            "POST /v1/embeddings",
            "POST /v1/moderations",
            "GET /v1/models",
        ],
        // OpenAI's admin surface is `/v1/organization/…` (singular); the
        // proxy's frozen default only denies `/v1/organizations/`.
        deny: &["/v1/organization/"],
    },
    BrokeredProvider {
        id: "gemini",
        names: &["GEMINI_API_KEY", "GOOGLE_GEMINI_API_KEY"],
        value_prefixes: &["AIza"],
        hosts: &["generativelanguage.googleapis.com"],
        allow: &[
            "POST /v1beta/models",
            "GET /v1beta/models",
            "POST /v1/models",
            "GET /v1/models",
        ],
        deny: &[],
    },
    BrokeredProvider {
        id: "openrouter",
        names: &["OPENROUTER_API_KEY"],
        value_prefixes: &["sk-or-"],
        hosts: &["openrouter.ai"],
        allow: &[
            "POST /api/v1/chat/completions",
            "POST /api/v1/completions",
            "GET /api/v1/models",
        ],
        deny: &[],
    },
];

/// Is this value an ADMIN key (c8)? Admin keys are refused brokering.
pub fn is_admin_key(value: &str) -> bool {
    ADMIN_VALUE_PREFIXES.iter().any(|p| value.starts_with(p))
}

/// Recognize a (name, value) pair as a brokerable provider key. `None` means
/// "import must not pin an upstream for this" — including admin keys and
/// recognized names carrying a foreign provider's value.
pub fn recognize(name: &str, value: &str) -> Option<&'static BrokeredProvider> {
    if is_admin_key(value) {
        return None;
    }
    let provider = PROVIDERS.iter().find(|p| {
        p.names.contains(&name) && p.value_prefixes.iter().any(|v| value.starts_with(v))
    })?;
    // A compatible-name variable carrying ANOTHER provider's key (OpenRouter /
    // Anthropic keys ride `OPENAI_API_KEY` for SDK compatibility) must not get
    // api.openai.com pinned — the pin would break the tool at run time.
    if provider.id == "openai" && OPENAI_FOREIGN_PREFIXES.iter().any(|p| value.starts_with(p)) {
        return None;
    }
    Some(provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_matrix_providers_by_name_and_value() {
        assert_eq!(
            recognize("ANTHROPIC_API_KEY", "sk-ant-api03-xyz")
                .unwrap()
                .id,
            "anthropic"
        );
        assert_eq!(
            recognize("ANTHROPIC_AUTH_TOKEN", "sk-ant-oat-xyz")
                .unwrap()
                .id,
            "anthropic"
        );
        assert_eq!(
            recognize("OPENAI_API_KEY", "sk-proj-xyz").unwrap().id,
            "openai"
        );
        assert_eq!(
            recognize("GEMINI_API_KEY", "AIzaSyExample").unwrap().id,
            "gemini"
        );
        assert_eq!(
            recognize("OPENROUTER_API_KEY", "sk-or-v1-xyz").unwrap().id,
            "openrouter"
        );
    }

    #[test]
    fn either_signal_alone_is_not_enough() {
        // Right value shape, wrong/unknown name: no pin.
        assert!(recognize("MY_KEY", "sk-proj-xyz").is_none());
        assert!(recognize("STRIPE_SECRET_KEY", "sk-live-xyz").is_none());
        // Right name, wrong value shape (a gateway/self-hosted credential): no pin.
        assert!(recognize("OPENAI_API_KEY", "gsk_groq_key").is_none());
        assert!(recognize("ANTHROPIC_API_KEY", "not-an-anthropic-key").is_none());
        // Deliberately-ambiguous names are excluded (Maps keys are AIza too).
        assert!(recognize("GOOGLE_API_KEY", "AIzaSyExample").is_none());
    }

    #[test]
    fn foreign_keys_riding_openai_api_key_are_refused() {
        assert!(recognize("OPENAI_API_KEY", "sk-or-v1-xyz").is_none());
        assert!(recognize("OPENAI_API_KEY", "sk-ant-api03-xyz").is_none());
    }

    #[test]
    fn admin_keys_are_never_pinned() {
        assert!(is_admin_key("sk-ant-admin01-xyz"));
        assert!(is_admin_key("sk-admin-xyz"));
        assert!(recognize("ANTHROPIC_API_KEY", "sk-ant-admin01-xyz").is_none());
        assert!(recognize("OPENAI_API_KEY", "sk-admin-xyz").is_none());
    }

    #[test]
    fn every_provider_has_pins_and_allow_rules() {
        // Pins without allow rules would make the proxy deny every request —
        // strictly worse than the G5 fallback the pin replaced.
        for p in PROVIDERS {
            assert!(!p.hosts.is_empty(), "{} has no host pin", p.id);
            assert!(!p.allow.is_empty(), "{} has no allow rules", p.id);
            for rule in p.allow {
                let (method, path) = rule
                    .split_once(' ')
                    .unwrap_or_else(|| panic!("{}: rule {rule:?} is not 'METHOD /path'", p.id));
                assert!(!method.is_empty() && method.chars().all(|c| c.is_ascii_uppercase()));
                assert!(
                    path.starts_with('/'),
                    "{}: {rule:?} path must be absolute",
                    p.id
                );
            }
        }
    }
}
