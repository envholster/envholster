//! `${NAME}` reference expansion for delivered values (plan/07 §7.4).
//!
//! WHY THIS EXISTS. A real `.env` file is not a flat list: Next.js (`@next/env`),
//! Vite, dotenv-expand, and Docker Compose all expand `${NAME}` references at
//! load time, so a file that says `API_BASE=${NEXT_PUBLIC_APP_URL}/api` means
//! the *expanded* string to every tool that reads it. A vault that replaces the
//! file and hands the child the literal `${NEXT_PUBLIC_APP_URL}/api` has
//! silently changed what the app sees. Expansion therefore happens at every
//! delivery seam (`run`, `export`), never at import — the stored value stays
//! byte-identical to what the file said, so import→export round-trips.
//!
//! WHAT IS EXPANDED. Only the BRACED form `${NAME}` and its default-bearing
//! variant `${NAME:-default}`. The bare `$NAME` form is deliberately NOT
//! expanded: passwords and tokens routinely contain `$` followed by letters
//! (`p$ssw0rd`, `$2b$12$…` bcrypt hashes), and treating those as references
//! would corrupt secret values. Braces are unambiguous. An unresolvable
//! reference is left verbatim rather than blanked — blanking is how
//! dotenv-expand behaves, but it turns a typo into an invisible empty string
//! inside a database URL; leaving `${TYPO}` in place fails loudly at the
//! consumer instead. `$${NAME}` escapes to a literal `${NAME}`.
//!
//! WHAT IT IS EXPANDED AGAINST. A caller-supplied lookup over the *final*
//! delivered set (vars + secrets, secrets winning on collision), so a secret
//! such as `DATABASE_URL=postgres://app:${DB_PASSWORD}@host/db` resolves the
//! password from its sibling secret — the most common shape dotenv-expand is
//! used for. Resolution is recursive with a hard depth cap so a cycle
//! (`A=${B}`, `B=${A}`) terminates with the references left literal instead of
//! hanging or overflowing the stack.

/// Maximum nesting of references followed before giving up on a chain and
/// leaving the innermost reference literal. Real files nest one or two deep.
const MAX_DEPTH: usize = 8;

/// Expand `${NAME}` / `${NAME:-default}` in `value`, resolving each name
/// through `lookup`, which returns the *raw* (unexpanded) value for a name or
/// `None` when the name is unknown. Referenced values are themselves expanded
/// (depth-capped) before substitution.
pub fn expand<F>(value: &str, lookup: &F) -> String
where
    F: Fn(&str) -> Option<String>,
{
    expand_depth(value, lookup, 0)
}

/// True when `value` contains at least one `${` that is not escaped as `$${`.
/// Lets callers skip the allocation for the overwhelmingly common plain case.
pub fn has_reference(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'$' && bytes[i + 1] == b'{' {
            // `$${` is an escape, not a reference.
            if i > 0 && bytes[i - 1] == b'$' {
                i += 2;
                continue;
            }
            return true;
        }
        i += 1;
    }
    false
}

fn expand_depth<F>(value: &str, lookup: &F, depth: usize) -> String
where
    F: Fn(&str) -> Option<String>,
{
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        // Escaped `$${…}` → emit a literal `${` and continue after it.
        if start > 0 && rest.as_bytes()[start - 1] == b'$' {
            out.push_str(&rest[..start - 1]);
            out.push_str("${");
            rest = &rest[start + 2..];
            continue;
        }
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            // Unterminated: nothing sensible to do — keep the tail verbatim.
            out.push_str(&rest[start..]);
            return out;
        };
        let inner = &after[..end];
        let (name, default) = match inner.split_once(":-") {
            Some((n, d)) => (n, Some(d)),
            None => (inner, None),
        };
        let substituted = if is_var_name(name) && depth < MAX_DEPTH {
            match lookup(name) {
                Some(raw) => Some(expand_depth(&raw, lookup, depth + 1)),
                None => default.map(|d| expand_depth(d, lookup, depth + 1)),
            }
        } else {
            None
        };
        match substituted {
            Some(v) => out.push_str(&v),
            // Unknown name, no default, bad name, or depth exhausted: leave the
            // reference exactly as written so the consumer fails loudly.
            None => {
                out.push_str("${");
                out.push_str(inner);
                out.push('}');
            }
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

fn is_var_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && matches!(b[0], b'A'..=b'Z' | b'a'..=b'z' | b'_')
        && b[1..]
            .iter()
            .all(|c| matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn lookup_in(m: &BTreeMap<String, String>) -> impl Fn(&str) -> Option<String> + '_ {
        move |n| m.get(n).cloned()
    }

    #[test]
    fn expands_the_nextjs_shape() {
        let m = map(&[("NEXT_PUBLIC_APP_URL", "http://localhost:3000")]);
        assert_eq!(
            expand("${NEXT_PUBLIC_APP_URL}/api", &lookup_in(&m)),
            "http://localhost:3000/api"
        );
    }

    #[test]
    fn expands_a_password_into_a_database_url() {
        let m = map(&[("DB_PASSWORD", "s3cret")]);
        assert_eq!(
            expand("postgres://app:${DB_PASSWORD}@localhost/db", &lookup_in(&m)),
            "postgres://app:s3cret@localhost/db"
        );
    }

    #[test]
    fn bare_dollar_is_never_a_reference() {
        let m = map(&[("ss", "BOOM")]);
        assert_eq!(expand("p$ssw0rd", &lookup_in(&m)), "p$ssw0rd");
        assert_eq!(expand("$2b$12$abc", &lookup_in(&m)), "$2b$12$abc");
        assert!(!has_reference("p$ssw0rd"));
    }

    #[test]
    fn unknown_reference_is_left_literal_not_blanked() {
        let m = map(&[]);
        assert_eq!(expand("x=${MISSING}/y", &lookup_in(&m)), "x=${MISSING}/y");
    }

    #[test]
    fn default_value_applies_only_when_unset() {
        let set = map(&[("PORT", "4000")]);
        let unset = map(&[]);
        assert_eq!(expand("${PORT:-3000}", &lookup_in(&set)), "4000");
        assert_eq!(expand("${PORT:-3000}", &lookup_in(&unset)), "3000");
    }

    #[test]
    fn nested_references_resolve_and_cycles_terminate() {
        let m = map(&[("A", "${B}"), ("B", "${C}"), ("C", "leaf")]);
        assert_eq!(expand("${A}", &lookup_in(&m)), "leaf");
        let cyc = map(&[("A", "${B}"), ("B", "${A}")]);
        // Terminates; the innermost unresolved reference stays literal.
        let out = expand("${A}", &lookup_in(&cyc));
        assert!(
            out.starts_with("${"),
            "cycle must leave a literal reference, got {out}"
        );
    }

    #[test]
    fn escape_yields_literal_braces() {
        let m = map(&[("X", "no")]);
        assert_eq!(expand("$${X}", &lookup_in(&m)), "${X}");
        assert!(!has_reference("$${X}"));
        assert!(has_reference("a ${X} b"));
    }

    #[test]
    fn unterminated_reference_is_kept_verbatim() {
        let m = map(&[("X", "v")]);
        assert_eq!(expand("a ${X", &lookup_in(&m)), "a ${X");
    }
}
