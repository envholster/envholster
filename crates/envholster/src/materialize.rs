//! `${secret:NAME}` composite materialization, shared by `run` and `export`.
//!
//! The manifest resolver leaves a var that references a declared secret as a
//! `VarValue::Composite` whose template carries `${secret:NAME}` in canonical
//! form (`envholster_core::manifest::resolve_vars`). Materializing it means
//! pasting the secret's value in — the same disclosure as delivering the
//! secret itself, which is why both delivery doors share this one function
//! and neither `get` nor `list` ever calls it.

use crate::errors::CliError;

/// Replace every `${secret:NAME}` in `template` with the value `lookup`
/// returns for NAME. A reference to a secret that has no value in scope is
/// an error naming the secret, never a silent blank: a database URL with an
/// empty password is the kind of misconfiguration that fails far from its
/// cause.
pub fn materialize(
    template: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<String, CliError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("${secret:") {
        out.push_str(&rest[..start]);
        let after = &rest[start + "${secret:".len()..];
        let end = after.find('}').ok_or_else(|| {
            CliError::parse(
                "malformed composite template (unclosed ${secret:...})",
                None,
            )
        })?;
        let name = &after[..end];
        let value = lookup(name).ok_or_else(|| {
            CliError::not_found(
                format!(
                    "composite references secret {name:?}, which has no value in this \
                     environment (or base)"
                ),
                Some(format!("envholster set {name}")),
            )
        })?;
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_each_reference_and_keeps_the_rest() {
        let lookup = |n: &str| (n == "PW").then(|| "hunter2".to_owned());
        assert_eq!(
            materialize("postgres://app:${secret:PW}@db/app", &lookup).unwrap(),
            "postgres://app:hunter2@db/app"
        );
        assert_eq!(materialize("plain", &lookup).unwrap(), "plain");
    }

    #[test]
    fn missing_secret_is_an_error_not_a_blank() {
        let none = |_: &str| None;
        let err = materialize("x=${secret:NOPE}", &none).unwrap_err();
        assert!(err.message.contains("NOPE"));
        assert!(materialize("${secret:UNCLOSED", &none).is_err());
    }
}
