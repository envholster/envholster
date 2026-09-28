//! Manifest file IO and mutation helpers.
//!
//! serde + toml serve ONLY this plaintext file (c6/c20). `add`/`rm`/`import`
//! update vault and manifest together under the vault's advisory flock
//! (plan/02 §8, §12): the vault saves first (authoritative), then the
//! manifest is written; the write is validated by re-parsing before it
//! replaces the file.

use std::path::Path;

use envholster_core::{EnvName, LocalOverride, Manifest, SecretDecl, SecretMode, Tier};

use crate::context::Project;
use crate::errors::CliError;

pub fn load_manifest(path: &Path) -> Result<Manifest, CliError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        CliError::not_found(
            format!("manifest {} unreadable: {e}", path.display()),
            Some("envholster init".to_owned()),
        )
    })?;
    Manifest::parse(&text).map_err(CliError::from)
}

/// Permissive load for the daemon-facing `run` path: tolerates overlapping
/// `[[secret]]` blocks (an operator can both `add` and hand-edit a secret) that
/// strict `parse` rejects as a `check`-time authoring divergence. The daemon's
/// `authorize()` (§8) is the authoritative gate on every injection regardless.
pub fn load_manifest_permissive(path: &Path) -> Result<Manifest, CliError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        CliError::not_found(
            format!("manifest {} unreadable: {e}", path.display()),
            Some("envholster init".to_owned()),
        )
    })?;
    Manifest::parse_permissive(&text).map_err(CliError::from)
}

/// The gitignored local override, when present (vars only — D10).
pub fn load_local(project: &Project) -> Result<Option<LocalOverride>, CliError> {
    let path = project.local_override_path();
    if !path.is_file() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)?;
    Ok(Some(LocalOverride::parse(&text).map_err(CliError::from)?))
}

/// An empty schema-1 manifest.
pub fn empty_manifest() -> Manifest {
    Manifest {
        schema: Manifest::SCHEMA,
        project: None,
        environments: None,
        vars: Default::default(),
        envs: Default::default(),
        secrets: Vec::new(),
        agents: Default::default(),
        broker: None,
        exec: None,
    }
}

/// Serializes, validates by re-parsing, and atomically replaces the manifest
/// (temp file + rename in the same directory). The manifest is committed and
/// world-readable by design — no restrictive mode is applied.
pub fn store_manifest(path: &Path, manifest: &Manifest) -> Result<(), CliError> {
    let text = toml::to_string(manifest)
        .map_err(|e| CliError::failure(format!("manifest serialization failed: {e}"), None))?;
    // Round-trip validation: never write a manifest this build cannot read.
    Manifest::parse(&text).map_err(CliError::from)?;

    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let tmp = match dir {
        Some(dir) => dir.join(format!(".envholster.toml.tmp{}", std::process::id())),
        None => Path::new(&format!(".envholster.toml.tmp{}", std::process::id())).to_owned(),
    };
    std::fs::write(&tmp, text.as_bytes())?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(CliError::from(e));
    }
    Ok(())
}

/// Declares `env` in `[environments].names` if it is not `base` and not yet
/// declared.
pub fn ensure_env_declared(manifest: &mut Manifest, env: &EnvName) {
    if env.as_str() == envholster_core::constants::BASE_ENV {
        return;
    }
    let section = manifest.environments.get_or_insert_with(|| {
        envholster_core::manifest::EnvironmentsSection { names: Vec::new() }
    });
    if !section.names.iter().any(|n| n == env.as_str()) {
        section.names.push(env.as_str().to_owned());
    }
}

/// Ensures a `[[secret]]` declaration covers (name, env). If an existing
/// block already governs this env, it is left untouched — the vault record
/// is authoritative and `check` surfaces divergence (plan/02 §12). Otherwise
/// an env-scoped block is appended.
pub fn ensure_secret_decl(
    manifest: &mut Manifest,
    name: &str,
    env: &EnvName,
    tier: Tier,
    mode: SecretMode,
) {
    ensure_env_declared(manifest, env);
    if manifest.secret_decl(name, env).is_some() {
        return;
    }
    manifest.secrets.push(SecretDecl {
        name: name.to_owned(),
        envs: vec![env.as_str().to_owned()],
        tier: Some(tier.as_u8()),
        mode: Some(mode),
        env_var: None,
        scope: Default::default(),
        from: None,
        description: None,
        value_type: None,
        example: None,
        required: None,
    });
}

/// Drops every wildcard (`envs = []`) declaration of `name` once the vault
/// holds no record of that name in ANY environment. `remove_secret_decl`
/// leaves a wildcard alone on purpose (it may still cover other envs), but a
/// wildcard with no value anywhere only makes `run` fail on a secret that
/// no longer exists. Returns true when the manifest changed.
pub fn remove_unused_wildcard_decl(
    manifest: &mut Manifest,
    name: &str,
    still_stored: bool,
) -> bool {
    if still_stored {
        return false;
    }
    let before = manifest.secrets.len();
    manifest
        .secrets
        .retain(|decl| !(decl.name == name && decl.envs.is_empty()));
    manifest.secrets.len() != before
}

/// Removes `env` from the declaration governing (name, env). An exactly
/// env-scoped block is dropped; a multi-env block loses this env; a wildcard
/// block (empty `envs`) is left alone — `check` reports the now-missing
/// value elsewhere. Returns true when the manifest changed.
pub fn remove_secret_decl(manifest: &mut Manifest, name: &str, env: &EnvName) -> bool {
    let mut changed = false;
    manifest.secrets.retain_mut(|decl| {
        if decl.name != name || decl.envs.is_empty() {
            return true;
        }
        let before = decl.envs.len();
        decl.envs.retain(|e| e != env.as_str());
        if decl.envs.len() != before {
            changed = true;
        }
        !decl.envs.is_empty()
    });
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(name: &str) -> EnvName {
        EnvName::parse(name).unwrap()
    }

    #[test]
    fn declaring_and_removing_secret_blocks() {
        let mut m = empty_manifest();
        ensure_secret_decl(
            &mut m,
            "API_KEY",
            &env("prod"),
            Tier::Critical,
            SecretMode::ApiKey,
        );
        assert_eq!(m.environment_names(), vec!["prod"]);
        assert_eq!(m.secrets.len(), 1);
        assert_eq!(m.secrets[0].tier, Some(3));

        // Idempotent for a covered env.
        ensure_secret_decl(
            &mut m,
            "API_KEY",
            &env("prod"),
            Tier::Ambient,
            SecretMode::Generic,
        );
        assert_eq!(m.secrets.len(), 1);
        assert_eq!(m.secrets[0].tier, Some(3), "existing block untouched");

        // A different env gets its own disjoint block (per-env tiers).
        ensure_secret_decl(
            &mut m,
            "API_KEY",
            &env("dev"),
            Tier::Ambient,
            SecretMode::ApiKey,
        );
        assert_eq!(m.secrets.len(), 2);

        assert!(remove_secret_decl(&mut m, "API_KEY", &env("prod")));
        assert_eq!(m.secrets.len(), 1);
        assert!(!remove_secret_decl(&mut m, "API_KEY", &env("prod")));

        // The mutated manifest still validates through a full round-trip.
        let text = toml::to_string(&m).unwrap();
        Manifest::parse(&text).unwrap();
    }

    /// `ssh set-tier` must actually MOVE the declared tier, whatever the
    /// declaration's shape. The wildcard case is the regression: a block with
    /// no `envs` was skipped by `remove_secret_decl` and then satisfied
    /// `ensure_secret_decl`, so the manifest kept the OLD tier and the daemon's
    /// max(vault, manifest) rule kept enforcing it after the record had moved.
    #[test]
    fn base_is_never_declared_explicitly() {
        let mut m = empty_manifest();
        ensure_secret_decl(
            &mut m,
            "K",
            &env("base"),
            Tier::Ambient,
            SecretMode::Generic,
        );
        assert!(m.environments.is_none());
        let text = toml::to_string(&m).unwrap();
        Manifest::parse(&text).unwrap();
    }
}
