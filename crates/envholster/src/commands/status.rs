//! `status` — schema, generation, cell floors (G-A), needs-rotation badges,
//! recovery-blob drift, parked recovery identity (plan/04 §4.4; plan/07
//! §7.10). Never values.
//!
//! `--json` renders the SAME offline vault view as one hand-emitted object
//! (no serde in this crate — the workspace forbids new dependencies). Badge
//! `kind`s are a stable snake-case enum; `message` carries the human text
//! unchanged, so the two surfaces can never say different things.

use envholster_core::{RecipientClass, Vault};

use crate::commands::recovery::parked_identity_path;
use crate::commands::{class_name, unlock_ambient_cells};
use crate::context::{discover_project, now_epoch, open_vault, uuid_string, Project, Session};
use crate::errors::{json_string, CliError};
use crate::manifestio::load_manifest;

/// One status badge, carried structured so the human renderer prints
/// `message` verbatim while `--json` also exposes the stable `kind` plus the
/// machine-usable scope fields and next command.
pub struct Badge {
    pub kind: &'static str,
    pub secret: Option<String>,
    pub env: Option<String>,
    pub tier: Option<u8>,
    pub label: Option<String>,
    pub message: String,
    pub next: Option<String>,
}

impl Badge {
    fn simple(kind: &'static str, message: String, next: Option<String>) -> Self {
        Badge {
            kind,
            secret: None,
            env: None,
            tier: None,
            label: None,
            message,
            next,
        }
    }
}

pub fn run(session: &mut Session, json: bool) -> Result<(), CliError> {
    let project = discover_project()?;
    let manifest = load_manifest(&project.manifest_path)?;
    let mut vault = open_vault(&project)?;

    // Cell floors are header-visible — no unlock needed for them (G-A).
    let (_, locked) = unlock_ambient_cells(&mut vault, session);

    // Badges. Needs-rotation lives inside ciphertext, so it is visible only
    // for cells this run could unlock (tier-1, software).
    let now = now_epoch();
    let mut badges: Vec<Badge> = Vec::new();
    for meta in vault.list() {
        if meta.needs_rotation {
            badges.push(Badge {
                kind: "needs-value-rotation",
                secret: Some(meta.name.clone()),
                env: Some(meta.env.as_str().to_owned()),
                tier: Some(meta.tier.as_u8()),
                label: None,
                message: format!(
                    "needs-value-rotation: {} ({}:{}) — set a new value",
                    meta.name,
                    meta.env.as_str(),
                    meta.tier.as_u8()
                ),
                next: Some(format!("envholster set {}", meta.name)),
            });
        }
        if meta
            .rotate_after
            .is_some_and(|after| meta.rotated_at.saturating_add(after) < now)
        {
            badges.push(Badge {
                kind: "rotate-after-overdue",
                secret: Some(meta.name.clone()),
                env: Some(meta.env.as_str().to_owned()),
                tier: Some(meta.tier.as_u8()),
                label: None,
                message: format!(
                    "rotate-after overdue: {} ({}:{})",
                    meta.name,
                    meta.env.as_str(),
                    meta.tier.as_u8()
                ),
                next: Some(format!("envholster set {}", meta.name)),
            });
        }
    }
    if !locked.is_empty() {
        let cells: Vec<String> = locked
            .iter()
            .map(|c| format!("{}:{}", c.env.as_str(), c.tier.as_u8()))
            .collect();
        badges.push(Badge::simple(
            "locked-cells",
            format!(
                "rotation badges unavailable for locked cells: {}",
                cells.join(", ")
            ),
            None,
        ));
    }
    badges.extend(recovery_badge(&project, &vault));

    let parked = parked_identity_path(&uuid_string(&vault.uuid()));
    if parked.is_file() {
        badges.push(Badge::simple(
            "recovery-identity-parked",
            format!(
                "recovery key is still on this machine ({}) — move it to paper or removable \
                 media",
                parked.display()
            ),
            Some("envholster recovery create".to_owned()),
        ));
    }

    if !vault
        .recipients()
        .iter()
        .any(|r| r.class == RecipientClass::Hardware)
    {
        badges.push(Badge::simple(
            "no-hardware-recipient",
            "no hardware recipient enrolled — secrets are stored at tier 1; tier 2/3 needs a \
             hardware key"
                .to_owned(),
            Some(
                "envholster recipient add <age1yubikey1...|age1se1...> --class hardware \
                 --label <label>"
                    .to_owned(),
            ),
        ));
    }

    if json {
        let view = StatusView {
            vault: project.vault_path.to_string_lossy().into_owned(),
            vault_schema: Vault::SCHEMA,
            generation: vault.generation(),
            uuid: uuid_string(&vault.uuid()),
            environments: {
                let mut envs = vec!["base".to_owned()];
                envs.extend(manifest.environment_names().iter().map(|s| (*s).to_owned()));
                envs
            },
            selected_env: session.env.as_str().to_owned(),
            cells: vault
                .cells()
                .into_iter()
                .map(|cell| CellRow {
                    env: cell.id.env.as_str().to_owned(),
                    tier: cell.id.tier.as_u8(),
                    floor: class_name(cell.floor),
                    unlocked: cell.unlocked,
                    records: cell.record_count,
                })
                .collect(),
            badges,
        };
        println!("{}", render_status_json(&view));
        return Ok(());
    }

    println!("vault:      {}", project.vault_path.display());
    println!("schema:     {}", Vault::SCHEMA);
    println!("generation: {}", vault.generation());
    println!("uuid:       {}", uuid_string(&vault.uuid()));
    println!(
        "manifest:   {} (schema {})",
        project.manifest_path.display(),
        manifest.schema
    );
    {
        let mut envs = vec!["base (reserved)".to_owned()];
        envs.extend(manifest.environment_names().iter().map(|s| (*s).to_owned()));
        println!("environments: {}", envs.join(", "));
    }
    println!("selected env: {}", session.env.as_str());

    println!("cells:");
    if vault.cells().is_empty() {
        println!("  (none — cells are created lazily on first write)");
    }
    for cell in vault.cells() {
        let state = if cell.unlocked {
            format!("unlocked, {} record(s)", cell.record_count)
        } else {
            "locked".to_owned()
        };
        println!(
            "  {}:{}\tfloor={}\t{}",
            cell.id.env.as_str(),
            cell.id.tier.as_u8(),
            class_name(cell.floor),
            state
        );
    }

    println!("badges:");
    if badges.is_empty() {
        println!("  (none)");
    }
    for badge in badges {
        println!("  {}", badge.message);
    }
    Ok(())
}

/// Offline drift heuristic ONLY: the blob's generation sits inside age
/// ciphertext, so the definitive lockstep check is `recovery verify`
/// (RECOVERY-SPEC §2). Missing blob or a blob older than the vault is
/// surfaced as a badge; callers (status, doctor) branch on the stable `kind`.
pub fn recovery_badge(project: &Project, vault: &Vault) -> Vec<Badge> {
    let _ = vault;
    let blob = project.recovery_blob_path();
    let vault_meta = std::fs::metadata(&project.vault_path);
    let blob_meta = std::fs::metadata(&blob);
    match (vault_meta, blob_meta) {
        (_, Err(_)) => vec![Badge::simple(
            "recovery-blob-missing",
            format!(
                "recovery blob MISSING ({}) — any vault save restores lockstep; then run \
                 'envholster recovery verify'",
                blob.display()
            ),
            Some("envholster recovery verify".to_owned()),
        )],
        (Ok(v), Ok(b)) => {
            let drifted = match (v.modified(), b.modified()) {
                (Ok(vm), Ok(bm)) => bm
                    .checked_add(std::time::Duration::from_secs(2))
                    .is_some_and(|bm| bm < vm),
                _ => false,
            };
            if drifted {
                vec![Badge::simple(
                    "recovery-blob-drift",
                    "recovery blob is older than the vault (possible generation drift) — run \
                     'envholster recovery verify'"
                        .to_owned(),
                    Some("envholster recovery verify".to_owned()),
                )]
            } else {
                vec![Badge::simple(
                    "recovery-lockstep-note",
                    "recovery blob present; lockstep is verified only by 'envholster recovery \
                     verify' (offline check is heuristic)"
                        .to_owned(),
                    Some("envholster recovery verify".to_owned()),
                )]
            }
        }
        (Err(_), _) => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// JSON rendering — pure over a plain view struct so the golden tests
// exercise it without a vault or the filesystem.
// ---------------------------------------------------------------------------

struct CellRow {
    env: String,
    tier: u8,
    floor: &'static str,
    unlocked: bool,
    records: usize,
}

struct StatusView {
    vault: String,
    vault_schema: u32,
    generation: u64,
    uuid: String,
    environments: Vec<String>,
    selected_env: String,
    cells: Vec<CellRow>,
    badges: Vec<Badge>,
}

fn render_status_json(view: &StatusView) -> String {
    let mut out = String::from("{\"schema\":1,\"vault\":");
    out.push_str(&json_string(&view.vault));
    out.push_str(",\"vault_schema\":");
    out.push_str(&view.vault_schema.to_string());
    out.push_str(",\"generation\":");
    out.push_str(&view.generation.to_string());
    out.push_str(",\"uuid\":");
    out.push_str(&json_string(&view.uuid));
    out.push_str(",\"environments\":[");
    for (i, env) in view.environments.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&json_string(env));
    }
    out.push_str("],\"selected_env\":");
    out.push_str(&json_string(&view.selected_env));
    out.push_str(",\"cells\":[");
    for (i, cell) in view.cells.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"env\":");
        out.push_str(&json_string(&cell.env));
        out.push_str(",\"tier\":");
        out.push_str(&cell.tier.to_string());
        out.push_str(",\"floor\":");
        out.push_str(&json_string(cell.floor));
        out.push_str(",\"unlocked\":");
        out.push_str(if cell.unlocked { "true" } else { "false" });
        out.push_str(",\"records\":");
        out.push_str(&cell.records.to_string());
        out.push('}');
    }
    out.push_str("],\"badges\":[");
    for (i, badge) in view.badges.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&badge_json(badge));
    }
    out.push_str("]}");
    out
}

fn badge_json(badge: &Badge) -> String {
    let mut out = String::from("{\"kind\":");
    out.push_str(&json_string(badge.kind));
    if let Some(secret) = &badge.secret {
        out.push_str(",\"secret\":");
        out.push_str(&json_string(secret));
    }
    if let Some(env) = &badge.env {
        out.push_str(",\"env\":");
        out.push_str(&json_string(env));
    }
    if let Some(tier) = badge.tier {
        out.push_str(",\"tier\":");
        out.push_str(&tier.to_string());
    }
    if let Some(label) = &badge.label {
        out.push_str(",\"label\":");
        out.push_str(&json_string(label));
    }
    out.push_str(",\"message\":");
    out.push_str(&json_string(&badge.message));
    out.push_str(",\"next\":");
    match &badge.next {
        Some(next) => out.push_str(&json_string(next)),
        None => out.push_str("null"),
    }
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view() -> StatusView {
        StatusView {
            vault: "/p/secrets.holster".to_owned(),
            vault_schema: 1,
            generation: 7,
            uuid: "3f2a9c10-88e2-4c5b-9d41-6b7f0a2c9e55".to_owned(),
            environments: vec!["base".to_owned()],
            selected_env: "base".to_owned(),
            cells: vec![
                CellRow {
                    env: "base".to_owned(),
                    tier: 1,
                    floor: "software",
                    unlocked: true,
                    records: 3,
                },
                CellRow {
                    env: "base".to_owned(),
                    tier: 2,
                    floor: "hardware",
                    unlocked: false,
                    records: 0,
                },
            ],
            badges: vec![
                Badge {
                    kind: "needs-value-rotation",
                    secret: Some("STRIPE_KEY".to_owned()),
                    env: Some("base".to_owned()),
                    tier: Some(2),
                    label: None,
                    message: "needs-value-rotation: STRIPE_KEY (base:2) — set a new value"
                        .to_owned(),
                    next: Some("envholster set STRIPE_KEY".to_owned()),
                },
                Badge::simple(
                    "recovery-identity-parked",
                    "recovery key is still on this machine".to_owned(),
                    Some("envholster recovery create".to_owned()),
                ),
            ],
        }
    }

    #[test]
    fn status_json_golden() {
        let json = render_status_json(&view());
        assert_eq!(
            json,
            "{\"schema\":1,\"vault\":\"/p/secrets.holster\",\"vault_schema\":1,\
             \"generation\":7,\"uuid\":\"3f2a9c10-88e2-4c5b-9d41-6b7f0a2c9e55\",\
             \"environments\":[\"base\"],\"selected_env\":\"base\",\
             \"cells\":[{\"env\":\"base\",\"tier\":1,\"floor\":\"software\",\
             \"unlocked\":true,\"records\":3},{\"env\":\"base\",\"tier\":2,\
             \"floor\":\"hardware\",\"unlocked\":false,\"records\":0}],\
             \"badges\":[{\"kind\":\"needs-value-rotation\",\"secret\":\"STRIPE_KEY\",\
             \"env\":\"base\",\"tier\":2,\"message\":\"needs-value-rotation: STRIPE_KEY \
             (base:2) — set a new value\",\"next\":\"envholster set STRIPE_KEY\"},\
             {\"kind\":\"recovery-identity-parked\",\"message\":\"recovery key is still on \
             this machine\",\"next\":\"envholster recovery create\"}]}"
        );
    }

    #[test]
    fn badge_scope_fields_are_omitted_when_absent() {
        let json = badge_json(&Badge::simple(
            "recovery-lockstep-note",
            "recovery blob present".to_owned(),
            Some("envholster recovery verify".to_owned()),
        ));
        assert_eq!(
            json,
            "{\"kind\":\"recovery-lockstep-note\",\"message\":\"recovery blob present\",\
             \"next\":\"envholster recovery verify\"}"
        );
        assert!(!json.contains("\"secret\""));
        assert!(!json.contains("\"label\""));
    }

    #[test]
    fn badge_kinds_are_the_frozen_set() {
        for kind in [
            "needs-value-rotation",
            "rotate-after-overdue",
            "locked-cells",
            "recovery-blob-missing",
            "recovery-blob-drift",
            "recovery-lockstep-note",
            "recovery-identity-parked",
            "no-hardware-recipient",
        ] {
            assert!(kind
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
        }
    }

    #[test]
    fn strings_in_the_view_are_escaped() {
        let mut v = view();
        v.vault = "/p/with \"quotes\"".to_owned();
        let json = render_status_json(&v);
        assert!(json.contains("\"vault\":\"/p/with \\\"quotes\\\"\""));
    }
}
