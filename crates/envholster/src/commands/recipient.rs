//! `recipient {add,list}` (wrap matrix G-A: plan/02 §2).

use std::collections::BTreeMap;

use envholster_core::{
    CellId, Enrollment, EnvName, EnvSelector, RecipientClass, RecipientEntry, RecipientKind, Tier,
};

use crate::commands::{class_name, enrolled_max_tier, unlock_all_persisted};
use crate::context::{discover_project, open_vault, Session};
use crate::errors::{json_string, CliError};
use crate::ClassArg;

fn parse_tier(raw: u8) -> Result<Tier, CliError> {
    Tier::try_from_u8(raw).ok_or_else(|| {
        CliError::parse(
            format!("invalid tier {raw}: tiers are 1 (ambient), 2 (sensitive), 3 (critical)"),
            None,
        )
    })
}

/// Enrollment display (inverse-readable form of the header field).
pub fn enrollment_display(enrollment: &Enrollment) -> String {
    match &enrollment.0 {
        EnvSelector::All { max_tier } => format!("*:{}", max_tier.as_u8()),
        EnvSelector::Named(map) => map
            .iter()
            .map(|(env, tier)| format!("{}:{}", env.as_str(), tier.as_u8()))
            .collect::<Vec<_>>()
            .join(","),
    }
}

/// Cells the entry could be wrapped to (mirror of the core wrap matrix).
fn eligible(entry: &RecipientEntry, cell: &CellId) -> bool {
    match entry.class {
        RecipientClass::Recovery => true,
        RecipientClass::Hardware => {
            enrolled_max_tier(entry, &cell.env).is_some_and(|m| m >= cell.tier)
        }
        RecipientClass::Software => {
            cell.tier == Tier::Ambient
                && enrolled_max_tier(entry, &cell.env).is_some_and(|m| m >= cell.tier)
        }
    }
}

/// `recipient add <age1...> --label <l> [--env <e>]... [--max-tier N]
/// [--class software|hardware]`. Hardware is accepted only for the plugin
/// encodings (`age1yubikey1...`, `age1se1...`); an X25519 key is software
/// whatever the flag says, because the wrap matrix keys on the class.
pub fn add(
    session: &mut Session,
    encoded: &str,
    label: &str,
    class: &ClassArg,
    envs: &[String],
    max_tier: Option<u8>,
) -> Result<(), CliError> {
    let plugin_encoding = encoded.starts_with("age1yubikey1") || encoded.starts_with("age1se1");
    let class = match class {
        ClassArg::Hardware if plugin_encoding => RecipientClass::Hardware,
        ClassArg::Hardware => {
            return Err(CliError::parse(
                "--class hardware needs a hardware recipient encoding (age1yubikey1... or \
                 age1se1...)",
                Some(format!(
                    "envholster recipient add {encoded} --label {label}  # software"
                )),
            ))
        }
        ClassArg::Software => RecipientClass::Software,
    };
    let default_tier = match class {
        RecipientClass::Software => Tier::Ambient,
        RecipientClass::Hardware | RecipientClass::Recovery => Tier::Critical,
    };
    let tier = match max_tier {
        Some(raw) => parse_tier(raw)?,
        None => default_tier,
    };
    let enrollment = if envs.is_empty() {
        Enrollment(EnvSelector::All { max_tier: tier })
    } else {
        let mut map = BTreeMap::new();
        for env in envs {
            map.insert(EnvName::parse(env).map_err(CliError::from)?, tier);
        }
        Enrollment(EnvSelector::Named(map))
    };
    let entry = RecipientEntry::from_encoded(encoded, class, label.to_owned(), enrollment)
        .map_err(|e| {
            CliError::from(e).with_next(
                "pass a full age recipient encoding (age1..., age1yubikey1..., age1se1...) and a \
                 class matching its kind (x25519=software, plugin=hardware)",
            )
        })?;

    let project = discover_project()?;
    let mut vault = open_vault(&project)?;

    // Every save re-encrypts every persisted cell (AAD covers the header
    // core), so unlock them all through the session loop before core re-wraps.
    unlock_all_persisted(&mut vault, session)?;
    let reachable: Vec<CellId> = vault
        .cells()
        .into_iter()
        .map(|c| c.id)
        .filter(|id| eligible(&entry, id))
        .collect();
    let id = entry.id.as_str().to_owned();
    let display = enrollment_display(&entry.enrollment);
    vault
        .add_recipient(entry, &session.identities, &session.ui)
        .map_err(CliError::from)?;
    vault.save().map_err(CliError::from)?;

    println!(
        "enrolled recipient {id} ({}, {label}) enroll={display}; re-wrapped {} cell(s)",
        class_name(class),
        reachable.len()
    );
    if class == RecipientClass::Software {
        println!(
            "note: software recipients reach tier-1 cells only; tier >= 2 stays \
             hardware-only"
        );
    }
    println!("commit secrets.holster and secrets.holster.recovery.age to share the change");
    Ok(())
}

pub fn list(session: &mut Session, json: bool) -> Result<(), CliError> {
    let _ = session;
    let project = discover_project()?;
    let vault = open_vault(&project)?;
    if json {
        let mut out = String::from("{\"schema\":1,\"recipients\":[");
        for (i, entry) in vault.recipients().iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&json_row(entry));
        }
        out.push_str("]}");
        println!("{out}");
        return Ok(());
    }
    for entry in vault.recipients() {
        println!(
            "{}\t{}\t{}\t{}\tenroll={}\t{}",
            entry.id.as_str(),
            class_name(entry.class),
            kind_display(entry),
            entry.label,
            enrollment_display(&entry.enrollment),
            entry.encoded.as_deref().unwrap_or("-"),
        );
    }
    Ok(())
}

fn kind_display(entry: &RecipientEntry) -> String {
    match &entry.kind {
        RecipientKind::X25519 => "x25519".to_owned(),
        RecipientKind::Scrypt { log_n } => format!("scrypt:{log_n}"),
        RecipientKind::Plugin { name } => format!("plugin:{}", name.as_str()),
    }
}

fn json_row(entry: &RecipientEntry) -> String {
    let mut row = String::from("{\"id\":");
    row.push_str(&json_string(entry.id.as_str()));
    row.push_str(",\"class\":");
    row.push_str(&json_string(class_name(entry.class)));
    row.push_str(",\"kind\":");
    row.push_str(&json_string(&kind_display(entry)));
    row.push_str(",\"label\":");
    row.push_str(&json_string(&entry.label));
    row.push_str(",\"enrollment\":");
    row.push_str(&json_string(&enrollment_display(&entry.enrollment)));
    row.push_str(",\"recipient\":");
    match entry.encoded.as_deref() {
        Some(encoded) => row.push_str(&json_string(encoded)),
        None => row.push_str("null"),
    }
    row.push('}');
    row
}
