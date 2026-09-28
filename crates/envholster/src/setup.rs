//! Optional launch instructions. This module never opens identities or vaults.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use clap::{Args, Subcommand, ValueEnum};
use envholster_core::EnvName;

use crate::context::discover_project;
use crate::errors::{CliError, EXIT_FINDINGS, EXIT_OK};

const SKILL: &str = include_str!("../../../integrations/skills/envholster/SKILL.md");
const RULE: &str = include_str!("../../../integrations/agent-rule.md");
const NPM_SETUP: &str = include_str!("../../../integrations/npm-setup.cjs");
const BEGIN: &str = "\n\n<!-- envholster:launch:v1 -->\n";
const END: &str = "<!-- /envholster:launch:v1 -->\n";
const LIMIT: u64 = 1024 * 1024;

#[derive(Subcommand)]
pub enum SetupCommand {
    /// Install global guidance for detected apps, or select apps with --app.
    Agents {
        #[arg(long, value_enum, value_delimiter = ',')]
        app: Vec<Agent>,
        #[command(flatten)]
        mode: Mode,
    },
    /// Record an explicit local launch environment in this project's instructions.
    Project {
        /// Wrap one npm script with /bin/sh; pre/post hooks stay separate (repeatable).
        #[arg(long)]
        npm_script: Vec<String>,
        #[command(flatten)]
        mode: Mode,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Agent {
    Codex,
    Claude,
    Cursor,
}

impl Agent {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Cursor => "cursor",
        }
    }
}

#[derive(Default, Args)]
pub struct Mode {
    /// Verify installed files without changing anything; exit 7 for missing files.
    #[arg(long, conflicts_with = "remove")]
    check: bool,
    /// Remove only unchanged Envholster instructions and restore wrapped scripts.
    #[arg(long)]
    remove: bool,
}

pub(crate) fn check_project(environment: &str, scripts: &[String]) -> Result<(), CliError> {
    if project(
        Some(environment),
        scripts,
        &Mode {
            check: true,
            remove: false,
        },
    )? != EXIT_OK
    {
        return Err(problem("Launch setup changed. Review `envholster setup project --check` before cleanup; originals were kept."));
    }
    Ok(())
}

pub fn run(
    action: Option<&SetupCommand>,
    environment: Option<&str>,
    options: &crate::onboarding::Options,
    identity: &Option<PathBuf>,
) -> Result<i32, CliError> {
    match action {
        Some(SetupCommand::Agents { app, mode }) => agents(app, mode),
        Some(SetupCommand::Project { npm_script, mode }) => project(environment, npm_script, mode),
        None => crate::onboarding::run(options, identity),
    }
}

fn problem(message: impl Into<String>) -> CliError {
    CliError::failure(message, Some("envholster setup --help".into()))
}

pub(crate) struct AgentPaths {
    user: PathBuf,
    codex: PathBuf,
    claude: PathBuf,
}

impl AgentPaths {
    pub(crate) fn new() -> Result<Self, CliError> {
        let user = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or_else(|| problem("HOME must name an existing absolute directory"))?;
        let user = fs::canonicalize(user)?;
        let config = |var: &str, fallback: &str| -> Result<PathBuf, CliError> {
            let path = std::env::var_os(var)
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| user.join(fallback));
            if !path.is_absolute() {
                return Err(problem(format!("{var} must be an absolute directory")));
            }
            Ok(path)
        };
        Ok(Self {
            codex: config("CODEX_HOME", ".codex")?,
            claude: config("CLAUDE_CONFIG_DIR", ".claude")?,
            user,
        })
    }

    pub(crate) fn detected(&self) -> Vec<Agent> {
        [
            (
                Agent::Codex,
                self.codex.is_dir() || program("codex").is_some(),
            ),
            (
                Agent::Claude,
                self.claude.is_dir() || program("claude").is_some(),
            ),
            (
                Agent::Cursor,
                self.user.join(".cursor").is_dir()
                    || self
                        .user
                        .join(".agents/skills/envholster/.envholster-cursor")
                        .is_file()
                    || program("cursor").is_some()
                    || program("cursor-agent").is_some(),
            ),
        ]
        .into_iter()
        .filter_map(|(app, found)| found.then_some(app))
        .collect()
    }
}

pub(crate) fn agents(requested: &[Agent], mode: &Mode) -> Result<i32, CliError> {
    let paths = AgentPaths::new()?;
    let selected = if requested.is_empty() {
        paths.detected()
    } else {
        requested.to_vec()
    };
    if selected.is_empty() {
        println!("No supported apps detected. Select one with `envholster setup agents --app codex,claude,cursor`.");
        return Ok(if mode.check { EXIT_FINDINGS } else { EXIT_OK });
    }
    let mut edits = Vec::new();
    if selected.contains(&Agent::Codex) || selected.contains(&Agent::Cursor) {
        let skill_dir = paths.user.join(".agents/skills/envholster");
        let mut keep_shared = false;
        for app in [Agent::Codex, Agent::Cursor] {
            let marker = skill_dir.join(format!(".envholster-{}", app.name()));
            if selected.contains(&app) {
                edits.push(owned(marker, "envholster setup v1\n", mode.remove)?);
            } else if read_optional(&marker)?.is_some() {
                keep_shared = true;
            }
        }
        // Removing one adapter must not remove the other app's shared skill.
        if !mode.remove || !keep_shared {
            edits.push(owned(skill_dir.join("SKILL.md"), SKILL, mode.remove)?);
        }
    }
    if selected.contains(&Agent::Codex) {
        let regular = paths.codex.join("AGENTS.md");
        let over = paths.codex.join("AGENTS.override.md");
        let override_active = read_optional(&over)?.is_some_and(|s| !s.trim().is_empty());
        // Codex loads only the first nonempty global instruction file.
        edits.push(block(
            if override_active {
                over.clone()
            } else {
                regular.clone()
            },
            RULE,
            mode.remove,
        )?);
        let inactive = if override_active { regular } else { over };
        if read_optional(&inactive)?.is_some_and(|s| s.contains(BEGIN)) {
            edits.push(block(inactive, RULE, true)?);
        }
    }
    if selected.contains(&Agent::Claude) {
        edits.push(owned(
            paths.claude.join("skills/envholster/SKILL.md"),
            SKILL,
            mode.remove,
        )?);
        edits.push(owned(
            paths.claude.join("rules/envholster.md"),
            RULE,
            mode.remove,
        )?);
    }
    let result = apply(edits, mode)?;
    if result == EXIT_OK && !mode.remove {
        println!("Restart agent sessions to load guidance. Verification checks files, not model compliance.");
        if selected.contains(&Agent::Cursor) {
            println!(
                "Cursor uses the global skill. Project setup adds an always-applied Cursor rule."
            );
        }
    }
    Ok(result)
}

pub(crate) fn project(
    environment: Option<&str>,
    scripts: &[String],
    mode: &Mode,
) -> Result<i32, CliError> {
    if mode.remove && !scripts.is_empty() {
        return Err(problem(
            "--npm-script cannot be used when removing project setup",
        ));
    }
    let project = discover_project()?;
    if !project.vault_path.is_file() && !mode.remove {
        return Err(problem(
            "This project has a manifest but no secrets.holster. Complete init/import first.",
        ));
    }
    let regular = project.root.join("AGENTS.md");
    let over = project.root.join("AGENTS.override.md");
    let override_active = read_optional(&over)?.is_some_and(|s| !s.trim().is_empty());
    let instructions = if override_active {
        over.clone()
    } else {
        regular.clone()
    };
    let current = read_optional(&instructions)?.unwrap_or_default();
    let claude = read_optional(&project.root.join("CLAUDE.md"))?.unwrap_or_default();
    let cursor_path = project.root.join(".cursor/rules/envholster.mdc");
    let cursor_current = read_optional(&cursor_path)?.unwrap_or_default();
    let saved_body = section(&current)?
        .or(section(&claude)?)
        .or_else(|| cursor_current.strip_prefix("---\nalwaysApply: true\n---\n\n"));
    let saved = saved_body.and_then(saved_environment);
    let previous_scripts: Vec<String> = saved_body
        .and_then(|body| {
            body.lines().find_map(|line| {
                line.strip_prefix("Wrapped npm scripts: [")
                    .and_then(|s| s.strip_suffix(']'))
            })
        })
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let selected_scripts: Vec<String> = previous_scripts
        .iter()
        .chain(scripts.iter())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if selected_scripts.iter().any(|s| {
        s.is_empty()
            || s.len() > 64
            || !s.as_bytes()[0].is_ascii_alphanumeric()
            || !s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":_-".contains(&b))
    }) {
        return Err(problem("npm script names must start with a letter or digit and contain only letters, digits, colon, underscore or hyphen, up to 64 characters"));
    }
    let chosen = environment.or(saved);
    if chosen.is_none() && mode.check {
        println!("NEEDS SETUP: project launch instructions are missing. Choose an explicit --env.");
        return Ok(EXIT_FINDINGS);
    }
    let chosen = chosen.or(mode.remove.then_some("base"));
    let chosen = chosen.ok_or_else(|| problem("Choose an explicit launch environment with `envholster setup project --env <environment>`. ENVHOLSTER_ENV is not used for setup."))?;
    EnvName::parse(chosen).map_err(CliError::from)?;
    if !mode.remove {
        let manifest = crate::manifestio::load_manifest(&project.manifest_path)?;
        if chosen != "base" && !manifest.environment_names().contains(&chosen) {
            return Err(problem("The launch environment is not declared in envholster.toml. Choose base or a declared environment."));
        }
    }
    let previous_body = project_rule(chosen, &previous_scripts);
    let body = project_rule(chosen, &selected_scripts);
    let cursor = format!("---\nalwaysApply: true\n---\n\n{body}");
    let previous_cursor = format!("---\nalwaysApply: true\n---\n\n{previous_body}");
    let mut edits = vec![
        block(instructions, &previous_body, mode.remove)?,
        block(project.root.join("CLAUDE.md"), &previous_body, mode.remove)?,
        owned(cursor_path, &previous_cursor, mode.remove)?,
    ];
    if !mode.remove {
        for edit in &mut edits[..2] {
            edit.after = edit.after.take().map(|s| {
                s.replacen(
                    &format!("{BEGIN}{previous_body}{END}"),
                    &format!("{BEGIN}{body}{END}"),
                    1,
                )
            });
        }
        edits[2].after = Some(cursor);
    }
    let inactive = if override_active { regular } else { over };
    if read_optional(&inactive)?.is_some_and(|s| s.contains(BEGIN)) {
        edits.push(block(inactive, &previous_body, true)?);
    }
    let package = project.root.join("package.json");
    let before = read_optional(&package)?;
    if !selected_scripts.is_empty()
        || before
            .as_ref()
            .is_some_and(|s| s.contains("\"envholsterSetup\""))
    {
        let original = before.as_deref().ok_or_else(|| problem("No package.json exists at the vault root. Configure a monorepo package manually using the launch instructions."))?;
        let action = if mode.remove {
            "remove"
        } else if mode.check {
            "check"
        } else {
            "install"
        };
        let after = npm_transform(original, action, chosen, &selected_scripts)?;
        edits.push(Edit {
            path: package,
            before,
            after: Some(after),
        });
    }
    let result = apply(edits, mode)?;
    if result == EXIT_OK && !mode.remove && !mode.check {
        println!("Project launch guidance configured. Commit the instruction files and any package.json changes.");
        if !scripts.is_empty() {
            println!("Selected npm scripts now use Envholster. Their pre/post hooks are unchanged; configure those separately if they need credentials. The wrapper uses /bin/sh.");
        }
    }
    Ok(result)
}

fn project_rule(environment: &str, scripts: &[String]) -> String {
    format!("# Envholster local launches\n\nLaunch environment: `{environment}`\nWrapped npm scripts: [{}]\n\nFor local app processes that need credentials, use\n`envholster --env {environment} run -- <original-command-and-arguments>`.\nInspect the package script first. If it already starts with `envholster`, run\nthe ordinary package command without another wrapper. Preserve the working\ndirectory and arguments. Review the environment separately for deployment,\nbuild, test, or migration tasks.\n\n{RULE}", scripts.join(","))
}

fn saved_environment(body: &str) -> Option<&str> {
    body.lines().find_map(|line| {
        line.strip_prefix("Launch environment: `")
            .and_then(|s| s.strip_suffix('`'))
    })
}

fn npm_transform(
    original: &str,
    action: &str,
    environment: &str,
    scripts: &[String],
) -> Result<String, CliError> {
    let node = program("node").ok_or_else(|| problem("Node.js is needed only for optional package.json setup. Install Node or configure the script manually."))?;
    let mut child = Command::new(node)
        .env_clear()
        .args(["-e", NPM_SETUP, "--", action, environment])
        .args(scripts)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    // Read output concurrently so a large package file cannot fill both pipes.
    let mut input = child
        .stdin
        .take()
        .ok_or_else(|| problem("Package setup stdin is unavailable"))?;
    let source = original.to_owned();
    let writer = std::thread::spawn(move || input.write_all(source.as_bytes()));
    let output = child.wait_with_output()?;
    writer
        .join()
        .map_err(|_| problem("Package setup input failed"))??;
    if !output.status.success() {
        return Err(problem("Package setup conflicts with the current scripts or metadata. Review package.json; existing wrappers and modified managed scripts are left untouched."));
    }
    String::from_utf8(output.stdout).map_err(|_| problem("Package setup returned invalid text"))
}

pub(crate) fn program(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?).find_map(|dir| {
        let path = dir.join(name);
        let meta = fs::metadata(&path).ok()?;
        (meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            .then(|| fs::canonicalize(path).ok())
            .flatten()
    })
}

struct Edit {
    path: PathBuf,
    before: Option<String>,
    after: Option<String>,
}

pub(crate) fn safe_path(path: &Path) -> Result<(), CliError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(problem(format!(
                    "Refusing symlink at {}. Configure this integration manually.",
                    ancestor.display()
                )))
            }
            Ok(meta) if ancestor != path && !meta.is_dir() => {
                return Err(problem("An integration parent is not a directory"))
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub(crate) fn store_state(path: &Path, text: &str) -> Result<(), CliError> {
    let before = read_optional(path)?;
    replace(&Edit {
        path: path.to_owned(),
        before,
        after: Some(text.to_owned()),
    })
}

pub(crate) fn diagnose() -> Vec<String> {
    let mut findings = Vec::new();
    if let Ok(project) = discover_project() {
        let configured = ["AGENTS.md", "AGENTS.override.md", "CLAUDE.md"]
            .iter()
            .any(|name| {
                read_optional(&project.root.join(name))
                    .ok()
                    .flatten()
                    .is_some_and(|s| s.contains(BEGIN))
            })
            || project.root.join(".cursor/rules/envholster.mdc").exists();
        if configured {
            match self::project(None, &[], &Mode { check: true, remove: false }) {
                Ok(EXIT_OK) => {},
                _ => findings.push("Launch instructions or package scripts need attention; run envholster setup project --check".into()),
            }
        }
    }
    if let Ok(paths) = AgentPaths::new() {
        let mut installed = Vec::new();
        for app in [Agent::Codex, Agent::Cursor] {
            if paths
                .user
                .join(format!(
                    ".agents/skills/envholster/.envholster-{}",
                    app.name()
                ))
                .exists()
            {
                installed.push(app);
            }
        }
        if paths.claude.join("rules/envholster.md").exists() {
            installed.push(Agent::Claude);
        }
        if !installed.is_empty()
            && !matches!(
                agents(
                    &installed,
                    &Mode {
                        check: true,
                        remove: false
                    }
                ),
                Ok(EXIT_OK)
            )
        {
            findings.push(
                "Installed agent guidance needs attention; run envholster setup agents --check"
                    .into(),
            );
        }
    }
    findings
}

pub(crate) fn read_optional(path: &Path) -> Result<Option<String>, CliError> {
    safe_path(path)?;
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if !meta.is_file() || meta.nlink() != 1 || meta.len() > LIMIT {
        return Err(problem(format!(
            "Expected a regular, unshared instruction file under 1 MiB at {}",
            path.display()
        )));
    }
    let mut text = String::new();
    fs::File::open(path)?
        .take(LIMIT + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > LIMIT {
        return Err(problem("Instruction file exceeds 1 MiB"));
    }
    Ok(Some(text))
}

fn section(text: &str) -> Result<Option<&str>, CliError> {
    if !text.contains("envholster:launch:v1") {
        return Ok(None);
    }
    if text.matches(BEGIN).count() != 1 || text.matches(END).count() != 1 {
        return Err(problem("An Envholster instruction block has been edited or duplicated. Review it before rerunning setup."));
    }
    let (_, rest) = text
        .split_once(BEGIN)
        .ok_or_else(|| problem("Invalid instruction block"))?;
    let (body, _) = rest
        .split_once(END)
        .ok_or_else(|| problem("Invalid instruction block"))?;
    Ok(Some(body))
}

fn owned(path: PathBuf, expected: &str, remove: bool) -> Result<Edit, CliError> {
    let before = read_optional(&path)?;
    if before.as_ref().is_some_and(|s| s != expected) {
        return Err(problem(format!("Existing file differs from the bundled integration: {}. Review it manually; setup will not overwrite it.", path.display())));
    }
    Ok(Edit {
        path,
        before,
        after: (!remove).then(|| expected.to_owned()),
    })
}

fn block(path: PathBuf, body: &str, remove: bool) -> Result<Edit, CliError> {
    let before = read_optional(&path)?;
    let text = before.as_deref().unwrap_or_default();
    let managed = format!("{BEGIN}{body}{END}");
    let after = match section(text)? {
        Some(existing) if existing != body => {
            return Err(problem(format!(
                "Managed instructions have changed in {}. Review them before setup or removal.",
                path.display()
            )))
        }
        Some(_) if remove => text.replacen(&managed, "", 1),
        Some(_) => text.to_owned(),
        None if remove => text.to_owned(),
        None => format!("{text}{managed}"),
    };
    let after = if remove && after.is_empty() {
        None
    } else {
        Some(after)
    };
    Ok(Edit {
        path,
        before,
        after,
    })
}

fn apply(edits: Vec<Edit>, mode: &Mode) -> Result<i32, CliError> {
    if edits
        .iter()
        .any(|edit| edit.after.as_ref().is_some_and(|s| s.len() as u64 > LIMIT))
    {
        return Err(problem(
            "An integration file would exceed 1 MiB; configure it manually",
        ));
    }
    let mut missing = false;
    let mut applied: Vec<&Edit> = Vec::new();
    for edit in &edits {
        if edit.before == edit.after {
            println!("OK {}", edit.path.display());
        } else if mode.check {
            println!("NEEDS SETUP {}", edit.path.display());
            missing = true;
        } else {
            if let Err(error) = replace(edit) {
                let mut rollback_failed = false;
                for previous in applied.into_iter().rev() {
                    rollback_failed |= replace(&Edit {
                        path: previous.path.clone(),
                        before: previous.after.clone(),
                        after: previous.before.clone(),
                    })
                    .is_err();
                }
                if rollback_failed {
                    return Err(problem("Setup failed and could not restore every changed file. Review the listed paths and run setup --check for the selected scope."));
                }
                return Err(error);
            }
            applied.push(edit);
            println!(
                "{} {}",
                if mode.remove {
                    "Removed integration from"
                } else {
                    "Configured"
                },
                edit.path.display()
            );
        }
    }
    Ok(if missing { EXIT_FINDINGS } else { EXIT_OK })
}

fn replace(edit: &Edit) -> Result<(), CliError> {
    if read_optional(&edit.path)? != edit.before {
        return Err(problem(
            "An instruction file changed during setup. Rerun setup after reviewing the file.",
        ));
    }
    let Some(after) = &edit.after else {
        if edit.before.is_some() {
            fs::remove_file(&edit.path)?;
        }
        return Ok(());
    };
    let parent = edit
        .path
        .parent()
        .ok_or_else(|| problem("Missing instruction parent"))?;
    fs::create_dir_all(parent)?;
    safe_path(&edit.path)?;
    let temp = parent.join(format!(".envholster-setup-{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    let result = (|| -> Result<(), CliError> {
        file.write_all(after.as_bytes())?;
        if edit.before.is_some() {
            file.set_permissions(fs::metadata(&edit.path)?.permissions())?;
        }
        file.sync_all()?;
        if read_optional(&edit.path)? != edit.before {
            return Err(problem("An instruction file changed during setup"));
        }
        if edit.before.is_none() {
            // A new target must not replace a file created since preflight.
            fs::hard_link(&temp, &edit.path)?;
        } else {
            fs::rename(&temp, &edit.path)?;
        }
        Ok(())
    })();
    let _ = fs::remove_file(temp);
    result
}
