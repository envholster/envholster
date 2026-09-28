//! Project discovery and resumable onboarding. Journals contain names and keyed
//! fingerprints only; they are never a substitute for live vault/recovery proofs.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::commands::{importcmd, init, recovery};
use crate::context::{config_dir, create_secret_dir, discover_project, Session};
use crate::errors::{CliError, EXIT_FINDINGS, EXIT_OK};
use crate::setup::{self, Agent, Mode};
use crate::setup_ui as ui;
use clap::Args;
use envholster_core::{sha256_hex_lower, EnvName};

const INSPECT: &str = include_str!("../../../integrations/project-inspect.cjs");
const STATE_HEADER: &str = "# Envholster onboarding state. Contains no secret values.\n";

#[derive(Args, Default)]
pub struct Options {
    /// Folder containing your projects. Omit to browse for one.
    #[arg(long)]
    pub root: Option<PathBuf>,
    /// Select a project explicitly (repeatable); relative paths start at --root.
    #[arg(long = "project", conflicts_with = "all")]
    project_dir: Vec<PathBuf>,
    /// Select every discovered project under the explicit --root.
    #[arg(long, requires = "root")]
    all: bool,
    /// Review detection and proposed changes without initializing projects.
    #[arg(long)]
    plan: bool,
    /// Accept the displayed plan without prompting; requires explicit selection.
    #[arg(long)]
    yes: bool,
    /// Directory for separate recovery files, one per project.
    #[arg(long)]
    recovery_dir: Option<PathBuf>,
    /// Use an existing recovery identity for one explicitly selected project.
    #[arg(long, conflicts_with = "recovery_dir")]
    recovery_file: Option<PathBuf>,
    /// Explicitly accept a recovery copy on this computer; move it offline later.
    #[arg(long)]
    allow_same_disk: bool,
    /// Keep the original dotenv files and report protection as incomplete.
    #[arg(long)]
    keep_sources: bool,
    /// Skip optional global coding-agent guidance.
    #[arg(long)]
    no_agents: bool,
    /// Use numbered menus, useful for screen readers and simple terminals.
    #[arg(long)]
    plain: bool,
    /// Maximum project discovery depth; ignored dependency folders are never scanned.
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u8).range(0..=12))]
    depth: u8,
    /// Review a fresh import plan while retaining the existing vault and recovery key.
    #[arg(long)]
    restart: bool,
}

#[derive(Clone)]
struct Candidate {
    root: PathBuf,
    files: Vec<String>,
    managed: bool,
}

#[derive(Clone)]
struct ProjectPlan {
    root: PathBuf,
    profile: Option<importcmd::ImportProfile>,
    manager: String,
    scripts: Vec<String>,
    environment: String,
    imported: bool,
    configured: bool,
    complete: bool,
    recovery: Option<PathBuf>,
    local_recovery_accepted: bool,
    import: importcmd::GuidedPlan,
    /// Production-style scripts setup leaves alone. Not journaled: the warning
    /// belongs to the first review, and a resumed plan was already reviewed.
    unwrapped: Vec<String>,
}

/// Scripts that usually load dotenv files through the framework or the app.
const BUILD_SCRIPTS: [&str; 3] = ["build", "start", "preview"];

fn error(message: impl Into<String>) -> CliError {
    CliError::failure(message, Some("envholster setup".into()))
}

pub(crate) fn run(options: &Options, identity: &Option<PathBuf>) -> Result<i32, CliError> {
    let identity = identity.as_ref().map(fs::canonicalize).transpose()?;
    let interactive = std::io::stdin().is_terminal();
    if !interactive && !options.plan && !options.yes {
        println!("Envholster is installed. Open a terminal and run `envholster setup` to select your projects.");
        return Ok(EXIT_OK);
    }
    if options.yes && !options.all && options.project_dir.is_empty() {
        return Err(error(
            "--yes requires explicit --project selections or --root with --all",
        ));
    }
    let cwd = std::env::current_dir()?;
    let initial = options
        .root
        .as_ref()
        .map(|p| ui::resolve_path(p, &cwd))
        .unwrap_or_else(|| remembered_root().unwrap_or_else(|| cwd.clone()));
    println!("\nEnvholster setup\nChoose your projects. Keep your usual launch commands.\n");
    let root = if options.root.is_some() || !options.project_dir.is_empty() || !interactive {
        fs::canonicalize(&initial)?
    } else {
        ui::folder("Where do you keep your projects?", &initial, options.plain)?
    };
    println!(
        "Looking for projects in {} ...",
        ui::clean(root.to_string_lossy())
    );
    let candidates = discover(&root, options.depth)?;
    let selected = if !options.project_dir.is_empty() {
        options
            .project_dir
            .iter()
            .map(|p| fs::canonicalize(ui::resolve_path(p, &root)).map_err(CliError::from))
            .collect::<Result<Vec<_>, _>>()?
    } else if options.all || options.plan && !interactive {
        candidates.iter().map(|p| p.root.clone()).collect()
    } else {
        if candidates.is_empty() {
            return Err(error("No projects found. Choose another root folder or pass --project PATH for a new project."));
        }
        let labels: Vec<_> = candidates
            .iter()
            .map(|p| {
                let relative = p.root.strip_prefix(&root).unwrap_or(&p.root);
                let label = if relative.as_os_str().is_empty() {
                    p.root
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned()
                } else {
                    relative.display().to_string()
                };
                format!(
                    "{label}  · {}  · {} dotenv file(s)",
                    if p.managed { "existing vault" } else { "new" },
                    p.files.len()
                )
            })
            .collect();
        let defaults = if candidates.len() == 1 {
            vec![0]
        } else {
            vec![]
        };
        ui::select(
            "Which projects should Envholster protect?",
            &labels,
            true,
            &defaults,
            options.plain,
        )?
        .into_iter()
        .map(|i| candidates[i].root.clone())
        .collect()
    };
    let mut selected: Vec<_> = selected
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if interactive && !options.yes && !options.plan {
        while let Some(parent) = selected
            .iter()
            .find(|parent| {
                selected
                    .iter()
                    .any(|child| child != *parent && child.starts_with(parent))
            })
            .cloned()
        {
            let choice = ui::select(
                &format!(
                    "{} contains other selected projects",
                    ui::clean(parent.to_string_lossy())
                ),
                &[
                    "Use separate vaults for the selected apps inside this workspace".into(),
                    "Use one vault at the workspace root".into(),
                ],
                false,
                &[0],
                options.plain,
            )?[0];
            if choice == 0 {
                selected.retain(|p| p != &parent);
            } else {
                selected.retain(|p| p == &parent || !p.starts_with(&parent));
            }
        }
    }
    if selected.is_empty() {
        println!("No projects selected.");
        return Ok(EXIT_OK);
    }
    for path in &selected {
        if !path.is_dir() || !path.starts_with(&root) {
            return Err(error(
                "Selected projects must be directories inside the chosen root",
            ));
        }
        if selected
            .iter()
            .any(|other| other != path && path.starts_with(other))
        {
            return Err(error("Choose either a workspace root or its individual apps, not both in one batch. Each selected project gets its own vault."));
        }
    }
    let mut plans = Vec::new();
    let mut failures = 0;
    for path in &selected {
        match prepare(path, options.restart) {
            Ok(plan) => plans.push(plan),
            Err(problem) => {
                failures += 1;
                eprintln!(
                    "Needs attention: {}\n  {}",
                    ui::clean(path.to_string_lossy()),
                    ui::clean(&problem.message)
                );
            }
        }
    }
    if plans.is_empty() {
        return Ok(EXIT_FINDINGS);
    }
    if let Some(file) = &options.recovery_file {
        if plans.len() != 1 {
            return Err(error(
                "--recovery-file requires exactly one selected project",
            ));
        }
        plans[0].recovery = Some(fs::canonicalize(ui::resolve_path(file, &cwd))?);
        plans[0].local_recovery_accepted = false;
    }
    println!("\nYour project plan");
    for plan in &plans {
        println!("\n  {}", ui::clean(plan.root.to_string_lossy()));
        println!(
            "    {} encrypted value(s) · launch environment {}{}",
            plan.import.values.len(),
            plan.environment,
            if plan.complete {
                " · verify existing setup"
            } else if plan.imported {
                " · resume"
            } else {
                ""
            }
        );
        let sources: BTreeSet<_> = plan
            .import
            .sources
            .iter()
            .map(|s| ui::clean(s.path.file_name().unwrap_or_default().to_string_lossy()))
            .collect();
        if !sources.is_empty() {
            println!(
                "    Import: {}",
                sources.into_iter().collect::<Vec<_>>().join(", ")
            );
        }
        let tracked = tracked_sources(plan);
        if !tracked.is_empty() && !options.keep_sources {
            println!(
                "    Kept because git tracks them: {}. Deleting a committed file leaves its values in git history and can break builds that read it from the repository.",
                file_names(&tracked)
            );
        }
        println!("    Launch: {}", launch_description(plan));
        // Mirrors setup::project: a nonempty AGENTS.override.md takes the
        // section instead of AGENTS.md.
        let agents = if setup::read_optional(&plan.root.join("AGENTS.override.md"))?
            .is_some_and(|s| !s.trim().is_empty())
        {
            "AGENTS.override.md"
        } else {
            "AGENTS.md"
        };
        println!(
            "    Writes: an Envholster section in {agents} and CLAUDE.md, .cursor/rules/envholster.mdc{}",
            if plan.scripts.is_empty() {
                ""
            } else {
                ", and the wrapped scripts in package.json"
            }
        );
        if !options.keep_sources
            && plan
                .import
                .sources
                .iter()
                .any(|s| !tracked.contains(&s.path))
        {
            if let Some(hint) = unwrapped_hint(plan) {
                println!("    {hint}");
            }
        }
        if plan
            .import
            .values
            .iter()
            .any(|v| v.name.starts_with("NEXT_PUBLIC_") || v.name.starts_with("VITE_"))
        {
            println!("    Browser-public variable names detected. Encryption does not hide values bundled into browser code.");
        }
    }
    println!("\nAll imported values stay encrypted. Originals are removed only after import and recovery verification.");
    if options.keep_sources {
        println!("You chose to retain plaintext originals; setup will report them as remaining.");
    }
    if options.plan {
        return Ok(if failures == 0 {
            EXIT_OK
        } else {
            EXIT_FINDINGS
        });
    }
    if !options.yes
        && !ui::confirm(
            &format!("Protect these {} project(s) with this plan?", plans.len()),
            false,
        )?
    {
        return Ok(EXIT_OK);
    }
    remember_root(&root)?;

    let recovery_folder = choose_recovery_folder(options, &plans, interactive)?;
    if let Some(folder) = &recovery_folder {
        if selected.iter().any(|project| folder.starts_with(project)) {
            return Err(error(
                "Choose a recovery folder outside all selected projects",
            ));
        }
    }
    let mut allow_same_disk = options.allow_same_disk;
    let mut needs_local_consent = false;
    for plan in &plans {
        let destination = plan
            .recovery
            .clone()
            .or_else(|| recovery_folder.as_ref().map(|p| p.join("recovery.txt")));
        if let Some(path) = destination {
            if selected.iter().any(|p| path.starts_with(p)) {
                return Err(error(
                    "Recovery files must be outside every selected project",
                ));
            }
            if !plan.local_recovery_accepted && recovery::on_this_machines_disk(&path, &plan.root)?
            {
                needs_local_consent = true;
            }
        }
    }
    if !allow_same_disk && needs_local_consent {
        if !interactive || options.yes {
            return Err(error("The recovery folder is on this computer. Use removable storage or explicitly pass --allow-same-disk."));
        }
        allow_same_disk = ui::confirm("This recovery folder is on this computer. Save here now and move the recovery files offline afterward?", false)?;
        if !allow_same_disk {
            return Err(error(
                "Choose another recovery folder and rerun setup; project files have not changed",
            ));
        }
    }
    if !options.no_agents && interactive && !options.yes {
        choose_agents(options.plain)?;
    }
    let mut completed = Vec::new();
    let total = plans.len();
    for (index, plan) in plans.iter_mut().enumerate() {
        println!(
            "\n[{}/{}] {}",
            index + 1,
            total,
            ui::clean(plan.root.to_string_lossy())
        );
        match apply_project(
            plan,
            recovery_folder.as_deref(),
            allow_same_disk,
            options.keep_sources,
            &identity,
        ) {
            Ok(true) => completed.push(plan.clone()),
            Ok(false) => failures += 1,
            Err(problem) => {
                failures += 1;
                eprintln!("Needs attention: {}\n  Rerun envholster setup to continue. Use --restart to review changed source files.", ui::clean(&problem.message));
            }
        }
    }
    println!(
        "\n{} project(s) complete · {} need attention",
        completed.len(),
        failures
    );
    if plans.iter().any(|p| p.local_recovery_accepted) {
        println!("Recovery copies were verified on this computer. Move them offline; local copies do not protect against losing this disk.");
    }
    for plan in &completed {
        println!(
            "  {}: {}",
            ui::clean(plan.root.to_string_lossy()),
            launch_description(plan)
        );
    }
    if interactive && !options.yes && !completed.is_empty() {
        let mut choices = vec!["Finish setup".into()];
        choices.extend(completed.iter().map(|p| {
            format!(
                "Start {} in {}",
                launch_description(p),
                p.root.file_name().unwrap_or_default().to_string_lossy()
            )
        }));
        let choice = ui::select("Ready to code", &choices, false, &[0], options.plain)?[0];
        if choice > 0 {
            launch(&completed[choice - 1], &identity)?;
        }
    }
    Ok(if failures == 0 {
        EXIT_OK
    } else {
        EXIT_FINDINGS
    })
}

fn choose_recovery_folder(
    options: &Options,
    plans: &[ProjectPlan],
    interactive: bool,
) -> Result<Option<PathBuf>, CliError> {
    if let Some(path) = &options.recovery_dir {
        let path = ui::resolve_path(path, &std::env::current_dir()?);
        return prepare_recovery_folder(&path, plans).map(Some);
    }
    if plans.iter().all(|p| p.recovery.is_some()) {
        return Ok(None);
    }
    if !interactive || options.yes {
        if options.keep_sources {
            return Ok(None);
        }
        return Err(error("Provide --recovery-dir for unattended setup, or --keep-sources to defer recovery and keep plaintext originals"));
    }
    'choose: loop {
        let choice = ui::select(
            "Where should recovery copies go?",
            &[
                "Choose a folder on removable or separate storage (recommended)".into(),
                "Paste a recovery folder path".into(),
                "Do this later; keep original dotenv files for now".into(),
            ],
            false,
            &[0],
            options.plain,
        )?[0];
        let folder = match choice {
            0 => ui::folder(
                "Choose a folder outside your projects for recovery copies",
                &std::env::current_dir()?,
                options.plain,
            )?,
            1 => loop {
                let entered = ui::line("Recovery folder path: ")?;
                if entered.is_empty() {
                    continue 'choose;
                }
                let path = ui::resolve_input_path(&entered, &std::env::current_dir()?);
                match prepare_recovery_folder(&path, plans) {
                    Ok(folder) => return Ok(Some(folder)),
                    Err(problem) => eprintln!(
                        "{}\nTry another path, or press Enter to choose another recovery option.",
                        ui::clean(&problem.message)
                    ),
                }
            },
            _ => return Ok(None),
        };
        match prepare_recovery_folder(&folder, plans) {
            Ok(folder) => return Ok(Some(folder)),
            Err(problem) => {
                eprintln!("{}", ui::clean(&problem.message));
                ui::line("Press Enter to choose another recovery folder: ")?;
            }
        }
    }
}

fn prepare_recovery_folder(path: &Path, plans: &[ProjectPlan]) -> Result<PathBuf, CliError> {
    use std::os::unix::fs::PermissionsExt;
    setup::safe_path(path)?;
    // Resolve '..' before checking scope, including when the final folder is new.
    let mut ancestor = path;
    let mut tail = Vec::new();
    while !ancestor.exists() {
        tail.push(
            ancestor
                .file_name()
                .ok_or_else(|| error("Invalid recovery folder"))?
                .to_owned(),
        );
        ancestor = ancestor
            .parent()
            .ok_or_else(|| error("Invalid recovery folder"))?;
    }
    let mut normalized = fs::canonicalize(ancestor)?;
    for part in tail.into_iter().rev() {
        normalized.push(part);
    }
    if plans.iter().any(|p| normalized.starts_with(&p.root)) {
        return Err(error(
            "Choose a recovery folder outside all selected projects",
        ));
    }
    if normalized.is_dir() && fs::metadata(&normalized)?.permissions().mode() & 0o777 != 0o700 {
        normalized.push("Envholster Recovery");
    }
    create_secret_dir(&normalized)?;
    Ok(normalized)
}

fn choose_agents(plain: bool) -> Result<(), CliError> {
    let apps = setup::AgentPaths::new()?.detected();
    if apps.is_empty() {
        return Ok(());
    }
    let seen = read_preferences()?
        .get("seen_agents")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let fresh: Vec<Agent> = apps
        .into_iter()
        .filter(|a| !seen.iter().any(|s| s.as_str() == Some(a.name())))
        .collect();
    if fresh.is_empty() {
        return Ok(());
    }
    let labels = fresh
        .iter()
        .map(|a| a.name().to_owned())
        .collect::<Vec<_>>();
    if ui::confirm(
        &format!(
            "Add optional launch guidance for detected coding agents ({})?",
            labels.join(", ")
        ),
        true,
    )? {
        let selected = ui::select(
            "Coding agents to configure",
            &labels,
            true,
            &(0..fresh.len()).collect::<Vec<_>>(),
            plain,
        )?;
        let apps = selected.into_iter().map(|i| fresh[i]).collect::<Vec<_>>();
        if !apps.is_empty() {
            setup::agents(&apps, &Mode::default())?;
        }
    }
    let mut prefs = read_preferences()?;
    let mut seen = seen;
    seen.extend(fresh.iter().map(|a| toml::Value::String(a.name().into())));
    prefs.insert("seen_agents".into(), toml::Value::Array(seen));
    write_table(&preferences_path(), prefs)
}

fn discover(root: &Path, depth: u8) -> Result<Vec<Candidate>, CliError> {
    let mut queue = vec![(root.to_owned(), 0)];
    let mut result = Vec::new();
    let mut visited = 0;
    while let Some((dir, level)) = queue.pop() {
        visited += 1;
        if visited > 20_000 {
            return Err(error(
                "Too many folders to scan. Choose a narrower project root.",
            ));
        }
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => {
                eprintln!(
                    "Skipped unreadable folder: {}",
                    ui::clean(dir.to_string_lossy())
                );
                continue;
            }
        };
        let mut names = BTreeSet::new();
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                continue;
            }
            names.insert(name.clone());
            if kind.is_dir()
                && level < depth
                && !name.starts_with('.')
                && !matches!(
                    name.as_str(),
                    "node_modules" | "target" | "vendor" | "dist" | "build" | "venv" | "Library"
                )
            {
                queue.push((entry.path(), level + 1));
            }
        }
        let files: Vec<_> = names
            .iter()
            .filter(|s| importcmd::dotenv_like(s) && s.as_str() != ".env.example")
            .cloned()
            .collect();
        let managed = names.contains("envholster.toml") || names.contains("secrets.holster");
        if managed
            || !files.is_empty()
            || [
                "package.json",
                "Cargo.toml",
                "pyproject.toml",
                "manage.py",
                "go.mod",
                "Gemfile",
                ".git",
            ]
            .iter()
            .any(|n| names.contains(*n))
        {
            result.push(Candidate {
                root: dir,
                files,
                managed,
            });
        }
    }
    result.sort_by(|a, b| a.root.cmp(&b.root));
    Ok(result)
}

fn inspect(
    root: &Path,
) -> Result<(Option<importcmd::ImportProfile>, String, Vec<String>), CliError> {
    let mut manager = [
        ("pnpm-lock.yaml", "pnpm"),
        ("yarn.lock", "yarn"),
        ("bun.lock", "bun"),
        ("bun.lockb", "bun"),
    ]
    .into_iter()
    .find(|(file, _)| root.join(file).is_file())
    .map(|(_, manager)| manager)
    .unwrap_or("npm")
    .to_owned();
    let Some(package) = setup::read_optional(&root.join("package.json"))? else {
        return Ok((None, manager, vec![]));
    };
    let Some(node) = setup::program("node") else {
        println!(
            "Node.js is unavailable; package-script detection will wait until it is installed."
        );
        return Ok((None, manager, vec![]));
    };
    let mut child = Command::new(node)
        .env_clear()
        .args(["-e", INSPECT])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| error("Project inspection stdin is unavailable"))?;
    let writer = std::thread::spawn(move || stdin.write_all(package.as_bytes()));
    let output = child.wait_with_output()?;
    writer
        .join()
        .map_err(|_| error("Project inspection failed"))??;
    if !output.status.success() {
        return Err(error(
            "package.json could not be parsed. Review it before onboarding.",
        ));
    }
    let text =
        String::from_utf8(output.stdout).map_err(|_| error("Invalid project inspection output"))?;
    let fields: BTreeMap<_, _> = text.lines().filter_map(|s| s.split_once('=')).collect();
    if let Some(names) = fields.get("file_readers").filter(|names| !names.is_empty()) {
        return Err(error(format!("Package scripts ({names}) explicitly read dotenv files, possibly through another script. Originals were kept. Review file compatibility with `envholster run --dotenv` before migrating this project; automatic setup does not enable temporary plaintext files.")));
    }
    let profile = match fields.get("profile").copied() {
        Some("nextjs") => Some(importcmd::ImportProfile::Nextjs),
        Some("vite") => Some(importcmd::ImportProfile::Vite),
        Some("ambiguous") => return Err(error("Both Next.js and Vite were detected. Select the intended dotenv precedence with explicit `envholster import --profile` before onboarding.")),
        _ => None,
    };
    if let Some(m) = fields.get("manager").filter(|m| !m.is_empty()) {
        manager = m.to_string();
    }
    let scripts = fields
        .get("scripts")
        .unwrap_or(&"")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    Ok((profile, manager, scripts))
}

fn prepare(root: &Path, restart: bool) -> Result<ProjectPlan, CliError> {
    setup::safe_path(root)?;
    if root.join("envholster.toml").is_file() != root.join("secrets.holster").is_file() {
        return Err(error("Only one of envholster.toml and secrets.holster exists. Restore the missing file before setup; neither will be overwritten."));
    }
    let previous = load_state(root)?;
    if !restart {
        if let Some(plan) = previous {
            return Ok(plan);
        }
    }
    let (profile, manager, scripts) = inspect(root)?;
    let import = importcmd::guided_plan(root, profile)?;
    let environment = if profile.is_some() {
        "development"
    } else {
        "base"
    }
    .to_owned();
    let unwrapped = BUILD_SCRIPTS
        .into_iter()
        .filter(|s| scripts.iter().any(|found| found == s))
        .map(str::to_owned)
        .collect();
    let scripts = if scripts.iter().any(|s| s == "dev") && manager != "yarn" {
        ["dev", "predev", "postdev"]
            .into_iter()
            .filter(|s| scripts.iter().any(|found| found == s))
            .map(str::to_owned)
            .collect()
    } else {
        vec![]
    };
    Ok(ProjectPlan {
        root: root.to_owned(),
        profile,
        manager,
        scripts,
        environment,
        imported: false,
        configured: false,
        complete: false,
        recovery: previous.as_ref().and_then(|p| p.recovery.clone()),
        local_recovery_accepted: previous.as_ref().is_some_and(|p| p.local_recovery_accepted),
        import,
        unwrapped,
    })
}

/// Sources git tracks are kept: deleting a committed file does not remove its
/// values from history, and a build or deploy that reads it from the
/// repository would silently lose them.
fn tracked_sources(plan: &ProjectPlan) -> Vec<PathBuf> {
    plan.import
        .sources
        .iter()
        .map(|s| s.path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|path| path.is_file() && crate::commands::run::git_tracks(&plan.root, path))
        .collect()
}

fn file_names(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| ui::clean(p.file_name().unwrap_or_default().to_string_lossy()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// How to run a script setup did not wrap, so it still gets the vault values.
fn unwrapped_hint(plan: &ProjectPlan) -> Option<String> {
    let script = plan.unwrapped.first()?;
    let env = if plan.profile.is_some() {
        "--env production "
    } else {
        ""
    };
    Some(format!(
        "Not wrapped: {}. Without the dotenv files they no longer get these values; run them as `envholster {env}run -- {} run {script}`.",
        plan.unwrapped.join(", "),
        plan.manager
    ))
}

struct Directory(PathBuf);
impl Directory {
    fn enter(path: &Path) -> Result<Self, CliError> {
        let old = std::env::current_dir()?;
        std::env::set_current_dir(path)?;
        Ok(Self(old))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.0);
    }
}

fn apply_project(
    plan: &mut ProjectPlan,
    recovery_folder: Option<&Path>,
    allow_same_disk: bool,
    keep_sources: bool,
    identity: &Option<PathBuf>,
) -> Result<bool, CliError> {
    let _directory = Directory::enter(&plan.root)?;
    if !plan.root.join("secrets.holster").is_file() {
        let mut session = Session::new(&Some("base".into()), identity)?;
        init::run(&mut session, &[], None)?;
    }
    let project = discover_project()?;
    let mut session = Session::new(&Some("base".into()), identity)?;
    if plan.recovery.is_none() {
        if let Some(folder) = recovery_folder {
            let id = sha256_hex_lower(plan.root.to_string_lossy().as_bytes());
            plan.recovery = Some(folder.join(format!("envholster-{}-recovery.txt", &id[..16])));
        }
    }
    save_state(plan)?;
    if !plan.imported {
        if !plan.import.sources.is_empty() {
            importcmd::guided_apply(&mut session, &project, &plan.import, plan.profile)?;
        }
        plan.imported = true;
        save_state(plan)?;
    }
    importcmd::guided_verify(&mut session, &project, &plan.import)?;
    if !plan.configured {
        if plan.environment != "base" {
            let mut manifest = crate::manifestio::load_manifest(&project.manifest_path)?;
            crate::manifestio::ensure_env_declared(
                &mut manifest,
                &EnvName::parse(&plan.environment).map_err(CliError::from)?,
            );
            crate::manifestio::store_manifest(&project.manifest_path, &manifest)?;
        }
        setup::project(Some(&plan.environment), &plan.scripts, &Mode::default())?;
        plan.configured = true;
        save_state(plan)?;
    }
    setup::check_project(&plan.environment, &plan.scripts)?;
    let Some(recovery_path) = &plan.recovery else {
        println!("Recovery is pending. Original dotenv files were kept. Rerun setup with a recovery folder.");
        return Ok(false);
    };
    let local = recovery::on_this_machines_disk(recovery_path, &plan.root)?;
    recovery::guided_save(
        &session,
        recovery_path,
        allow_same_disk || plan.local_recovery_accepted,
    )?;
    plan.local_recovery_accepted = local && (allow_same_disk || plan.local_recovery_accepted);
    save_state(plan)?;
    importcmd::guided_verify(&mut session, &project, &plan.import)?;
    let tracked = tracked_sources(plan);
    if !keep_sources {
        let mut deleted = BTreeSet::new();
        for source in &plan.import.sources {
            if !tracked.contains(&source.path) && deleted.insert(source.path.clone()) {
                importcmd::guided_remove_source(source)?;
            }
        }
    }
    let remaining = remaining_plaintext(&plan.root)?;
    plan.complete = remaining.is_empty();
    save_state(plan)?;
    if plan.complete {
        println!("Verified: encrypted values, recovery copy and launch instructions. No root dotenv plaintext remains.");
    } else {
        println!(
            "Plaintext remains: {}",
            remaining
                .iter()
                .map(|p| ui::clean(p.file_name().unwrap_or_default().to_string_lossy()))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !keep_sources && !tracked.is_empty() {
        let names = file_names(&tracked);
        println!("Kept because git tracks them: {names}. Once nothing builds from them, run `git rm {names}`, commit, and rotate any secrets they held.");
    }
    if !keep_sources
        && plan
            .import
            .sources
            .iter()
            .any(|s| !tracked.contains(&s.path))
    {
        if let Some(hint) = unwrapped_hint(plan) {
            println!("{hint}");
        }
    }
    println!("Deletion does not erase git history or backups. Rotate credentials that were previously exposed.");
    Ok(plan.complete)
}

fn remaining_plaintext(root: &Path) -> Result<Vec<PathBuf>, CliError> {
    use std::io::Read;
    let mut remaining = Vec::new();
    for entry in fs::read_dir(root)?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if importcmd::dotenv_like(&name) && name != ".env.example" {
            let marker = importcmd::ENV_BREADCRUMB.as_bytes();
            let kind = entry.file_type()?;
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            if kind.is_file() && entry.metadata()?.len() == marker.len() as u64 {
                fs::File::open(entry.path())?
                    .take(marker.len() as u64 + 1)
                    .read_to_end(&mut bytes)?;
            }
            if bytes.as_slice() != marker {
                remaining.push(entry.path());
            }
        }
    }
    remaining.sort();
    Ok(remaining)
}

fn launch_description(plan: &ProjectPlan) -> String {
    if !plan.scripts.is_empty() {
        format!("{} run {}", plan.manager, plan.scripts[0])
    } else {
        format!(
            "envholster --env {} run -- <your app command>",
            plan.environment
        )
    }
}

fn launch(plan: &ProjectPlan, identity: &Option<PathBuf>) -> Result<(), CliError> {
    if plan.scripts.is_empty() {
        println!("{}", launch_description(plan));
        return Ok(());
    }
    let _directory = Directory::enter(&plan.root)?;
    let mut command = Command::new(&plan.manager);
    command.args(["run", &plan.scripts[0]]);
    if let Some(path) = identity {
        command.env("ENVHOLSTER_IDENTITY_FILE", path);
    }
    let result = command.status()?;
    if !result.success() {
        return Err(error("The app exited with an error. Setup remains saved; use envholster doctor for names-only diagnostics."));
    }
    Ok(())
}

fn state_path(root: &Path) -> PathBuf {
    state_folder().join(format!(
        "{}.toml",
        sha256_hex_lower(root.to_string_lossy().as_bytes())
    ))
}
fn preferences_path() -> PathBuf {
    state_folder().join("preferences.toml")
}
fn state_folder() -> PathBuf {
    fs::canonicalize(config_dir())
        .unwrap_or_else(|_| config_dir())
        .join("onboarding")
}
fn read_preferences() -> Result<toml::Table, CliError> {
    Ok(read_table(&preferences_path())?.unwrap_or_default())
}
fn remembered_root() -> Option<PathBuf> {
    read_preferences()
        .ok()?
        .get("last_root")?
        .as_str()
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
}
fn remember_root(root: &Path) -> Result<(), CliError> {
    let mut prefs = read_preferences()?;
    prefs.insert(
        "last_root".into(),
        toml::Value::String(root.to_string_lossy().into()),
    );
    write_table(&preferences_path(), prefs)
}

fn read_table(path: &Path) -> Result<Option<toml::Table>, CliError> {
    if fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return Ok(None);
    }
    let Some(text) = setup::read_optional(path)? else {
        return Ok(None);
    };
    if !text.starts_with(STATE_HEADER) {
        return Err(error(
            "An onboarding state file has unrecognized contents and was left unchanged",
        ));
    }
    text.parse::<toml::Table>().map(Some).map_err(|_| {
        error(format!("Onboarding state could not be parsed. Move {} aside after reviewing it, then rerun setup. Keep the vault, identities and recovery files; use --recovery-file for an existing recovery copy.", ui::clean(path.to_string_lossy())))
    })
}
fn write_table(path: &Path, table: toml::Table) -> Result<(), CliError> {
    read_table(path)?;
    create_secret_dir(
        path.parent()
            .ok_or_else(|| error("Missing state directory"))?,
    )?;
    let text = format!(
        "{STATE_HEADER}{}",
        toml::to_string(&table).map_err(|_| error("Could not serialize onboarding state"))?
    );
    setup::store_state(path, &text)
}

fn save_state(plan: &ProjectPlan) -> Result<(), CliError> {
    let mut table = toml::Table::new();
    table.insert("version".into(), toml::Value::Integer(1));
    for (key, value) in [
        ("root", plan.root.to_string_lossy().into_owned()),
        ("manager", plan.manager.clone()),
        ("environment", plan.environment.clone()),
        (
            "profile",
            match plan.profile {
                Some(importcmd::ImportProfile::Nextjs) => "nextjs",
                Some(importcmd::ImportProfile::Vite) => "vite",
                None => "",
            }
            .into(),
        ),
    ] {
        table.insert(key.into(), toml::Value::String(value));
    }
    for (key, value) in [
        ("imported", plan.imported),
        ("configured", plan.configured),
        ("complete", plan.complete),
        ("local_recovery_accepted", plan.local_recovery_accepted),
    ] {
        table.insert(key.into(), toml::Value::Boolean(value));
    }
    table.insert(
        "scripts".into(),
        toml::Value::Array(
            plan.scripts
                .iter()
                .cloned()
                .map(toml::Value::String)
                .collect(),
        ),
    );
    if let Some(path) = &plan.recovery {
        table.insert(
            "recovery".into(),
            toml::Value::String(path.to_string_lossy().into()),
        );
    }
    let records = |rows: Vec<Vec<(&str, String)>>| {
        toml::Value::Array(
            rows.into_iter()
                .map(|row| {
                    toml::Value::Table(
                        row.into_iter()
                            .map(|(k, v)| (k.into(), toml::Value::String(v)))
                            .collect(),
                    )
                })
                .collect(),
        )
    };
    table.insert(
        "sources".into(),
        records(
            plan.import
                .sources
                .iter()
                .map(|s| {
                    vec![
                        ("path", s.path.to_string_lossy().into()),
                        ("env", s.env.as_str().into()),
                        ("fingerprint", s.fingerprint.clone()),
                    ]
                })
                .collect(),
        ),
    );
    table.insert(
        "values".into(),
        records(
            plan.import
                .values
                .iter()
                .map(|s| {
                    vec![
                        ("name", s.name.clone()),
                        ("env", s.env.as_str().into()),
                        ("fingerprint", s.fingerprint.clone()),
                    ]
                })
                .collect(),
        ),
    );
    write_table(&state_path(&plan.root), table)
}

fn load_state(root: &Path) -> Result<Option<ProjectPlan>, CliError> {
    let Some(table) = read_table(&state_path(root))? else {
        return Ok(None);
    };
    let string = |key: &str| {
        table
            .get(key)
            .and_then(toml::Value::as_str)
            .ok_or_else(|| error(format!("Onboarding state is incomplete. Review and move {} aside, then rerun setup with your existing recovery file.", ui::clean(state_path(root).to_string_lossy()))))
    };
    if table.get("version").and_then(toml::Value::as_integer) != Some(1)
        || Path::new(string("root")?) != root
    {
        return Err(error(
            "Onboarding state belongs to another project or version",
        ));
    }
    let environment = string("environment")?.to_owned();
    EnvName::parse(&environment).map_err(CliError::from)?;
    let manager = string("manager")?.to_owned();
    if !["npm", "pnpm", "yarn", "bun"].contains(&manager.as_str()) {
        return Err(error("Unrecognized package manager in onboarding state"));
    }
    let field = |row: &toml::Value, key: &str| {
        row.get(key)
            .and_then(toml::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| error("Invalid onboarding record"))
    };
    let mut import = importcmd::GuidedPlan::default();
    for row in table
        .get("sources")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| error("Missing onboarding sources"))?
    {
        let path = PathBuf::from(field(row, "path")?);
        if path.parent() != Some(root)
            || !path
                .file_name()
                .is_some_and(|s| importcmd::dotenv_like(&s.to_string_lossy()))
        {
            return Err(error("Onboarding source is outside the selected project"));
        }
        import.sources.push(importcmd::GuidedSource {
            path,
            env: EnvName::parse(&field(row, "env")?).map_err(CliError::from)?,
            fingerprint: field(row, "fingerprint")?,
        });
    }
    for row in table
        .get("values")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| error("Missing onboarding values"))?
    {
        let name = field(row, "name")?;
        if !envholster_core::is_valid_var_name(&name) {
            return Err(error("Invalid variable name in onboarding state"));
        }
        import.values.push(importcmd::GuidedValue {
            name,
            env: EnvName::parse(&field(row, "env")?).map_err(CliError::from)?,
            fingerprint: field(row, "fingerprint")?,
        });
    }
    let scripts = table
        .get("scripts")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| error("Missing launch scripts"))?
        .iter()
        .map(|s| {
            s.as_str()
                .map(str::to_owned)
                .ok_or_else(|| error("Invalid launch script"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if scripts.iter().any(|s| {
        s.is_empty()
            || s.len() > 64
            || !s.as_bytes()[0].is_ascii_alphanumeric()
            || !s
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b":_-".contains(&c))
    }) {
        return Err(error("Invalid launch script in onboarding state"));
    }
    if import
        .sources
        .iter()
        .map(|s| &s.fingerprint)
        .chain(import.values.iter().map(|s| &s.fingerprint))
        .any(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(error(
            "Invalid verification fingerprint in onboarding state",
        ));
    }
    let recovery = table
        .get("recovery")
        .and_then(toml::Value::as_str)
        .map(PathBuf::from);
    if recovery.as_ref().is_some_and(|p| {
        !p.is_absolute()
            || p.starts_with(root)
            || p.components().any(|c| c == std::path::Component::ParentDir)
    }) {
        return Err(error(
            "Invalid recovery path in onboarding state. Review the state file before resuming.",
        ));
    }
    Ok(Some(ProjectPlan {
        root: root.to_owned(),
        profile: match string("profile")? {
            "nextjs" => Some(importcmd::ImportProfile::Nextjs),
            "vite" => Some(importcmd::ImportProfile::Vite),
            "" => None,
            _ => return Err(error("Invalid import profile")),
        },
        manager,
        scripts,
        environment,
        imported: table
            .get("imported")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false),
        configured: table
            .get("configured")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false),
        complete: table
            .get("complete")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false),
        recovery,
        local_recovery_accepted: table
            .get("local_recovery_accepted")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false),
        import,
        unwrapped: vec![],
    }))
}

pub(crate) fn doctor_findings() -> Vec<String> {
    let Ok(project) = discover_project() else {
        return vec![];
    };
    let mut findings = Vec::new();
    let root = fs::canonicalize(&project.root).unwrap_or(project.root);
    match load_state(&root) {
        Ok(Some(plan)) if !plan.complete => {
            findings.push("Project onboarding is incomplete; run envholster setup to resume".into())
        }
        Err(problem) => findings.push(format!(
            "Project onboarding state needs review: {}",
            ui::clean(problem.message)
        )),
        _ => {}
    }
    if let Ok(files) = remaining_plaintext(&root) {
        for path in files {
            findings.push(format!(
                "Plaintext dotenv file remains: {}. Run envholster setup to review and protect it.",
                ui::clean(path.to_string_lossy())
            ));
        }
    }
    findings
}
