//! All migration exercises use disposable homes and withhold subprocess output.
#![forbid(unsafe_code)]
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_envholster");
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "envholster-onboard-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(path.join("projects")).unwrap();
        fs::create_dir_all(path.join("home")).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
    fn app(&self, name: &str, dotenv: &str) -> PathBuf {
        let path = self.0.join("projects").join(name);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join(".env"), dotenv).unwrap();
        path
    }
    fn command(&self) -> Command {
        let mut c = Command::new(BIN);
        c.env_clear()
            .env("HOME", self.0.join("home"))
            .env("XDG_CONFIG_HOME", self.0.join("home/.config"))
            .env("TMPDIR", &self.0)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .current_dir(self.0.join("projects"))
            .stdin(Stdio::null());
        c
    }
    fn setup(&self, names: &[&str], args: &[&str]) -> Output {
        let mut c = self.command();
        c.args(["setup", "--root"]).arg(self.0.join("projects"));
        for name in names {
            c.args(["--project", name]);
        }
        c.args(["--yes", "--no-agents"])
            .args(args)
            .output()
            .unwrap()
    }
    fn recover(&self, names: &[&str], args: &[&str]) -> Output {
        let path = self.0.join("recovery");
        let mut flags = vec![
            "--recovery-dir",
            path.to_str().unwrap(),
            "--allow-same-disk",
        ];
        flags.extend(args);
        self.setup(names, &flags)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[track_caller]
fn success(output: Output) {
    assert!(
        output.status.success(),
        "onboarding failed (status {:?}); output withheld",
        output.status.code()
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("fixture-private"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("fixture-private"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("AGE-SECRET-KEY-"));
}
fn marker(path: &Path) -> bool {
    fs::read_to_string(path)
        .unwrap()
        .starts_with("# Managed by Env Holster.")
}

#[test]
fn batch_onboards_only_selected_projects_and_verifies_recovery() {
    let s = Scratch::new();
    let first = s.app(
        "first app",
        "TOKEN = \"fixture-private-first\"\nPORT=3000\n",
    );
    let second = s.app("second", "TOKEN=fixture-private-second\n");
    let untouched = s.app("leave alone", "TOKEN=fixture-private-untouched\n");
    success(s.recover(&["first app", "second"], &[]));
    for path in [&first, &second] {
        assert!(marker(&path.join(".env")));
        assert!(path.join("secrets.holster").is_file());
    }
    assert!(!untouched.join("envholster.toml").exists());
    assert!(!marker(&untouched.join(".env")));
    assert_eq!(fs::read_dir(s.0.join("recovery")).unwrap().count(), 2);
    for file in fs::read_dir(s.0.join("recovery")).unwrap() {
        assert_eq!(
            file.unwrap().metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    for file in fs::read_dir(s.0.join("home/.config/envholster/onboarding")).unwrap() {
        let bytes = fs::read(file.unwrap().path()).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("fixture-private"));
    }
    success(s.setup(&["first app", "second"], &[]));
    success(
        s.command()
            .current_dir(&first)
            .args([
                "run",
                "--",
                "/bin/sh",
                "-c",
                "test \"$TOKEN\" = fixture-private-first && test \"$PORT\" = 3000",
            ])
            .output()
            .unwrap(),
    );
}

#[test]
fn pending_recovery_retains_originals_and_resume_finishes() {
    let s = Scratch::new();
    let app = s.app("app", "TOKEN=fixture-private-pending\n");
    assert_eq!(
        s.setup(&["app"], &["--keep-sources"]).status.code(),
        Some(7)
    );
    assert!(!marker(&app.join(".env")));
    assert!(app.join("secrets.holster").exists());
    success(s.recover(&["app"], &[]));
    assert!(marker(&app.join(".env")));
    success(s.setup(&["app"], &[]));
}

#[test]
fn changed_sources_are_kept_until_a_new_reviewed_plan() {
    let s = Scratch::new();
    let app = s.app("app", "TOKEN=fixture-private-before\n");
    assert_eq!(
        s.setup(&["app"], &["--keep-sources"]).status.code(),
        Some(7)
    );
    fs::write(app.join(".env"), "TOKEN=fixture-private-after\n").unwrap();
    assert_eq!(s.recover(&["app"], &[]).status.code(), Some(7));
    assert!(!marker(&app.join(".env")));
    success(s.recover(&["app"], &["--restart"]));
    assert!(marker(&app.join(".env")));
    success(
        s.command()
            .current_dir(app)
            .args([
                "run",
                "--",
                "/bin/sh",
                "-c",
                "test \"$TOKEN\" = fixture-private-after",
            ])
            .output()
            .unwrap(),
    );
}

#[test]
fn nextjs_precedence_and_dev_hooks_survive_setup() {
    let s = Scratch::new();
    let app = s.app("web", "TOKEN=fixture-private-base\n");
    fs::write(app.join(".env.local"), "TOKEN=fixture-private-local\n").unwrap();
    fs::write(
        app.join(".env.development.local"),
        "TOKEN=fixture-private-dev\n",
    )
    .unwrap();
    fs::write(app.join("package.json"), r#"{"dependencies":{"next":"existing"},"scripts":{"dev":"node -e 'process.exit(process.env.TOKEN ? 0 : 1)'","predev":"node -e 'process.exit(process.env.TOKEN ? 0 : 1)'"}}"#).unwrap();
    success(s.recover(&["web"], &[]));
    let package = fs::read_to_string(app.join("package.json")).unwrap();
    assert!(
        package
            .matches("envholster --env development run --")
            .count()
            == 2
    );
    for (env, expected) in [
        ("development", "fixture-private-dev"),
        ("production", "fixture-private-local"),
        ("test", "fixture-private-base"),
    ] {
        success(
            s.command()
                .current_dir(&app)
                .args([
                    "--env",
                    env,
                    "run",
                    "--",
                    "/bin/sh",
                    "-c",
                    &format!("test \"$TOKEN\" = {expected}"),
                ])
                .output()
                .unwrap(),
        );
    }
}

#[test]
fn drifted_launch_rules_prevent_cleanup_on_resume() {
    let s = Scratch::new();
    let app = s.app("app", "TOKEN=fixture-private-before\n");
    assert_eq!(
        s.setup(&["app"], &["--keep-sources"]).status.code(),
        Some(7)
    );
    let path = app.join("AGENTS.md");
    let original = fs::read_to_string(&path).unwrap();
    fs::write(&path, original.replace("envholster", "changed-launch")).unwrap();
    assert_eq!(s.recover(&["app"], &[]).status.code(), Some(7));
    assert!(!marker(&app.join(".env")));
    fs::write(path, original).unwrap();
    success(s.recover(&["app"], &[]));
}

#[test]
fn unsupported_syntax_and_symlinks_leave_projects_untouched() {
    let s = Scratch::new();
    for (name, value) in [
        ("expand", "TOKEN=${OTHER}\n"),
        ("hash", "TOKEN=fixture-private#suffix\n"),
        ("trailing", "TOKEN=\"fixture-private\" trailing\n"),
    ] {
        let app = s.app(name, value);
        assert_eq!(s.recover(&[name], &[]).status.code(), Some(7));
        assert!(!app.join("envholster.toml").exists());
    }
    let outside = s.0.join("outside.env");
    fs::write(&outside, "TOKEN=fixture-private-outside\n").unwrap();
    let app = s.app("linked", "");
    fs::remove_file(app.join(".env")).unwrap();
    symlink(&outside, app.join(".env")).unwrap();
    assert_eq!(s.recover(&["linked"], &[]).status.code(), Some(7));
    assert!(!app.join("envholster.toml").exists());
}

#[test]
fn recovery_folder_in_selected_project_is_refused_before_mutation() {
    let s = Scratch::new();
    let app = s.app("app", "TOKEN=fixture-private-before\n");
    let recovery = app.join("new-recovery");
    assert!(!s
        .setup(
            &["app"],
            &[
                "--recovery-dir",
                recovery.to_str().unwrap(),
                "--allow-same-disk"
            ]
        )
        .status
        .success());
    assert!(!app.join("envholster.toml").exists());
    assert!(!recovery.exists());
}

#[test]
fn plan_does_not_initialize_and_unattended_setup_requires_selection() {
    let s = Scratch::new();
    let app = s.app("app", "TOKEN=fixture-private-before\n");
    success(s.setup(&["app"], &["--plan"]));
    assert!(!app.join("envholster.toml").exists());
    assert!(!s
        .command()
        .args(["setup", "--yes"])
        .output()
        .unwrap()
        .status
        .success());
}

#[test]
fn required_dotenv_file_reader_requires_compatibility_review_before_cleanup() {
    let s = Scratch::new();
    let app = s.app("file-reader", "TOKEN=fixture-private-file\n");
    fs::rename(app.join(".env"), app.join(".env.local")).unwrap();
    fs::write(app.join("package.json"), r#"{"scripts":{"dev":"node --env-file=.env.local -e 'process.exit(process.env.TOKEN ? 0 : 1)'"}}"#).unwrap();
    assert_eq!(s.recover(&["file-reader"], &[]).status.code(), Some(7));
    assert!(app.join(".env.local").is_file());
    assert!(!app.join("secrets.holster").exists());
    fs::write(app.join("package.json"), r#"{"scripts":{"dev":"npm run dev:app","dev:app":"node --env-file=.env.local -e 'process.exit(process.env.TOKEN ? 0 : 1)'"}}"#).unwrap();
    assert_eq!(s.recover(&["file-reader"], &[]).status.code(), Some(7));
    assert!(app.join(".env.local").is_file());
    assert!(!app.join("secrets.holster").exists());
}

#[test]
fn malformed_journal_gives_manual_repair_guidance_without_touching_sources() {
    let s = Scratch::new();
    let app = s.app("app", "TOKEN=fixture-private-state\n");
    assert_eq!(
        s.setup(&["app"], &["--keep-sources"]).status.code(),
        Some(7)
    );
    let journal = s.0.join("home/.config/envholster/onboarding").join(format!(
        "{}.toml",
        envholster_core::sha256_hex_lower(app.to_string_lossy().as_bytes())
    ));
    fs::write(
        journal,
        "# Envholster onboarding state. Contains no secret values.\nbad = [\n",
    )
    .unwrap();
    let output = s.recover(&["app"], &["--restart"]);
    assert_eq!(output.status.code(), Some(7));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Move "));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Use --restart"));
    assert!(!marker(&app.join(".env")));
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.test"])
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

#[test]
fn git_tracked_sources_are_kept_with_guidance() {
    let s = Scratch::new();
    let app = s.app("app", "TOKEN=fixture-private-tracked\n");
    git(&app, &["init", "-q"]);
    git(&app, &["add", ".env"]);
    git(&app, &["commit", "-q", "-m", "init"]);
    let plan = s.setup(&["app"], &["--plan"]);
    assert!(String::from_utf8_lossy(&plan.stdout).contains("Kept because git tracks them: .env."));
    let output = s.recover(&["app"], &[]);
    assert_eq!(output.status.code(), Some(7));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("run `git rm .env`"));
    assert!(!stdout.contains("fixture-private"));
    assert!(!marker(&app.join(".env")));
    assert!(app.join("secrets.holster").is_file());
    success(
        s.command()
            .current_dir(&app)
            .args([
                "run",
                "--",
                "/bin/sh",
                "-c",
                "test \"$TOKEN\" = fixture-private-tracked",
            ])
            .output()
            .unwrap(),
    );
}

#[test]
fn unwrapped_build_scripts_get_a_run_hint() {
    let s = Scratch::new();
    let app = s.app("web", "TOKEN=fixture-private-base\n");
    fs::write(
        app.join("package.json"),
        r#"{"dependencies":{"next":"existing"},"scripts":{"dev":"next dev","build":"next build","start":"next start"}}"#,
    )
    .unwrap();
    let plan = s.setup(&["web"], &["--plan"]);
    let stdout = String::from_utf8_lossy(&plan.stdout);
    assert!(stdout.contains("Not wrapped: build, start."));
    assert!(stdout.contains("`envholster --env production run -- npm run build`"));
    assert!(stdout.contains(
        "Writes: an Envholster section in AGENTS.md and CLAUDE.md, .cursor/rules/envholster.mdc, and the wrapped scripts in package.json"
    ));
    success(plan);
}
