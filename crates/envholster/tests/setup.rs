//! Setup runs in disposable homes; assertions never render process output.
#![forbid(unsafe_code)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const BIN: &str = env!("CARGO_BIN_EXE_envholster");

struct Scratch {
    root: PathBuf,
    user: PathBuf,
    project: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "envholster-setup-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let user = root.join("user");
        let project = root.join("app with spaces");
        fs::create_dir_all(&user).unwrap();
        fs::create_dir_all(&project).unwrap();
        Self {
            root,
            user,
            project,
        }
    }

    fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut command = Command::new(program);
        command
            .env_clear()
            .current_dir(&self.project)
            .env("HOME", &self.user)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("TMPDIR", &self.root)
            .env("XDG_CONFIG_HOME", self.user.join(".config"));
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(BIN)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn managed(&self) {
        put(
            &self.project.join("envholster.toml"),
            "schema = 1\n[environments]\nnames = [\"development\", \"production\"]\n",
        );
        put(
            &self.project.join("secrets.holster"),
            "setup must never open the vault\n",
        );
    }

    fn package(&self, text: &str) {
        put(&self.project.join("package.json"), text);
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn put(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn executable(path: &Path, text: &str) {
    put(path, text);
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[track_caller]
fn success(output: Output) {
    assert!(
        output.status.success(),
        "command failed with status {:?}; secret-bearing output is withheld",
        output.status.code()
    );
}

fn text(path: &Path) -> String {
    fs::read_to_string(path).unwrap()
}

#[test]
fn global_setup_preserves_user_rules_is_repeatable_and_never_loads_identities() {
    let s = Scratch::new();
    let regular = s.user.join(".codex/AGENTS.md");
    let over = s.user.join(".codex/AGENTS.override.md");
    let claude = s.user.join(".claude/CLAUDE.md");
    put(&regular, "Keep these user instructions.\n");
    put(&over, "These overrides win.\n");
    put(&claude, "Existing Claude instructions.\n");
    success(
        s.command(BIN)
            .args([
                "--identity",
                "/does/not/exist",
                "setup",
                "agents",
                "--app",
                "codex,claude,cursor",
            ])
            .output()
            .unwrap(),
    );
    assert_eq!(text(&regular), "Keep these user instructions.\n");
    assert_eq!(text(&claude), "Existing Claude instructions.\n");
    let installed = text(&over);
    assert!(installed.starts_with("These overrides win.\n"));
    success(s.run(&["setup", "agents", "--app", "codex,claude,cursor"]));
    assert_eq!(text(&over), installed);
    success(s.run(&["setup", "agents", "--app", "codex,claude,cursor", "--check"]));
    for _ in 0..2 {
        success(s.run(&[
            "setup",
            "agents",
            "--app",
            "codex,claude,cursor",
            "--remove",
        ]));
    }
    assert_eq!(text(&over), "These overrides win.\n");
    assert_eq!(text(&regular), "Keep these user instructions.\n");
    assert!(!s.user.join(".agents/skills/envholster/SKILL.md").exists());
    assert!(!s.user.join(".claude/rules/envholster.md").exists());
    assert!(!s.user.join(".config/envholster").exists());
}

#[test]
fn shared_skill_survives_removing_only_one_app() {
    let s = Scratch::new();
    success(s.run(&["setup", "agents", "--app", "codex,cursor"]));
    success(s.run(&["setup", "agents", "--app", "codex", "--remove"]));
    success(s.run(&["setup", "agents", "--app", "cursor", "--check"]));
    assert!(s.user.join(".agents/skills/envholster/SKILL.md").is_file());
    assert!(!s.user.join(".claude").exists());
    success(s.run(&["setup", "agents", "--app", "cursor", "--remove"]));
    assert!(!s.user.join(".agents/skills/envholster/SKILL.md").exists());
}

#[test]
fn noninteractive_onboarding_and_check_do_not_write() {
    let s = Scratch::new();
    success(s.run(&["setup"]));
    assert_eq!(
        s.run(&["setup", "agents", "--app", "codex,claude,cursor", "--check"])
            .status
            .code(),
        Some(7)
    );
    assert_eq!(fs::read_dir(&s.user).unwrap().count(), 0);
}

#[test]
fn conflict_preflight_refuses_symlinks_hardlinks_and_existing_skill_content() {
    for kind in 0..4 {
        let s = Scratch::new();
        let target = s.user.join(".claude/skills/envholster/SKILL.md");
        let outside = s.root.join("outside");
        put(&outside, "Preserve this file.\n");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        match kind {
            0 => put(&target, "User-owned skill.\n"),
            1 => symlink(&outside, &target).unwrap(),
            2 => fs::hard_link(&outside, &target).unwrap(),
            _ => {
                fs::remove_dir_all(s.user.join(".claude")).unwrap();
                let dir = s.root.join("dotfiles");
                fs::create_dir_all(&dir).unwrap();
                symlink(dir, s.user.join(".claude")).unwrap();
            }
        }
        assert!(!s
            .run(&["setup", "agents", "--app", "codex,claude"])
            .status
            .success());
        assert!(!s.user.join(".codex").exists());
        assert!(!s.user.join(".agents").exists());
        assert_eq!(text(&outside), "Preserve this file.\n");
    }
}

#[test]
fn custom_config_roots_and_detection_do_not_execute_agent_binaries() {
    let s = Scratch::new();
    let codex = s.root.join("custom codex");
    let claude = s.root.join("custom claude");
    fs::create_dir_all(&codex).unwrap();
    fs::create_dir_all(&claude).unwrap();
    let fake = s.root.join("bin");
    executable(
        &fake.join("cursor"),
        "#!/bin/sh\ntouch should-not-execute\nexit 99\n",
    );
    success(
        s.command(BIN)
            .args(["setup", "agents"])
            .env("CODEX_HOME", &codex)
            .env("CLAUDE_CONFIG_DIR", &claude)
            .env("PATH", &fake)
            .output()
            .unwrap(),
    );
    assert!(codex.join("AGENTS.md").is_file());
    assert!(claude.join("rules/envholster.md").is_file());
    assert!(!s.user.join(".codex").exists());
    assert!(!s.project.join("should-not-execute").exists());
    assert!(s
        .user
        .join(".agents/skills/envholster/.envholster-cursor")
        .is_file());
}

#[test]
fn project_requires_a_declared_explicit_environment_and_vault() {
    let s = Scratch::new();
    s.managed();
    assert!(!s
        .command(BIN)
        .args(["setup", "project"])
        .env("ENVHOLSTER_ENV", "production")
        .output()
        .unwrap()
        .status
        .success());
    assert!(!s
        .run(&["setup", "project", "--env", "staging"])
        .status
        .success());
    assert_eq!(
        s.run(&["setup", "project", "--check"]).status.code(),
        Some(7)
    );
    assert!(!s.project.join("AGENTS.md").exists());
    fs::remove_file(s.project.join("secrets.holster")).unwrap();
    assert!(!s
        .run(&["setup", "project", "--env", "base"])
        .status
        .success());
    assert!(!s.project.join("AGENTS.md").exists());
}

#[test]
fn project_preserves_overrides_permissions_and_unrelated_edits_when_removing() {
    let s = Scratch::new();
    s.managed();
    let agents = s.project.join("AGENTS.override.md");
    let claude = s.project.join("CLAUDE.md");
    put(&agents, "Project override.\n");
    put(&claude, "Project Claude rules.\n");
    fs::set_permissions(&agents, fs::Permissions::from_mode(0o640)).unwrap();
    success(s.run(&["setup", "project", "--env", "development"]));
    assert!(!s.project.join("AGENTS.md").exists());
    let installed = text(&agents);
    success(s.run(&["setup", "project"]));
    assert_eq!(text(&agents), installed);
    assert_eq!(
        fs::metadata(&agents).unwrap().permissions().mode() & 0o777,
        0o640
    );
    let nested = s.project.join("nested/app");
    fs::create_dir_all(&nested).unwrap();
    success(
        s.command(BIN)
            .current_dir(nested)
            .args(["setup", "project", "--check"])
            .output()
            .unwrap(),
    );
    put(&agents, &(installed + "\nLater user instruction.\n"));
    success(s.run(&["setup", "project", "--remove"]));
    success(s.run(&["setup", "project", "--remove"]));
    assert_eq!(
        text(&agents),
        "Project override.\n\nLater user instruction.\n"
    );
    assert_eq!(text(&claude), "Project Claude rules.\n");
    assert!(!s.project.join(".cursor/rules/envholster.mdc").exists());
}

#[test]
fn modified_managed_instructions_block_removal_before_any_edits() {
    let s = Scratch::new();
    s.managed();
    success(s.run(&["setup", "project", "--env", "base"]));
    let agents = s.project.join("AGENTS.md");
    let before = text(&agents);
    let claude = s.project.join("CLAUDE.md");
    put(&claude, &text(&claude).replace("names-only", "custom"));
    assert!(!s.run(&["setup", "project", "--remove"]).status.success());
    assert_eq!(text(&agents), before);
    assert!(s.project.join(".cursor/rules/envholster.mdc").exists());
}

#[test]
fn project_removal_recovers_if_one_instruction_file_was_deleted() {
    let s = Scratch::new();
    s.managed();
    success(s.run(&["setup", "project", "--env", "development"]));
    fs::remove_file(s.project.join("AGENTS.md")).unwrap();
    assert_eq!(
        s.run(&["setup", "project", "--check"]).status.code(),
        Some(7)
    );
    success(s.run(&["setup", "project", "--remove"]));
    assert!(!s.project.join("CLAUDE.md").exists());
}

#[test]
fn npm_conflicts_and_missing_runtime_leave_all_project_files_untouched() {
    for script in [
        "envholster run -- next dev",
        "echo ready && envholster run -- next dev",
    ] {
        let s = Scratch::new();
        s.managed();
        let package = format!("{{\"scripts\":{{\"dev\":\"{script}\"}}}}\n");
        s.package(&package);
        assert!(!s
            .run(&["setup", "project", "--env", "base", "--npm-script", "dev"])
            .status
            .success());
        assert_eq!(text(&s.project.join("package.json")), package);
        assert!(!s.project.join("AGENTS.md").exists());
    }
    let s = Scratch::new();
    s.managed();
    s.package("{\"scripts\":{\"dev\":\"next dev\"}}\n");
    assert!(!s
        .command(BIN)
        .env("PATH", "")
        .args(["setup", "project", "--env", "base", "--npm-script", "dev"])
        .output()
        .unwrap()
        .status
        .success());
    assert!(!s.project.join("AGENTS.md").exists());
}

#[test]
fn npm_script_restoration_preserves_other_package_edits_and_refuses_managed_changes() {
    let s = Scratch::new();
    s.managed();
    s.package("{\n  \"name\": \"before\",\n  \"scripts\": {\"dev\": \"next dev\", \"lint\": \"eslint .\"}\n}\n");
    success(s.run(&[
        "setup",
        "project",
        "--env",
        "development",
        "--npm-script",
        "dev",
    ]));
    let package = s.project.join("package.json");
    let installed = text(&package);
    success(s.run(&["setup", "project", "--npm-script", "dev"]));
    assert_eq!(text(&package), installed);
    put(&package, &installed.replace("\"before\"", "\"after\""));
    success(s.run(&["setup", "project", "--check"]));
    let valid = text(&package);
    put(
        &package,
        &valid.replace(
            "envholster --env development",
            "envholster --env production",
        ),
    );
    assert!(!s.run(&["setup", "project", "--remove"]).status.success());
    assert!(s.project.join("AGENTS.md").exists());
    put(&package, &valid);
    success(s.run(&["setup", "project", "--remove"]));
    success(s.command("node").args(["-e", "const p=require('./package.json');process.exit(p.name==='after' && p.scripts.dev==='next dev' && p.scripts.lint==='eslint .' && !p.envholsterSetup ? 0 : 1)"]).output().unwrap());
}

#[test]
fn npm_check_detects_lost_metadata_and_setup_can_add_another_selected_script() {
    let s = Scratch::new();
    s.managed();
    let original = "{\"scripts\":{\"dev\":\"next dev\",\"predev\":\"node prepare.cjs\"}}\n";
    s.package(original);
    success(s.run(&["setup", "project", "--env", "development"]));
    success(
        s.command(BIN)
            .args(["setup", "project", "--npm-script", "dev"])
            .env("NODE_OPTIONS", "--require=/does/not/exist")
            .output()
            .unwrap(),
    );
    success(s.run(&["setup", "project", "--npm-script", "predev"]));
    success(s.run(&["setup", "project", "--check"]));
    assert!(text(&s.project.join("AGENTS.md")).contains("Wrapped npm scripts: [dev,predev]"));
    let configured = text(&s.project.join("package.json"));
    s.package(original);
    assert!(!s.run(&["setup", "project", "--check"]).status.success());
    s.package(&configured);
    for path in ["AGENTS.md", "CLAUDE.md", ".cursor/rules/envholster.mdc"] {
        fs::remove_file(s.project.join(path)).unwrap();
    }
    success(s.run(&["setup", "project", "--remove"]));
    success(s.command("node").args(["-e", "const p=require('./package.json');process.exit(p.scripts.dev==='next dev' && p.scripts.predev==='node prepare.cjs' && !p.envholsterSetup ? 0 : 1)"]).output().unwrap());
}

#[test]
fn ordinary_npm_launch_injects_only_into_child_preserves_quoting_cwd_args_and_exit() {
    let s = Scratch::new();
    success(s.run(&["init"]));
    let manifest = s.project.join("envholster.toml");
    put(&manifest, &(text(&manifest) + "\n[environments]\nnames = [\"development\", \"production\"]\n[envs.development.vars]\nTEST_FLAVOR = \"development\"\n[envs.production.vars]\nTEST_FLAVOR = \"production\"\n"));
    let sentinel = format!(
        "synthetic-setup-value-{}",
        s.root.file_name().unwrap().to_string_lossy()
    );
    let mut set = s
        .command(BIN)
        .args([
            "--env",
            "development",
            "set",
            "SETUP_TEST_SECRET",
            "--stdin",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    set.stdin
        .take()
        .unwrap()
        .write_all(sentinel.as_bytes())
        .unwrap();
    success(set.wait_with_output().unwrap());
    s.package(r#"{"scripts":{"predev":"node hook.cjs","dev":"node -e \"process.exit(0)\" && node app.cjs 'fixed quoted'","postdev":"node hook.cjs"}}"#);
    put(
        &s.project.join("hook.cjs"),
        "if (process.env.SETUP_TEST_SECRET) process.exit(51);\n",
    );
    put(
        &s.project.join("app.cjs"),
        r#"
const fs = require('node:fs');
const args = process.argv.slice(2);
const expected = ['fixed quoted', 'space value', "quote'value", '$(touch escaped-argument)', '--flag'];
const ok = !!process.env.SETUP_TEST_SECRET && process.env.TEST_FLAVOR === 'development'
  && process.env.npm_lifecycle_event === 'dev'
  && fs.existsSync('envholster.toml') && !fs.existsSync('.env')
  && JSON.stringify(args) === JSON.stringify(expected);
process.exit(ok ? 0 : 41);
"#,
    );
    success(s.run(&[
        "setup",
        "project",
        "--env",
        "development",
        "--npm-script",
        "dev",
    ]));
    let path = format!(
        "{}:{}",
        Path::new(BIN).parent().unwrap().display(),
        std::env::var("PATH").unwrap()
    );
    let launch = || {
        let mut cmd = s.command("npm");
        cmd.env("PATH", &path)
            .env("ENVHOLSTER_ENV", "production")
            .args([
                "run",
                "dev",
                "--",
                "space value",
                "quote'value",
                "$(touch escaped-argument)",
                "--flag",
            ]);
        cmd
    };
    success(launch().output().unwrap());
    assert!(!s.project.join("escaped-argument").exists());
    assert!(!s.project.join(".env").exists());
    for file in ["package.json", "AGENTS.md", "CLAUDE.md", "envholster.toml"] {
        assert!(
            !text(&s.project.join(file)).contains(&sentinel),
            "secret leaked into setup output"
        );
    }
    put(&s.project.join("app.cjs"), "process.exit(23);\n");
    assert_eq!(launch().output().unwrap().status.code(), Some(23));
    fs::remove_file(s.project.join("secrets.holster")).unwrap();
    put(
        &s.project.join("app.cjs"),
        "require('node:fs').writeFileSync('should-not-run','');\n",
    );
    assert!(!launch().output().unwrap().status.success());
    assert!(!s.project.join("should-not-run").exists());
}

#[test]
fn source_installer_uses_locked_build_preserves_cwd_and_never_configures_after_failure() {
    for fail in [false, true] {
        let s = Scratch::new();
        let fake = s.root.join("tools");
        let install = s.root.join("install with spaces");
        executable(
            &fake.join("cargo"),
            r#"#!/bin/sh
printf '%s\n' "$PWD" "$@" > "$TEST_CARGO_TRACE"
[ "$TEST_FAIL" = no ] || exit 19
mkdir -p "$TEST_INSTALL_ROOT/bin"
cat > "$TEST_INSTALL_ROOT/bin/envholster" <<'SH'
#!/bin/sh
printf '%s\n' "$PWD" "$@" > "$TEST_SETUP_TRACE"
SH
chmod 700 "$TEST_INSTALL_ROOT/bin/envholster"
"#,
        );
        let cargo_trace = s.root.join("cargo.trace");
        let setup_trace = s.root.join("setup.trace");
        let installer = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/install.sh");
        let result = s
            .command("/bin/sh")
            .arg(installer)
            .arg("--root")
            .arg(&install)
            .args(["--agents", "codex,claude"])
            .env("PATH", format!("{}:/usr/bin:/bin", fake.display()))
            .env("TEST_CARGO_TRACE", &cargo_trace)
            .env("TEST_SETUP_TRACE", &setup_trace)
            .env("TEST_INSTALL_ROOT", &install)
            .env("TEST_FAIL", if fail { "yes" } else { "no" })
            .output()
            .unwrap();
        let trace = text(&cargo_trace);
        assert!(trace.lines().any(|line| line == "--locked"));
        assert!(trace.lines().any(|line| line == install.to_str().unwrap()));
        if fail {
            assert_eq!(result.status.code(), Some(19));
            assert!(!setup_trace.exists());
        } else {
            success(result);
            assert_eq!(
                text(&setup_trace),
                format!(
                    "{}\nsetup\nagents\n--app\ncodex,claude\n",
                    s.project.display()
                )
            );
        }
        assert_eq!(fs::read_dir(&s.user).unwrap().count(), 0);
    }
}
