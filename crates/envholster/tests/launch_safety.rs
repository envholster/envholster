//! Regressions for the six v1 launch-review findings. Fixtures are synthetic;
//! assertions intentionally report only outcomes, never secret-bearing output.
mod common;

use common::*;
use std::fs;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn put(sb: &Sandbox, file: &str, name: &str, value: &str) {
    fs::write(sb.project.join(file), format!("{name}={value}\n")).unwrap();
}

fn matches(sb: &Sandbox, env: &str, name: &str, expected: &str) -> bool {
    let result = sb.run(&["--env", env, "get", name], b"");
    result.success() && result.stdout == expected.as_bytes()
}

#[test]
fn capability_urls_require_encryption_and_plaintext_needs_review() {
    let sb = Sandbox::new("url-review");
    sb.init_vault();
    let token = sentinel("URL");
    for url in [
        format!("https://hooks.example.invalid/services/{token}"),
        format!("https://example.invalid/?credential={token}"),
        format!("https://example.invalid/#{token}"),
        format!("https://{token}@example.invalid"),
    ] {
        put(&sb, ".env", "SERVICE_URL", &url);
        assert!(sb.run(&["import", ".env"], b"n\nn\n").success());
        assert!(matches(&sb, "base", "SERVICE_URL", &url));
        assert!(!fs::read_to_string(sb.manifest_path())
            .unwrap()
            .contains(&token));
    }
    put(&sb, ".env", "PORT", "4100");
    let before = fs::read(sb.vault_path()).unwrap();
    assert!(!sb.run(&["import", ".env"], b"").success());
    assert!(fs::read(sb.vault_path()).unwrap() == before);
    assert!(sb.run(&["import", ".env"], b"\nn\nn\n").success());
    let manifest = fs::read_to_string(sb.manifest_path()).unwrap();
    assert!(manifest.contains("name = \"PORT\""));
    sb.cleanup();
}

/// Coding agents and scripts run import with stdin closed. The vault is saved
/// before the cleanup questions, so those take their defaults instead of
/// failing: the source file stays and the ignore rules are added.
#[test]
fn import_without_answers_keeps_the_source_and_succeeds() {
    let sb = Sandbox::new("no-answers");
    sb.init_vault();
    let token = sentinel("HEADLESS");
    put(&sb, ".env", "API_TOKEN", &token);
    assert!(
        sb.run(&["import", ".env", "--encrypt-all"], b"").success(),
        "import with closed stdin failed"
    );
    assert!(matches(&sb, "base", "API_TOKEN", &token));
    assert!(sb.project.join(".env").exists());
    let ignore = fs::read_to_string(sb.project.join(".gitignore")).unwrap();
    assert!(ignore.contains("*.envholster.lock"));
    sb.cleanup();
}

#[test]
fn chosen_identity_cannot_borrow_ambient_keys() {
    let sb = Sandbox::new("identity-exclusive");
    let init = sb.init_vault();
    let other = Sandbox::new("identity-other");
    other.generate_identity("unrelated");
    let value = sentinel("IDENTITY");
    assert!(sb
        .run(&["set", "REVIEW_KEY", "--stdin"], value.as_bytes())
        .success());
    let own = find_file_containing(&sb.home, "AGE-SECRET-KEY-1").unwrap();
    let wrong = find_file_containing(&other.home, "AGE-SECRET-KEY-1").unwrap();
    let result = sb.run(
        &["--identity", wrong.to_str().unwrap(), "get", "REVIEW_KEY"],
        b"",
    );
    assert!(!result.success());
    assert!(result.stdout.is_empty());
    let mut command = sb.command(&["--identity", own.to_str().unwrap(), "get", "REVIEW_KEY"]);
    command
        .env("ENVHOLSTER_IDENTITY", "malformed")
        .env("ENVHOLSTER_IDENTITY_FILE", sb.root.join("missing"));
    let result = run_with_timeout(command, b"", Duration::from_secs(10));
    assert!(result.success() && result.stdout == value.as_bytes());
    let mut command = sb.command(&["get", "REVIEW_KEY"]);
    command.env("ENVHOLSTER_IDENTITY_FILE", &wrong);
    assert!(!run_with_timeout(command, b"", Duration::from_secs(10)).success());
    let mut command = sb.command(&["get", "REVIEW_KEY"]);
    command
        .env("ENVHOLSTER_IDENTITY", fs::read_to_string(&own).unwrap())
        .env("ENVHOLSTER_IDENTITY_FILE", &wrong);
    let result = run_with_timeout(command, b"", Duration::from_secs(10));
    assert!(result.success() && result.stdout == value.as_bytes());
    let multi = sb.root.join("multiple.identities");
    fs::write(
        &multi,
        format!(
            "{}\n{}",
            fs::read_to_string(&wrong).unwrap(),
            fs::read_to_string(&init.recovery_identity).unwrap()
        ),
    )
    .unwrap();
    assert!(sb
        .run(
            &["--identity", multi.to_str().unwrap(), "recovery", "verify"],
            b""
        )
        .success());
    sb.cleanup();
    other.cleanup();
}

#[test]
fn nextjs_precedence_test_exclusion_and_missing_modes() {
    let sb = Sandbox::new("nextjs-profile");
    sb.init_vault();
    let base = sentinel("BASE");
    let local = sentinel("LOCAL");
    let mode = sentinel("MODE");
    let mode_local = sentinel("MODELOCAL");
    put(&sb, ".env", "REVIEW_KEY", &base);
    put(&sb, ".env.local", "REVIEW_KEY", &local);
    put(&sb, ".env.production", "REVIEW_KEY", &mode);
    put(&sb, ".env.development.local", "REVIEW_KEY", &mode_local);
    let before = fs::read(sb.vault_path()).unwrap();
    assert!(!sb
        .run(&["import", ".env", "--encrypt-all"], b"y\n")
        .success());
    assert!(fs::read(sb.vault_path()).unwrap() == before);
    assert!(sb
        .run(
            &["import", ".env", "--profile", "nextjs", "--encrypt-all"],
            "y\n".repeat(12).as_bytes()
        )
        .success());
    assert!(matches(&sb, "base", "REVIEW_KEY", &base));
    assert!(matches(&sb, "development", "REVIEW_KEY", &mode_local));
    assert!(matches(&sb, "production", "REVIEW_KEY", &local));
    assert!(matches(&sb, "test", "REVIEW_KEY", &base));
    assert!(!sb.project.join(".env.development.local").exists());
    assert!(!sb.project.join(".env.local").exists());
    sb.cleanup();
}

#[test]
fn vite_custom_modes_and_profile_without_base_file() {
    let sb = Sandbox::new("vite-profile");
    sb.init_vault();
    let local = sentinel("LOCAL");
    let mode = sentinel("MODE");
    let mode_local = sentinel("MODELOCAL");
    put(&sb, ".env.local", "REVIEW_KEY", &local);
    put(&sb, ".env.staging", "REVIEW_KEY", &mode);
    put(&sb, ".env.staging.local", "REVIEW_KEY", &mode_local);
    assert!(!sb
        .run(&["import", ".env.local", "--profile", "vite"], b"")
        .success());
    assert!(sb
        .run(
            &["import", ".env", "--profile", "vite", "--encrypt-all"],
            "n\n".repeat(10).as_bytes()
        )
        .success());
    assert!(matches(&sb, "staging", "REVIEW_KEY", &mode_local));
    assert!(matches(&sb, "production", "REVIEW_KEY", &local));
    assert!(matches(&sb, "development", "REVIEW_KEY", &local));
    sb.cleanup();
}

#[test]
fn encryption_preserves_overrides_and_removes_old_plaintext() {
    let sb = Sandbox::new("classification-layers");
    sb.init_vault();
    let base = format!("https://example.invalid/{}", sentinel("CAPABILITY"));
    let selected = "dev.example.invalid";
    put(&sb, ".env", "SERVICE_HOST", &base);
    put(&sb, ".env.development", "SERVICE_HOST", selected);
    assert!(sb
        .run(
            &["import", ".env", "--profile", "nextjs"],
            "y\n".repeat(10).as_bytes()
        )
        .success());
    assert!(matches(&sb, "development", "SERVICE_HOST", selected));
    put(&sb, ".env", "PUBLIC_HOST", "public.example.invalid");
    assert!(sb.run(&["import", ".env"], b"y\nn\nn\n").success());
    assert!(fs::read_to_string(sb.manifest_path())
        .unwrap()
        .contains("public.example.invalid"));
    assert!(sb
        .run(&["import", ".env", "--encrypt-all"], b"n\nn\n")
        .success());
    assert!(!fs::read_to_string(sb.manifest_path())
        .unwrap()
        .contains("public.example.invalid"));
    assert!(matches(
        &sb,
        "base",
        "PUBLIC_HOST",
        "public.example.invalid"
    ));
    // Later files win even when the earlier value looks secret and the later
    // value is classified as configuration before the bulk encryption choice.
    put(&sb, ".env", "ANOTHER_HOST", &base);
    put(&sb, ".env.local", "ANOTHER_HOST", selected);
    assert!(sb
        .run(&["import", ".env", "--encrypt-all"], b"n\nn\nn\n")
        .success());
    assert!(matches(&sb, "base", "ANOTHER_HOST", selected));
    sb.cleanup();
}

fn plan_digest(sb: &Sandbox, args: &[&str]) -> String {
    let result = sb.run(args, b"");
    assert!(result.success());
    result
        .stdout_str()
        .lines()
        .find_map(|line| line.strip_prefix("plan "))
        .unwrap()
        .to_owned()
}

#[test]
fn reviewed_apply_enforces_cross_environment_decisions_and_profile_digest() {
    let sb = Sandbox::new("apply-profile");
    sb.init_vault();
    put(
        &sb,
        ".env",
        "SERVICE_HOST",
        &format!("https://example.invalid/{}", sentinel("BASE")),
    );
    put(
        &sb,
        ".env.development",
        "SERVICE_HOST",
        "dev.example.invalid",
    );
    let digest = plan_digest(&sb, &["import", ".env", "--profile", "nextjs", "--plan"]);
    let decisions = format!("version 1\nplan {digest}\ncleanup delete_sources=no gitignore=no\ndecide .env SERVICE_HOST secret 1\ndecide .env.development SERVICE_HOST var\n");
    fs::write(sb.project.join("decisions.txt"), &decisions).unwrap();
    let before = fs::read(sb.vault_path()).unwrap();
    assert!(!sb
        .run(
            &[
                "import",
                ".env",
                "--profile",
                "nextjs",
                "--apply",
                "decisions.txt"
            ],
            b""
        )
        .success());
    assert!(fs::read(sb.vault_path()).unwrap() == before);
    fs::write(
        sb.project.join("decisions.txt"),
        decisions.replace("SERVICE_HOST var", "SERVICE_HOST secret 1"),
    )
    .unwrap();
    put(&sb, ".env.local", "OTHER_HOST", "other.example.invalid");
    assert!(!sb
        .run(
            &[
                "import",
                ".env",
                "--profile",
                "nextjs",
                "--apply",
                "decisions.txt"
            ],
            b""
        )
        .success());
    fs::remove_file(sb.project.join(".env.local")).unwrap();
    assert!(sb
        .run(
            &[
                "import",
                ".env",
                "--profile",
                "nextjs",
                "--apply",
                "decisions.txt"
            ],
            b""
        )
        .success());
    assert!(matches(
        &sb,
        "development",
        "SERVICE_HOST",
        "dev.example.invalid"
    ));
    sb.cleanup();
}

fn age_transform(args: &[&str], input: &[u8]) -> Vec<u8> {
    let age = find_age().expect("recovery regression requires the standalone age CLI");
    let mut child = Command::new(age)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "standalone age operation failed");
    output.stdout
}

#[test]
fn recovery_rejects_forged_contents_even_with_matching_generation_and_uuid() {
    let sb = Sandbox::new("recovery-contents");
    let init = sb.init_vault();
    let value = sentinel("RECOVERY");
    assert!(sb
        .run(&["set", "REVIEW_KEY", "--stdin"], value.as_bytes())
        .success());
    let vault = sb.read_vault();
    let recovery = vault.recovery_recipients()[0];
    let original = fs::read(sb.recovery_blob_path()).unwrap();
    let plain = age_transform(
        &["-d", "-i", init.recovery_identity.to_str().unwrap()],
        &original,
    );
    let plain = String::from_utf8(plain).unwrap();
    let verify = || {
        sb.run(
            &[
                "--identity",
                init.recovery_identity.to_str().unwrap(),
                "recovery",
                "verify",
            ],
            b"",
        )
        .success()
    };
    assert!(verify());
    let suffix = plain.rfind(",\"generation\":").unwrap();
    let empty = format!("{{\"envs\":{{}}{}", &plain[suffix..]);
    for forged in [
        empty,
        plain.replacen(
            &base64_encode(value.as_bytes()),
            &base64_encode(sentinel("FORGED").as_bytes()),
            1,
        ),
        plain.replacen("\"metadata\":{}", "\"metadata\":{\"extra\":\"changed\"}", 1),
        plain.replacen("\"schema\":1", "\"schema\":2", 1),
    ] {
        let encrypted = age_transform(
            &["-a", "-r", recovery.encoding.as_deref().unwrap()],
            forged.as_bytes(),
        );
        fs::write(sb.recovery_blob_path(), encrypted).unwrap();
        assert!(!verify(), "forged backup accepted");
    }
    // An authentic store encrypted only to the machine key is not recovery.
    fs::write(
        sb.recovery_blob_path(),
        age_transform(&["-a", "-r", &init.machine_recipient], plain.as_bytes()),
    )
    .unwrap();
    assert!(!verify());
    fs::write(sb.recovery_blob_path(), original).unwrap();
    assert!(verify());
    sb.cleanup();
}

struct Job {
    child: Child,
    group: Option<i32>,
}
impl Drop for Job {
    fn drop(&mut self) {
        if let Some(group) = self.group {
            envholster_mem::process::ProcessSignals::abort_child(group);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(Instant::now() < deadline, "child did not become ready");
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn job(sb: &Sandbox, dotenv: bool) -> Job {
    let mut args = vec!["run"];
    if dotenv {
        args.push("--dotenv");
    }
    // The shell creates a redirect target before writing to it, so a reader
    // that only waits for the file can see it empty; rename makes it appear
    // complete.
    args.extend([
        "--",
        "/bin/sh",
        "-c",
        "echo $$ > child.pid.tmp && mv child.pid.tmp child.pid; exec sleep 60",
    ]);
    let mut command = sb.command(&args);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    let mut job = Job {
        child: command.spawn().unwrap(),
        group: None,
    };
    wait_for(&sb.project.join("child.pid"));
    job.group = Some(
        fs::read_to_string(sb.project.join("child.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap(),
    );
    job
}
fn signal(pid: u32, signal: i32) {
    assert!(Command::new("/bin/kill")
        .arg(format!("-{signal}"))
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success());
}
fn wait_exit(job: &mut Job) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = job.child.try_wait().unwrap() {
            job.group = None;
            return status.code().unwrap_or(-1);
        }
        assert!(Instant::now() < deadline, "supervisor failed to exit");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn running_apps_release_vault_and_dotenv_path_has_one_owner() {
    let sb = Sandbox::new("run-concurrency");
    sb.init_vault();
    let value = sentinel("CONCURRENCY");
    assert!(sb
        .run(&["set", "REVIEW_KEY", "--stdin"], value.as_bytes())
        .success());
    fs::write(sb.project.join(".gitignore"), ".env*\n").unwrap();
    let mut running = job(&sb, true);
    let live_file = fs::read(sb.project.join(".env")).unwrap();
    assert!(matches(&sb, "base", "REVIEW_KEY", &value));
    assert!(sb
        .run(
            &["set", "ANOTHER_KEY", "--stdin"],
            sentinel("SECOND").as_bytes()
        )
        .success());
    assert!(sb.run(&["run", "--", "/usr/bin/true"], b"").success());
    assert!(!sb
        .run(&["run", "--dotenv", "--", "/usr/bin/true"], b"")
        .success());
    assert!(fs::read(sb.project.join(".env")).unwrap() == live_file);
    signal(running.child.id(), 15);
    assert_eq!(wait_exit(&mut running), 143);
    assert!(!sb.project.join(".env").exists());
    drop(running);
    sb.cleanup();
}

#[test]
fn normal_signals_remove_plaintext_and_restore_breadcrumb() {
    for sig in [2, 15, 1, 3] {
        let sb = Sandbox::new("signal-cleanup");
        sb.init_vault();
        put(&sb, ".env", "REVIEW_KEY", &sentinel("SIGNAL"));
        assert!(sb
            .run(&["import", ".env", "--encrypt-all"], b"y\ny\n")
            .success());
        let breadcrumb = fs::read(sb.project.join(".env")).unwrap();
        let mut running = job(&sb, true);
        signal(running.child.id(), sig);
        assert_eq!(wait_exit(&mut running), 128 + sig);
        assert!(fs::read(sb.project.join(".env")).unwrap() == breadcrumb);
        drop(running);
        sb.cleanup();
    }
}

#[test]
fn failed_spawn_cleans_dotenv_before_returning() {
    let sb = Sandbox::new("spawn-cleanup");
    sb.init_vault();
    fs::write(sb.project.join(".gitignore"), ".env*\n").unwrap();
    assert!(!sb
        .run(&["run", "--dotenv", "--", "/not/an/executable"], b"")
        .success());
    assert!(!sb.project.join(".env").exists());
    sb.cleanup();
}

#[test]
fn positional_mode_files_require_their_own_mapping_or_matching_environment() {
    for file in [
        ".env.production",
        ".env.production.local",
        "config/.env.production.local",
    ] {
        let sb = Sandbox::new("positional-mode");
        sb.init_vault();
        fs::create_dir_all(sb.project.join("config")).unwrap();
        let value = sentinel("PRODUCTION");
        put(&sb, file, "PRODUCTION_KEY", &value);
        put(&sb, ".env.other", "OTHER_KEY", &sentinel("OTHER"));
        let vault_before = fs::read(sb.vault_path()).unwrap();
        let manifest_before = fs::read(sb.manifest_path()).unwrap();
        for args in [
            vec!["import", file, "--encrypt-all"],
            vec!["import", file, "--plan"],
            vec!["import", file, "--apply", "missing-decisions.txt"],
            vec!["import", file, "--map", ".env.other=production"],
            vec!["--env", "development", "import", file, "--encrypt-all"],
        ] {
            let result = sb.run(&args, b"n\nn\n");
            assert!(!result.success(), "ambiguous positional mode accepted");
            assert!(result.stderr_str().contains("mode-specific"));
            assert!(fs::read(sb.vault_path()).unwrap() == vault_before);
            assert!(fs::read(sb.manifest_path()).unwrap() == manifest_before);
            assert!(sb.project.join(file).exists());
        }
        assert!(sb
            .run(
                &["--env", "production", "import", file, "--encrypt-all"],
                b"n\nn\n"
            )
            .success());
        assert!(matches(&sb, "production", "PRODUCTION_KEY", &value));
        assert!(!sb.run(&["get", "PRODUCTION_KEY"], b"").success());
        sb.cleanup();
    }
}

#[test]
fn explicit_positional_mapping_is_shared_by_plan_and_apply() {
    let sb = Sandbox::new("positional-mapped");
    sb.init_vault();
    let value = sentinel("MAPPED");
    put(&sb, ".env.production.local", "PRODUCTION_KEY", &value);
    let mapping = ".env.production.local=prod";
    let digest = plan_digest(
        &sb,
        &[
            "import",
            ".env.production.local",
            "--map",
            mapping,
            "--plan",
        ],
    );
    fs::write(sb.project.join("decisions.txt"), format!("version 1\nplan {digest}\ncleanup delete_sources=no gitignore=no\ndecide .env.production.local PRODUCTION_KEY secret 1\n")).unwrap();
    assert!(sb
        .run(
            &[
                "import",
                ".env.production.local",
                "--map",
                mapping,
                "--apply",
                "decisions.txt"
            ],
            b""
        )
        .success());
    assert!(matches(&sb, "prod", "PRODUCTION_KEY", &value));
    assert!(!sb.run(&["get", "PRODUCTION_KEY"], b"").success());
    sb.cleanup();
}

#[test]
fn missing_identity_file_names_the_selected_environment_variable() {
    let sb = Sandbox::new("identity-attribution");
    sb.init_vault();
    let mut command = sb.command(&["get", "KEY"]);
    command.env("ENVHOLSTER_IDENTITY_FILE", sb.root.join("missing.identity"));
    let result = run_with_timeout(command, b"", Duration::from_secs(10));
    assert!(!result.success());
    assert!(result.stderr_str().contains("ENVHOLSTER_IDENTITY_FILE"));
    sb.cleanup();
}

#[test]
fn refused_dotenv_destinations_leave_no_lock_sidecar() {
    let sb = Sandbox::new("dotenv-preflight");
    sb.init_vault();
    fs::write(sb.project.join(".gitignore"), "").unwrap();
    let before = walk_files(&sb.project);
    assert!(!sb
        .run(&["run", "--dotenv", "--", "/usr/bin/true"], b"")
        .success());
    assert!(walk_files(&sb.project) == before);
    fs::write(sb.project.join(".gitignore"), ".env*\n").unwrap();
    put(&sb, ".env", "EXISTING_KEY", &sentinel("EXISTING"));
    let existing = fs::read(sb.project.join(".env")).unwrap();
    assert!(!sb
        .run(&["run", "--dotenv", "--", "/usr/bin/true"], b"")
        .success());
    assert!(fs::read(sb.project.join(".env")).unwrap() == existing);
    assert!(!sb.project.join(".env.envholster.lock").exists());
    sb.cleanup();
}

#[test]
fn import_ignore_rules_cover_custom_dotenv_lock_sidecars() {
    let sb = Sandbox::new("custom-dotenv-lock");
    sb.init_vault();
    put(&sb, ".env", "KEY", &sentinel("CUSTOM"));
    fs::write(
        sb.project.join(".gitignore"),
        "*.env\nenvholster.local.toml\n",
    )
    .unwrap();
    assert!(sb
        .run(&["import", ".env", "--encrypt-all"], b"y\ny\n")
        .success());
    assert!(fs::read_to_string(sb.project.join(".gitignore"))
        .unwrap()
        .contains("*.envholster.lock"));
    fs::create_dir_all(sb.project.join("config")).unwrap();
    let result = sb.run(
        &["run", "--dotenv", "config/app.env", "--", "/usr/bin/true"],
        b"",
    );
    assert!(result.success());
    assert!(!result.stderr_str().contains("add '*.envholster.lock'"));
    assert!(!sb.project.join("config/app.env").exists());
    assert_eq!(
        fs::metadata(sb.project.join("config/app.env.envholster.lock"))
            .unwrap()
            .len(),
        0
    );
    sb.cleanup();
}

#[test]
fn ordinary_local_sibling_uses_the_explicit_import_environment() {
    let sb = Sandbox::new("local-selected-env");
    sb.init_vault();
    put(&sb, ".env", "SELECTED_KEY", &sentinel("BASEFILE"));
    let selected = sentinel("LOCALFILE");
    put(&sb, ".env.local", "SELECTED_KEY", &selected);
    assert!(sb
        .run(
            &["--env", "development", "import", ".env", "--encrypt-all"],
            b"n\nn\nn\n"
        )
        .success());
    assert!(matches(&sb, "development", "SELECTED_KEY", &selected));
    assert!(!sb.run(&["get", "SELECTED_KEY"], b"").success());
    sb.cleanup();
}

fn git(sb: &Sandbox, args: &[&str]) -> bool {
    Command::new("git")
        .args(args)
        .current_dir(&sb.project)
        .env("HOME", &sb.home)
        .env("XDG_CONFIG_HOME", sb.home.join(".config"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// `.env` and `*.env` do not ignore `.env.production`, and a later
/// `!.env.production` revokes `.env*`; a cleanup that scanned for rule
/// spellings instead of asking per imported file left the credentials
/// committable. Exercised with git answering and with the no-git fallback.
#[test]
fn gitignore_cleanup_covers_every_selected_source() {
    for use_git in [false, true] {
        for existing in [".env\n", "*.env\n", ".env*\n!.env.production\n"] {
            let sb = Sandbox::new("gitignore-coverage");
            sb.init_vault();
            if use_git {
                assert!(git(&sb, &["init", "-q"]));
            }
            put(
                &sb,
                ".env.production",
                "PRODUCTION_KEY",
                &sentinel("PRODUCTION"),
            );
            fs::write(sb.project.join(".gitignore"), existing).unwrap();
            // Keep the file, accept the ignore offer.
            assert!(sb
                .run(
                    &[
                        "--env",
                        "production",
                        "import",
                        ".env.production",
                        "--encrypt-all"
                    ],
                    b"n\ny\n"
                )
                .success());
            let rules = fs::read_to_string(sb.project.join(".gitignore")).unwrap();
            assert!(
                rules[existing.len()..].lines().any(|line| line == ".env*"),
                "{rules}"
            );
            if use_git {
                assert!(git(&sb, &["check-ignore", "-q", ".env.production"]));
            }
            // Coverage that already holds is not offered again: stdin carries
            // only the delete answer, so a second prompt would fail the import.
            put(
                &sb,
                ".env.production.local",
                "PRODUCTION_KEY",
                &sentinel("LOCAL"),
            );
            assert!(sb
                .run(
                    &[
                        "--env",
                        "production",
                        "import",
                        ".env.production.local",
                        "--encrypt-all"
                    ],
                    b"n\n"
                )
                .success());
            assert_eq!(
                fs::read_to_string(sb.project.join(".gitignore")).unwrap(),
                rules
            );
            sb.cleanup();
        }
    }
}

#[test]
fn apply_gitignore_cleanup_covers_every_selected_source() {
    let sb = Sandbox::new("gitignore-apply-coverage");
    sb.init_vault();
    put(
        &sb,
        ".env.production",
        "PRODUCTION_KEY",
        &sentinel("PRODUCTION"),
    );
    fs::write(sb.project.join(".gitignore"), "*.env\n").unwrap();
    let digest = plan_digest(
        &sb,
        &["--env", "production", "import", ".env.production", "--plan"],
    );
    fs::write(
        sb.project.join("decisions.txt"),
        format!("version 1\nplan {digest}\ncleanup delete_sources=no gitignore=yes\ndecide .env.production PRODUCTION_KEY secret 1\n"),
    )
    .unwrap();
    assert!(sb
        .run(
            &[
                "--env",
                "production",
                "import",
                ".env.production",
                "--apply",
                "decisions.txt"
            ],
            b""
        )
        .success());
    let rules = fs::read_to_string(sb.project.join(".gitignore")).unwrap();
    assert!(
        rules["*.env\n".len()..].lines().any(|line| line == ".env*"),
        "{rules}"
    );
    assert!(sb.project.join(".env.production").exists());
    sb.cleanup();
}

/// Appending `.env*` to the root `.gitignore` is not proof the file is safe:
/// git resolves ignore rules per directory, so a nested `.gitignore` carrying
/// `!.env.production` still wins, and no rule at all applies to a tracked
/// file. Cleanup must ask git again after writing and say so by name instead
/// of reporting a bare "updated".
#[test]
fn gitignore_cleanup_warns_when_a_source_stays_committable() {
    // Nested negation, interactive offer.
    let sb = Sandbox::new("gitignore-nested-negation");
    sb.init_vault();
    assert!(git(&sb, &["init", "-q"]));
    fs::create_dir_all(sb.project.join("app")).unwrap();
    fs::write(sb.project.join("app/.gitignore"), "!.env.production\n").unwrap();
    fs::write(sb.project.join(".gitignore"), "*.env\n").unwrap();
    put(
        &sb,
        "app/.env.production",
        "PRODUCTION_KEY",
        &sentinel("NESTED"),
    );
    let result = sb.run(
        &[
            "--env",
            "production",
            "import",
            "app/.env.production",
            "--encrypt-all",
        ],
        b"n\ny\n",
    );
    assert!(result.success(), "{}", result.combined());
    let rules = fs::read_to_string(sb.project.join(".gitignore")).unwrap();
    assert!(rules.lines().any(|line| line == ".env*"), "{rules}");
    assert!(!git(&sb, &["check-ignore", "-q", "app/.env.production"]));
    let stderr = result.stderr_str();
    assert!(
        stderr.contains("still does not ignore app/.env.production"),
        "{stderr}"
    );
    sb.cleanup();

    // Tracked file, interactive offer.
    let sb = Sandbox::new("gitignore-tracked");
    sb.init_vault();
    assert!(git(&sb, &["init", "-q"]));
    put(
        &sb,
        ".env.production",
        "PRODUCTION_KEY",
        &sentinel("TRACKED"),
    );
    assert!(git(&sb, &["add", "-f", ".env.production"]));
    let result = sb.run(
        &[
            "--env",
            "production",
            "import",
            ".env.production",
            "--encrypt-all",
        ],
        b"n\ny\n",
    );
    assert!(result.success(), "{}", result.combined());
    let stderr = result.stderr_str();
    assert!(stderr.contains("git tracks .env.production"), "{stderr}");
    assert!(
        stderr.contains("git rm --cached .env.production"),
        "{stderr}"
    );
    sb.cleanup();

    // Tracked file, `--apply --json`: the machine-readable result names it.
    let sb = Sandbox::new("gitignore-tracked-apply");
    sb.init_vault();
    assert!(git(&sb, &["init", "-q"]));
    put(
        &sb,
        ".env.production",
        "PRODUCTION_KEY",
        &sentinel("TRACKEDAPPLY"),
    );
    assert!(git(&sb, &["add", "-f", ".env.production"]));
    let digest = plan_digest(
        &sb,
        &["--env", "production", "import", ".env.production", "--plan"],
    );
    fs::write(
        sb.project.join("decisions.txt"),
        format!("version 1\nplan {digest}\ncleanup delete_sources=no gitignore=yes\ndecide .env.production PRODUCTION_KEY secret 1\n"),
    )
    .unwrap();
    let result = sb.run(
        &[
            "--env",
            "production",
            "import",
            ".env.production",
            "--apply",
            "decisions.txt",
            "--json",
        ],
        b"",
    );
    assert!(result.success(), "{}", result.combined());
    let stdout = result.stdout_str();
    assert!(stdout.contains("\"gitignore_updated\":true"), "{stdout}");
    assert!(
        stdout.contains("\"uncovered_sources\":[\".env.production\"]"),
        "{stdout}"
    );
    assert!(
        result.stderr_str().contains("git tracks .env.production"),
        "{}",
        result.stderr_str()
    );
    sb.cleanup();
}
