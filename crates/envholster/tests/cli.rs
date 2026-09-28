//! Black-box end-to-end suite for the `envholster` binary (ported from the
//! earlier daemon-era `envholster-e2e` crate, adapted to
//! the single-binary command tree: `set` replaces add/edit, `recovery
//! create|verify` replaces the init ceremony and `recovery test`).
//!
//! Tests exercise the built binary via `std::process::Command` in a fresh
//! HOME/TMPDIR/project sandbox under `std::env::temp_dir()`. std only.

#![forbid(unsafe_code)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

use common::*;

// ===========================================================================
// Suite 1 — Lifecycle: init → set → list → get → set → rm → status
// ===========================================================================

#[test]
fn lifecycle_init_set_list_get_rm_status() {
    let sb = Sandbox::new("lifecycle");
    let init = sb.init_vault();

    // The sentinel round-trip proof belongs to `recovery create`
    // (RECOVERY-SPEC §5.4) and must be observable in its output.
    let init_lower = init.output.to_lowercase();
    assert!(
        init_lower.contains("sentinel")
            || init_lower.contains("round-trip")
            || init_lower.contains("round trip"),
        "recovery create must surface the sentinel round-trip proof (RECOVERY-SPEC §5.4)\n\
         --- output ---\n{}",
        init.output
    );
    // The parked recovery identity is gone once the kit exists.
    assert!(
        find_file_containing(&sb.home, "AGE-SECRET-KEY-1")
            .into_iter()
            .chain(walk_files(
                &sb.home.join(".config").join("envholster").join("recovery")
            ))
            .all(|p| !p.to_string_lossy().contains("/recovery/")),
        "recovery create must delete the parked identity under ~/.config/envholster/recovery"
    );

    // File permissions (ENVELOPE-SPEC §1: vault + recovery blob 0600).
    assert_eq!(unix_mode(&sb.vault_path()), 0o600);
    assert_eq!(unix_mode(&sb.recovery_blob_path()), 0o600);
    let ident = find_file_containing(&sb.home, "AGE-SECRET-KEY-1")
        .expect("identity generate must have written an identity file under HOME");
    assert_eq!(unix_mode(&ident), 0o600, "{}", ident.display());

    // init wires the plaintext-dotenv rules into .gitignore.
    let gitignore = fs::read_to_string(sb.project.join(".gitignore")).unwrap();
    assert!(gitignore.lines().any(|l| l.trim() == ".env"), "{gitignore}");

    // set — value via stdin, never argv.
    let v1 = sentinel("LC1");
    let r_set = sb.run(&["set", "SVC_TOKEN", "--stdin"], v1.as_bytes());
    r_set.assert_success("set SVC_TOKEN");
    assert!(!r_set.combined().contains(&v1), "`set` echoed the value");

    let r_list = sb.run(&["list"], b"");
    r_list.assert_success("list");
    let list_out = r_list.combined();
    assert!(list_out.contains("SVC_TOKEN"), "{list_out}");
    assert!(!list_out.contains(&v1), "list leaked a value:\n{list_out}");
    assert!(
        list_out.contains("NAME\tENV\tTIER\tKEY\tSTATUS"),
        "list prints the plain column header\n{list_out}"
    );

    let r_get = sb.run(&["get", "SVC_TOKEN"], b"");
    r_get.assert_success("get SVC_TOKEN");
    let got = r_get.stdout_str();
    assert!(got == v1 || got == format!("{v1}\n"), "got {got:?}");

    // set again — updates in place.
    let v2 = sentinel("LC2");
    sb.run(&["set", "SVC_TOKEN", "--stdin"], v2.as_bytes())
        .assert_success("set (update) SVC_TOKEN");
    let got2 = sb.run(&["get", "SVC_TOKEN"], b"").stdout_str();
    assert!(got2 == v2 || got2 == format!("{v2}\n"), "got {got2:?}");

    // Generation: init=1, +1 per save (set, set) ⇒ 3 (ENVELOPE-SPEC §9).
    assert_eq!(sb.read_vault().generation, 3);

    sb.run(&["rm", "SVC_TOKEN"], b"")
        .assert_success("rm SVC_TOKEN");
    let r_gone = sb.run(&["get", "SVC_TOKEN"], b"");
    r_gone.assert_failure("get of a removed secret");
    assert!(!r_gone.stderr.is_empty());
    assert!(!sb.run(&["list"], b"").combined().contains("SVC_TOKEN"));

    let st = sb.run(&["status"], b"").assert_success("status").combined();
    assert!(
        !st.contains(&v1) && !st.contains(&v2),
        "status leaked a value:\n{st}"
    );
    assert_eq!(sb.read_vault().generation, 4);

    // A verified kit: doctor has nothing to complain about.
    let r_doc = sb.run(&["doctor"], b"");
    assert!(
        r_doc.success(),
        "doctor must pass on a fresh project with a created kit:\n{}",
        r_doc.combined()
    );

    sb.cleanup();
}

// ===========================================================================
// Suite 2 — Sentinel no-plaintext harness (flagship gate)
// ===========================================================================

#[test]
fn sentinel_plaintext_never_touches_disk_or_output() {
    let sb = Sandbox::new("sentinel");
    sb.init_vault();

    let s1 = sentinel("NP1");
    let s2 = sentinel("NP2");

    let r_add = sb.run(&["set", "SENTRY_SECRET", "--stdin"], s1.as_bytes());
    r_add.assert_success("set sentinel secret");
    assert!(!r_add.combined().contains(&s1));
    let r_edit = sb.run(&["set", "SENTRY_SECRET", "--stdin"], s2.as_bytes());
    r_edit.assert_success("set (update) sentinel secret");
    assert!(!r_edit.combined().contains(&s1) && !r_edit.combined().contains(&s2));

    for args in [&["list"][..], &["status"][..], &["doctor"][..]] {
        let r = sb.run(args, b"");
        let out = r.combined();
        assert!(
            !out.contains(&s1) && !out.contains(&s2),
            "{args:?} output contains the sentinel:\n{out}"
        );
    }

    let needles: Vec<String> = vec![
        s1.clone(),
        s2.clone(),
        base64_encode(s1.as_bytes()),
        base64_encode(s2.as_bytes()),
    ];
    let needle_refs: Vec<&str> = needles.iter().map(String::as_str).collect();
    let hits = scan_tree_for(&sb.root, &needle_refs);
    assert!(
        hits.is_empty(),
        "sentinel plaintext found on disk:\n{}",
        hits.join("\n")
    );
    let files = walk_files(&sb.root);
    assert!(files.contains(&sb.vault_path()));
    assert!(files.contains(&sb.recovery_blob_path()));

    let got = sb.run(&["get", "SENTRY_SECRET"], b"").stdout_str();
    assert!(got == s2 || got == format!("{s2}\n"));

    sb.cleanup();
}

// ===========================================================================
// Suite 3 — Import / export: the .env replacement loop
// ===========================================================================

#[test]
fn import_export_semantic_roundtrip() {
    let sb = Sandbox::new("import");
    sb.init_vault();

    let sec_api = sentinel("IMP-API");
    let sec_db = sentinel("IMP-DB");
    let sec_tok = sentinel("IMP-TOK");
    let sec_prod = sentinel("IMP-PROD");

    let dotenv = format!(
        "# service config\nPORT=3000\nLOG_LEVEL=debug\nNEXT_PUBLIC_API_URL=https://api.example.com\n\nAPI_KEY={sec_api}\nexport DATABASE_URL=\"postgres://app:{sec_db}@db.internal:5432/app\"\nSECRET_TOKEN='{sec_tok}'\n"
    );
    let dotenv_prod = format!("LOG_LEVEL=warn\nCACHE_TTL=60\nPROD_SECRET={sec_prod}\n");
    fs::write(sb.project.join(".env"), &dotenv).unwrap();
    fs::write(sb.project.join(".env.production"), &dotenv_prod).unwrap();

    let expected_base = parse_dotenv(&dotenv);
    let expected_prod_layer = parse_dotenv(&dotenv_prod);

    // No hardware recipient: secrets store at tier 1 without a tier prompt.
    // The post-import cleanup prompts (delete offers, .gitignore) take `y`.
    let script = "y\n".repeat(8);
    let r_imp = sb.run(
        &["import", ".env", "--map", ".env.production=prod"],
        script.as_bytes(),
    );
    r_imp.assert_success("import .env --map .env.production=prod");
    let imp_out = r_imp.combined();
    let imp_lower = imp_out.to_lowercase();
    assert!(imp_lower.contains("history"), "{imp_out}");
    assert!(imp_lower.contains("tier 1"), "{imp_out}");
    assert!(
        imp_lower.contains("delete") || imp_lower.contains("remove"),
        "{imp_out}"
    );
    for v in [&sec_api, &sec_db, &sec_tok, &sec_prod] {
        assert!(
            !imp_out.contains(v.as_str()),
            "import echoed a value\n{imp_out}"
        );
    }

    let l = sb.run(&["list"], b"").assert_success("list").combined();
    for name in ["API_KEY", "DATABASE_URL", "SECRET_TOKEN"] {
        assert!(l.contains(name), "list missing {name}:\n{l}");
    }
    for v in [&sec_api, &sec_db, &sec_tok, &sec_prod] {
        assert!(!l.contains(v.as_str()), "list leaked a value:\n{l}");
    }

    let r_exp = sb.run(&["export", "--format", "dotenv"], b"");
    r_exp.assert_success("export --format dotenv");
    assert_eq!(
        parse_dotenv(&r_exp.stdout_str()),
        expected_base,
        "--- export stdout ---\n{}",
        r_exp.stdout_str()
    );

    let mut expected_prod: BTreeMap<String, String> = expected_base.clone();
    for (k, v) in &expected_prod_layer {
        expected_prod.insert(k.clone(), v.clone());
    }
    let r_exp_prod = sb.run(&["export", "--env", "prod", "--format", "dotenv"], b"");
    r_exp_prod.assert_success("export --env prod");
    assert_eq!(parse_dotenv(&r_exp_prod.stdout_str()), expected_prod);

    let j = sb
        .run(&["export", "--format", "json"], b"")
        .assert_success("export --format json")
        .stdout_str();
    for (k, v) in &expected_base {
        assert!(
            j.contains(&format!("\"{k}\"")),
            "json missing key {k}:\n{j}"
        );
        assert!(
            j.contains(v.as_str()) || j.contains(&base64_encode(v.as_bytes())),
            "json missing value for {k}"
        );
    }

    // `run` delivers the same set to a child, with secrets in the environment.
    let r_run = sb.run(
        &[
            "run",
            "--",
            "sh",
            "-c",
            "printf '%s|%s|%s' \"$PORT\" \"$API_KEY\" \"$DATABASE_URL\"",
        ],
        b"",
    );
    r_run.assert_success("run -- sh -c");
    assert_eq!(
        r_run.stdout_str(),
        format!("3000|{sec_api}|postgres://app:{sec_db}@db.internal:5432/app")
    );

    sb.cleanup();
}

// ===========================================================================
// Suite 4 — Wrap matrix (G-A): tier ≥ 2 without hardware refuses
// ===========================================================================

#[test]
fn wrap_matrix_refuses_software_above_tier1() {
    let sb = Sandbox::new("wrapmatrix");
    sb.init_vault();
    let before = sb.read_vault();
    assert_eq!(before.generation, 1);
    let recipients_before = before.recipients.len();

    let fake = fake_age_recipient();
    let r_enroll = sb.run(
        &[
            "recipient",
            "add",
            &fake,
            "--label",
            "ci-software",
            "--env",
            "prod",
            "--max-tier",
            "2",
        ],
        b"y\n",
    );
    r_enroll.assert_failure("recipient add (software) --max-tier 2");
    let e = r_enroll.combined().to_lowercase();
    assert!(
        e.contains("tier") && (e.contains("software") || e.contains("hardware")),
        "{}",
        r_enroll.combined()
    );

    let t2_value = sentinel("T2");
    let r_set2 = sb.run(
        &["set", "PROD_DB_ROOT", "--tier", "2", "--stdin"],
        t2_value.as_bytes(),
    );
    r_set2.assert_failure("set --tier 2 with only software identities");
    let e2 = r_set2.combined().to_lowercase();
    assert!(e2.contains("hardware"), "{}", r_set2.combined());
    assert!(
        e2.contains("doctor") || e2.contains("recipient"),
        "{}",
        r_set2.combined()
    );

    let after = sb.read_vault();
    assert_eq!(after.generation, 1, "a refused operation must not save");
    assert_eq!(after.recipients.len(), recipients_before);
    assert!(after.cells.iter().all(|c| c.tier < 2));
    let b64 = base64_encode(t2_value.as_bytes());
    let hits = scan_tree_for(&sb.root, &[t2_value.as_str(), b64.as_str()]);
    assert!(hits.is_empty(), "{}", hits.join("\n"));

    sb.cleanup();
}

// ===========================================================================
// Suite 5 — Recovery: `recovery verify` + age-CLI-only blob decryption
// ===========================================================================

#[test]
fn recovery_verify_passes_on_fresh_vault() {
    let sb = Sandbox::new("recverify");
    let init = sb.init_vault();
    sb.run(
        &["set", "REC_SECRET", "--stdin"],
        sentinel("REC1").as_bytes(),
    )
    .assert_success("set REC_SECRET");

    // A second `recovery create` is refused: the kit exists.
    let r_again = sb.run(&["recovery", "create", "--paper"], b"");
    r_again.assert_failure("recovery create after the kit exists");
    assert!(r_again.combined().contains("recovery verify"));

    let ident = init.recovery_identity.to_string_lossy().into_owned();
    let key_line = fs::read_to_string(&init.recovery_identity)
        .unwrap()
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-1"))
        .expect("removable identity file must contain an AGE-SECRET-KEY-1 line")
        .to_string();
    let r = sb.run(
        &["recovery", "verify", "--identity", &ident],
        format!("{key_line}\n").as_bytes(),
    );
    r.assert_success("recovery verify");

    sb.cleanup();
}

#[test]
fn recovery_blob_decrypts_with_age_cli_alone() {
    let Some(age) = find_age() else {
        eprintln!("SKIPPED: age CLI not found — age-only decryption not exercised.");
        return;
    };

    let sb = Sandbox::new("recage");
    let init = sb.init_vault();
    let s = sentinel("REC2");
    sb.run(&["set", "REC_SECRET", "--stdin"], s.as_bytes())
        .assert_success("set REC_SECRET");

    let blob = fs::read_to_string(sb.recovery_blob_path()).unwrap();
    assert!(blob.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));

    let mut cmd = std::process::Command::new(&age);
    cmd.arg("-d")
        .arg("-i")
        .arg(&init.recovery_identity)
        .arg(sb.recovery_blob_path())
        .current_dir(&sb.project);
    let r = run_with_timeout(cmd, b"", Duration::from_secs(60));
    r.assert_success("age -d -i <recovery identity> secrets.holster.recovery.age");
    let json = r.stdout_str();

    let vault = sb.read_vault();
    assert_eq!(vault.generation, 2, "init + one set = generation 2");
    assert!(json.contains(&format!("\"generation\":{}", vault.generation)));
    assert!(json.contains(&format!("\"vault_uuid\":\"{}\"", vault.uuid)));
    assert!(json.contains("\"schema\":1"));
    assert!(json.contains("\"envs\":{\"base\":{\"1\":{\"REC_SECRET\":{"));
    assert!(json.contains(&format!("\"value\":\"{}\"", base64_encode(s.as_bytes()))));
    assert!(json.contains("\"mode\":\"env-var\""));
    assert!(json.contains("\"guarantee\":\"unassigned\""));
    assert!(json.trim_end_matches('\n').ends_with('}') && !json.trim_end().contains('\n'));

    sb.cleanup();
}

// ===========================================================================
// Suite 6 — Nonce discipline + generation counter (ENVELOPE-SPEC §5.3, §9)
// ===========================================================================

#[test]
fn nonces_are_fresh_and_generation_is_monotonic() {
    let sb = Sandbox::new("nonce");
    sb.init_vault();
    assert_eq!(sb.read_vault().generation, 1);

    sb.run(&["set", "KEY_ONE", "--stdin"], sentinel("N1").as_bytes())
        .assert_success("set KEY_ONE");
    let v2 = sb.read_vault();
    assert_eq!(v2.generation, 2);
    let c2 = v2.cell("base", 1).expect("cell (base,1)").clone();
    let t2 = v2.tag("base", 1).expect("tag base:1").to_string();
    let b2 = v2.body_b64("base", 1).expect("body base:1");
    assert_eq!(c2.nonce.len(), 48);
    assert!(c2
        .nonce
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    assert_eq!(t2.len(), 32);
    assert_eq!(base64_decoded_len(&b2) as u64, c2.ct_len);

    sb.run(&["set", "KEY_TWO", "--stdin"], sentinel("N2").as_bytes())
        .assert_success("set KEY_TWO");
    let v3 = sb.read_vault();
    assert_eq!(v3.generation, 3);
    let c3 = v3.cell("base", 1).expect("cell (base,1)").clone();
    let t3 = v3.tag("base", 1).unwrap().to_string();
    let b3 = v3.body_b64("base", 1).unwrap();
    assert_ne!(c3.nonce, c2.nonce);
    assert_ne!(b3, b2);
    assert_ne!(t3, t2);
    assert_eq!(c3.commitment, c2.commitment);
    assert!(c3.ct_len > c2.ct_len);

    let extra = fake_age_recipient();
    sb.run(
        &[
            "recipient",
            "add",
            &extra,
            "--label",
            "extra-reader",
            "--class",
            "software",
            "--env",
            "base",
            "--max-tier",
            "1",
        ],
        b"y\n",
    )
    .assert_success("recipient add (software, base:1)");
    let v4 = sb.read_vault();
    assert_eq!(v4.generation, 4);
    let c4 = v4.cell("base", 1).expect("cell (base,1)").clone();
    let t4 = v4.tag("base", 1).unwrap().to_string();
    let b4 = v4.body_b64("base", 1).unwrap();
    assert_eq!(c4.ct_len, c3.ct_len);
    assert_ne!(c4.nonce, c3.nonce);
    assert_ne!(b4, b3);
    assert_ne!(t4, t3);
    assert_eq!(c4.commitment, c3.commitment);

    let nonces = [c2.nonce.as_str(), c3.nonce.as_str(), c4.nonce.as_str()];
    for i in 0..nonces.len() {
        for j in i + 1..nonces.len() {
            assert_ne!(nonces[i], nonces[j], "nonce reuse across saves");
        }
    }

    let new_block = v4
        .recipients
        .iter()
        .find(|r| r.encoding.as_deref() == Some(extra.as_str()))
        .expect("newly enrolled recipient must appear in the header");
    assert_eq!(new_block.class, "software");
    let mut expected_ids: Vec<&str> = v4.recipients.iter().map(|r| r.id.as_str()).collect();
    expected_ids.sort_unstable();
    let wrap_ids: Vec<&str> = c4.wraps.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(wrap_ids, expected_ids);

    let lines = v4.body_lines("base", 1).unwrap();
    for (i, l) in lines.iter().enumerate() {
        if i + 1 < lines.len() {
            assert_eq!(l.len(), 64);
        } else {
            assert!((1..=64).contains(&l.len()));
        }
    }

    sb.cleanup();
}

// ===========================================================================
// Suite 7 — `run`: in-process delivery, filtering, --dotenv, exit codes
// ===========================================================================

/// Put `NAME = "VALUE"` under `[vars]` in the manifest, whatever shape
/// `init` wrote it in.
fn declare_var(sb: &Sandbox, name: &str, value: &str) {
    let path = sb.manifest_path();
    let text = fs::read_to_string(&path).unwrap();
    let line = format!("{name} = \"{value}\"\n");
    let updated = if let Some(pos) = text.find("[vars]") {
        let line_end = text[pos..]
            .find('\n')
            .map(|i| pos + i + 1)
            .unwrap_or(text.len());
        format!("{}{line}{}", &text[..line_end], &text[line_end..])
    } else {
        format!("{text}\n[vars]\n{line}")
    };
    fs::write(&path, updated).unwrap();
}

fn declare_port_var(sb: &Sandbox) {
    declare_var(sb, "PORT", "3000");
}

/// Run git inside the sandbox project with an isolated HOME.
fn git_cmd(sb: &Sandbox, args: &[&str]) {
    let out = git_output(sb, &sb.project, args);
    assert!(
        out.status.success(),
        "git {args:?} failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn git_output(sb: &Sandbox, dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        // The same isolation `Sandbox::command` gives the binary: git spawns
        // the merge drivers with THIS environment, and an ambient
        // XDG_CONFIG_HOME (set on GitHub's Ubuntu image) would otherwise
        // point them at a different identity directory.
        .env("HOME", &sb.home)
        .env("TMPDIR", &sb.tmp)
        .env("XDG_CONFIG_HOME", sb.home.join(".config"))
        .env("NO_COLOR", "1")
        .env_remove("ENVHOLSTER_ENV")
        .env_remove("ENVHOLSTER_IDENTITY")
        .env_remove("ENVHOLSTER_IDENTITY_FILE")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "e2e")
        .env("GIT_AUTHOR_EMAIL", "e2e@example.invalid")
        .env("GIT_COMMITTER_NAME", "e2e")
        .env("GIT_COMMITTER_EMAIL", "e2e@example.invalid")
        .output()
        .expect("git present")
}

#[test]
fn run_injects_secrets_and_vars() {
    let sb = Sandbox::new("run");
    sb.init_vault();
    let key = sentinel("RUN1");
    sb.run(&["set", "API_KEY", "--stdin"], key.as_bytes())
        .assert_success("set API_KEY");
    declare_port_var(&sb);

    let r = sb.run(
        &[
            "run",
            "--",
            "sh",
            "-c",
            "printf '%s %s' \"$API_KEY\" \"$PORT\"",
        ],
        b"",
    );
    r.assert_success("run -- sh -c");
    assert_eq!(r.stdout_str(), format!("{key} 3000"));

    // The identity variables and loader hooks never reach the child; the
    // rest of the shell environment does.
    let machine_identity = find_file_containing(&sb.home, "AGE-SECRET-KEY-1").unwrap();
    let mut cmd = sb.command(&["run", "--", "env"]);
    cmd.env("ENVHOLSTER_IDENTITY_FILE", &machine_identity)
        // Prefix-matched names dyld/ld.so ignore: a real hook would abort the
        // parent before the filter could run.
        .env("DYLD_FAKE_HOOK", "/nope.dylib")
        .env("LD_FAKE_HOOK", "/nope.so")
        .env("MY_TOOL_FLAG", "kept")
        .env("API_KEY", "stale-shell-value");
    let r_env = run_with_timeout(cmd, b"", Duration::from_secs(60));
    r_env.assert_success("run -- env");
    let env_out = r_env.stdout_str();
    assert!(!env_out.contains("ENVHOLSTER_IDENTITY"), "{env_out}");
    assert!(!env_out.contains("DYLD_FAKE_HOOK"), "{env_out}");
    assert!(!env_out.contains("LD_FAKE_HOOK"), "{env_out}");
    assert!(env_out.contains("MY_TOOL_FLAG=kept"), "{env_out}");
    assert!(env_out.contains(&format!("API_KEY={key}")), "{env_out}");
    assert!(!env_out.contains("stale-shell-value"), "{env_out}");

    // Exit codes pass through.
    let r7 = sb.run(&["run", "--", "sh", "-c", "exit 7"], b"");
    assert_eq!(
        r7.status.and_then(|s| s.code()),
        Some(7),
        "{}",
        r7.combined()
    );
    let r_missing = sb.run(&["run", "--", "definitely-not-a-command-xyz"], b"");
    r_missing.assert_failure("run of a missing command");
    assert!(r_missing
        .combined()
        .contains("definitely-not-a-command-xyz"));

    sb.cleanup();
}

#[test]
fn run_dotenv_writes_then_removes() {
    let sb = Sandbox::new("dotenv");
    sb.init_vault();
    let key = sentinel("DOT1");
    sb.run(&["set", "API_KEY", "--stdin"], key.as_bytes())
        .assert_success("set API_KEY");
    // A value quoting must protect: space, inline-comment `#`, padding.
    sb.run(&["set", "SPECIAL", "--stdin"], b"val with space # hash")
        .assert_success("set SPECIAL");
    declare_port_var(&sb);

    let r = sb.run(
        &[
            "run",
            "--dotenv",
            "--",
            "sh",
            "-c",
            "ls -l .env | cut -c1-10; cat .env",
        ],
        b"",
    );
    r.assert_success("run --dotenv");
    let out = r.stdout_str();
    assert!(
        out.starts_with("-rw-------"),
        "the dotenv file must be 0600:\n{out}"
    );
    assert!(out.contains("# envholster run --dotenv"), "{out}");
    assert!(out.contains(&format!("API_KEY={key}")), "{out}");
    // The file must parse back to the exact value the environment carries:
    // unquoted, a dotenv reader would strip ` # hash` as an inline comment.
    assert!(
        out.contains("SPECIAL='val with space # hash'"),
        "secret values must go through the quoting dotenv writer (single-quoted, so every \
         reader takes the bytes literally):\n{out}"
    );
    assert!(
        out.contains("PORT=3000") || out.contains("PORT=\"3000\""),
        "{out}"
    );
    assert!(
        r.stderr_str().contains("This notice prints once"),
        "the exposure notice prints on first use:\n{}",
        r.stderr_str()
    );
    assert!(
        !sb.project.join(".env").exists(),
        "the dotenv file must be gone after exit"
    );

    // Second run: notice not repeated; an existing .env is never overwritten.
    let r2 = sb.run(&["run", "--dotenv", "--", "true"], b"");
    r2.assert_success("run --dotenv (second)");
    assert!(!r2.stderr_str().contains("This notice prints once"));
    fs::write(sb.project.join(".env"), "KEEP=me\n").unwrap();
    let r3 = sb.run(&["run", "--dotenv", "--", "true"], b"");
    r3.assert_failure("run --dotenv over an existing .env");
    assert!(r3.combined().contains("refusing to overwrite"));
    assert_eq!(
        fs::read_to_string(sb.project.join(".env")).unwrap(),
        "KEEP=me\n"
    );

    sb.cleanup();
}

/// README's own quickstart: `import .env` (which leaves the comment-only
/// breadcrumb) followed by `run --dotenv` must work — the breadcrumb is
/// replaced for the child's lifetime and restored afterwards.
#[test]
fn import_breadcrumb_does_not_block_run_dotenv() {
    let sb = Sandbox::new("dotenvcrumb");
    sb.init_vault();
    let key = sentinel("CRUMB");
    fs::write(sb.project.join(".env"), format!("API_KEY={key}\n")).unwrap();
    // No hardware recipient: no tier prompts; the `y`s answer the delete
    // offer and (when shown) the gitignore offer.
    sb.run(&["import", ".env"], "y\n".repeat(4).as_bytes())
        .assert_success("import .env");
    let crumb = fs::read_to_string(sb.project.join(".env")).unwrap();
    assert!(crumb.starts_with("# Managed by Env Holster."), "{crumb}");

    let r = sb.run(&["run", "--dotenv", "--", "sh", "-c", "cat .env"], b"");
    r.assert_success("run --dotenv after import");
    let out = r.stdout_str();
    assert!(out.contains("# envholster run --dotenv"), "{out}");
    assert!(out.contains(&format!("API_KEY={key}")), "{out}");
    assert_eq!(
        fs::read_to_string(sb.project.join(".env")).unwrap(),
        crumb,
        "the import breadcrumb must be restored after the run"
    );

    sb.cleanup();
}

/// A typo'd `--env` must refuse, not silently deliver the base values as if
/// they were the requested environment's.
#[test]
fn undeclared_env_refuses_instead_of_delivering_base() {
    let sb = Sandbox::new("envtypo");
    sb.init_vault();
    let key = sentinel("TYPO");
    sb.run(&["set", "API_KEY", "--stdin"], key.as_bytes())
        .assert_success("set API_KEY");

    let r = sb.run(&["export", "--env", "prodction"], b"");
    r.assert_failure("export --env with an undeclared environment");
    assert!(
        !r.stdout_str().contains(&key),
        "base values leaked for a typo'd env:\n{}",
        r.combined()
    );
    assert!(r.combined().contains("not declared"), "{}", r.combined());

    let r2 = sb.run(
        &[
            "run",
            "--env",
            "prodction",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$API_KEY\"",
        ],
        b"",
    );
    r2.assert_failure("run --env with an undeclared environment");
    assert!(
        !r2.stdout_str().contains(&key),
        "base values reached the child for a typo'd env:\n{}",
        r2.combined()
    );

    sb.cleanup();
}

// ===========================================================================
// Suite 8 — merge driver: record-level three-way merge of secrets.holster
// ===========================================================================

#[test]
fn merge_driver_three_way() {
    let sb = Sandbox::new("merge");
    sb.init_vault();
    let scratch = sb.root.join("merge");
    fs::create_dir_all(&scratch).unwrap();
    let base = scratch.join("base.holster");
    let ours = scratch.join("ours.holster");
    let theirs = scratch.join("theirs.holster");

    // base: A. ours: base + B. theirs: base + C.
    let a = sentinel("MA");
    let b = sentinel("MB");
    let c = sentinel("MC");
    sb.run(&["set", "A", "--stdin"], a.as_bytes())
        .assert_success("set A");
    fs::copy(sb.vault_path(), &base).unwrap();
    sb.run(&["set", "B", "--stdin"], b.as_bytes())
        .assert_success("set B");
    fs::copy(sb.vault_path(), &ours).unwrap();
    fs::copy(&base, sb.vault_path()).unwrap();
    sb.run(&["set", "C", "--stdin"], c.as_bytes())
        .assert_success("set C");
    fs::copy(sb.vault_path(), &theirs).unwrap();

    let base_s = base.to_string_lossy().into_owned();
    let ours_s = ours.to_string_lossy().into_owned();
    let theirs_s = theirs.to_string_lossy().into_owned();
    let r = sb.run(&["merge-driver", &base_s, &ours_s, &theirs_s], b"");
    r.assert_success("merge-driver base ours theirs");
    fs::copy(&ours, sb.vault_path()).unwrap();
    for (name, want) in [("A", &a), ("B", &b), ("C", &c)] {
        let got = sb
            .run(&["get", name], b"")
            .assert_success(name)
            .stdout_str();
        assert!(
            got == *want || got == format!("{want}\n"),
            "{name}: {got:?}"
        );
    }

    // Both sides changed X differently: a conflict, and %A is left alone.
    fs::copy(&base, sb.vault_path()).unwrap();
    sb.run(&["set", "X", "--stdin"], b"one")
        .assert_success("set X=one");
    fs::copy(sb.vault_path(), &ours).unwrap();
    fs::copy(&base, sb.vault_path()).unwrap();
    sb.run(&["set", "X", "--stdin"], b"two")
        .assert_success("set X=two");
    fs::copy(sb.vault_path(), &theirs).unwrap();
    let ours_before = fs::read(&ours).unwrap();
    let r_conflict = sb.run(&["merge-driver", &base_s, &ours_s, &theirs_s], b"");
    r_conflict.assert_failure("merge-driver with a two-sided change");
    assert!(
        r_conflict.combined().contains("CONFLICT: base:X"),
        "{}",
        r_conflict.combined()
    );
    assert_eq!(
        fs::read(&ours).unwrap(),
        ours_before,
        "a conflict must not rewrite %A"
    );

    sb.cleanup();
}

/// Recipient sets are trust decisions: a recipient enrolled on one branch
/// only must surface as a conflict, never enroll silently. And two vaults
/// that were created independently (different UUIDs) are not branches of
/// one history at all — merging them must refuse outright.
#[test]
fn merge_driver_refuses_recipient_divergence_and_foreign_vaults() {
    let sb = Sandbox::new("merge-guard");
    sb.init_vault();
    let scratch = sb.root.join("merge");
    fs::create_dir_all(&scratch).unwrap();
    let base = scratch.join("base.holster");
    let ours = scratch.join("ours.holster");
    let theirs = scratch.join("theirs.holster");

    sb.run(&["set", "A", "--stdin"], sentinel("MG").as_bytes())
        .assert_success("set A");
    fs::copy(sb.vault_path(), &base).unwrap();
    fs::copy(sb.vault_path(), &ours).unwrap();

    // theirs: the same vault, plus a recipient enrolled on that branch only.
    let extra = fake_age_recipient();
    sb.run(
        &[
            "recipient",
            "add",
            &extra,
            "--label",
            "their-reader",
            "--class",
            "software",
            "--env",
            "base",
            "--max-tier",
            "1",
        ],
        b"y\n",
    )
    .assert_success("recipient add on their branch");
    fs::copy(sb.vault_path(), &theirs).unwrap();

    let base_s = base.to_string_lossy().into_owned();
    let ours_s = ours.to_string_lossy().into_owned();
    let theirs_s = theirs.to_string_lossy().into_owned();
    let ours_before = fs::read(&ours).unwrap();
    let r = sb.run(&["merge-driver", &base_s, &ours_s, &theirs_s], b"");
    r.assert_failure("merge-driver with divergent recipient sets");
    let combined = r.combined();
    assert!(
        combined.contains("recipient") && combined.contains("their-reader"),
        "must name the divergent recipient: {combined}"
    );
    assert_eq!(
        fs::read(&ours).unwrap(),
        ours_before,
        "a recipient conflict must not rewrite %A"
    );

    // A vault from a different project: same filename, unrelated history.
    let foreign = Sandbox::new("merge-foreign");
    foreign.init_vault();
    let theirs_foreign = scratch.join("theirs-foreign.holster");
    fs::copy(foreign.vault_path(), &theirs_foreign).unwrap();
    let theirs_foreign_s = theirs_foreign.to_string_lossy().into_owned();
    let r_foreign = sb.run(&["merge-driver", &base_s, &ours_s, &theirs_foreign_s], b"");
    r_foreign.assert_failure("merge-driver across unrelated vaults");
    assert!(
        r_foreign.combined().contains("same vault"),
        "must refuse on vault identity: {}",
        r_foreign.combined()
    );
    assert_eq!(
        fs::read(&ours).unwrap(),
        ours_before,
        "an identity refusal must not rewrite %A"
    );

    foreign.cleanup();
    sb.cleanup();
}

// ===========================================================================
// Suite 9 — review follow-ups: tracked files, aliased secrets, doctor scan
// ===========================================================================

/// A `.env` that is force-tracked despite an ignore rule is not ignored as
/// far as git is concerned (`git commit -a` would stage it): `--dotenv`
/// must refuse it, breadcrumb or not.
#[test]
fn run_dotenv_refuses_a_tracked_file() {
    let sb = Sandbox::new("dotenvtracked");
    sb.init_vault();
    sb.run(&["set", "API_KEY", "--stdin"], b"k")
        .assert_success("set API_KEY");
    git_cmd(&sb, &["init", "-q"]);
    // Produce the exact import breadcrumb the way a user would.
    fs::write(sb.project.join(".env"), "API_KEY=old\n").unwrap();
    sb.run(&["import", ".env"], "y\n".repeat(4).as_bytes())
        .assert_success("import .env");
    let crumb = fs::read_to_string(sb.project.join(".env")).unwrap();
    assert!(crumb.starts_with("# Managed by Env Holster."), "{crumb}");

    // Untracked and ignored: fine.
    sb.run(&["run", "--dotenv", "--", "true"], b"")
        .assert_success("run --dotenv on an untracked, ignored breadcrumb");

    // Force-tracked: refused, file untouched.
    git_cmd(&sb, &["add", "-f", ".env"]);
    let r = sb.run(&["run", "--dotenv", "--", "true"], b"");
    r.assert_failure("run --dotenv over a tracked .env");
    assert!(r.combined().contains("git tracks"), "{}", r.combined());
    assert!(r.combined().contains("git rm --cached"), "{}", r.combined());
    assert_eq!(fs::read_to_string(sb.project.join(".env")).unwrap(), crumb);

    sb.cleanup();
}

/// A declaration's `env_var` renames the delivered variable; a
/// `${secret:NAME}` composite still references the vault name. Both `run`
/// and `export` must resolve it.
#[test]
fn run_composite_uses_the_canonical_name_when_env_var_aliases_it() {
    let sb = Sandbox::new("alias");
    sb.init_vault();
    let tok = sentinel("ALIAS");
    sb.run(&["set", "token", "--stdin"], tok.as_bytes())
        .assert_success("set token");
    let manifest_path = sb.manifest_path();
    let text = fs::read_to_string(&manifest_path).unwrap();
    assert!(text.contains("name = \"token\""), "{text}");
    fs::write(
        &manifest_path,
        text.replacen(
            "name = \"token\"\n",
            "name = \"token\"\nenv_var = \"API_TOKEN\"\n",
            1,
        ),
    )
    .unwrap();
    declare_var(&sb, "DB_URL", "pg://u:${secret:token}@h/db");

    let r = sb.run(
        &[
            "run",
            "--",
            "sh",
            "-c",
            "printf '%s|%s|%s' \"$API_TOKEN\" \"$DB_URL\" \"${token:-unset}\"",
        ],
        b"",
    );
    r.assert_success("run with an aliased secret in a composite");
    assert_eq!(r.stdout_str(), format!("{tok}|pg://u:{tok}@h/db|unset"));

    let exported = parse_dotenv(
        &sb.run(&["export"], b"")
            .assert_success("export")
            .stdout_str(),
    );
    assert_eq!(
        exported.get("API_TOKEN").map(String::as_str),
        Some(tok.as_str())
    );
    assert_eq!(
        exported.get("DB_URL").map(String::as_str),
        Some(format!("pg://u:{tok}@h/db").as_str())
    );
    assert!(!exported.contains_key("token"));

    sb.cleanup();
}

/// A `--dotenv <custom path>` file left behind by a signalled run is found
/// by its marker line, whatever it is called.
#[test]
fn doctor_reports_a_leftover_dotenv_under_any_name() {
    let sb = Sandbox::new("leftover");
    sb.init_vault();
    assert!(sb.run(&["doctor"], b"").success());
    fs::write(
        sb.project.join("secrets.tmp.env"),
        "# envholster run --dotenv: temporary, deleted when the command exits\nAPI_KEY=x\n",
    )
    .unwrap();
    let r = sb.run(&["doctor"], b"");
    assert_eq!(r.status.and_then(|s| s.code()), Some(7), "{}", r.combined());
    assert!(r.combined().contains("secrets.tmp.env"), "{}", r.combined());
    fs::remove_file(sb.project.join("secrets.tmp.env")).unwrap();
    assert!(sb.run(&["doctor"], b"").success());

    sb.cleanup();
}

// ===========================================================================
// Suite 10 — loader hooks from the project; a real git merge; file readers
// ===========================================================================

/// The deny list applies to the final environment: a repository's
/// envholster.toml (or a secret named for a loader hook) must not load code
/// into the child. Refused before anything is written.
#[test]
fn run_refuses_loader_hooks_from_the_project() {
    let sb = Sandbox::new("loaderhook");
    sb.init_vault();
    let manifest_path = sb.manifest_path();
    let clean = fs::read_to_string(&manifest_path).unwrap();

    for (name, value) in [
        ("LD_PRELOAD", "/evil.so"),
        ("DYLD_INSERT_LIBRARIES", "/evil.dylib"),
        ("ENVHOLSTER_IDENTITY_FILE", "/tmp/x"),
    ] {
        fs::write(&manifest_path, &clean).unwrap();
        declare_var(&sb, name, value);
        let r = sb.run(&["run", "--", "true"], b"");
        r.assert_failure(&format!("run with {name} in [vars]"));
        assert!(r.combined().contains(name), "{}", r.combined());
        let r2 = sb.run(&["run", "--dotenv", "--", "true"], b"");
        r2.assert_failure(&format!("run --dotenv with {name} in [vars]"));
        assert!(!sb.project.join(".env").exists(), "nothing may be written");
        // export is meant to be sourced: the same refusal, every format.
        for format in ["dotenv", "shell", "json"] {
            let e = sb.run(&["export", "--format", format], b"");
            e.assert_failure(&format!("export --format {format} with {name} in [vars]"));
            assert!(e.combined().contains(name), "{}", e.combined());
            assert!(!e.stdout_str().contains(value), "{format}: value leaked");
        }
    }
    fs::write(&manifest_path, &clean).unwrap();

    // A secret whose name is a loader hook is refused the same way.
    sb.run(&["set", "DYLD_FRAMEWORK_PATH", "--stdin"], b"/evil")
        .assert_success("set DYLD_FRAMEWORK_PATH");
    let r = sb.run(&["run", "--", "true"], b"");
    r.assert_failure("run with a loader-hook secret name");
    assert!(
        r.combined().contains("DYLD_FRAMEWORK_PATH"),
        "{}",
        r.combined()
    );

    sb.cleanup();
}

/// A real three-way `git merge` through the installed drivers: the merge
/// commits cleanly, the worktree is clean afterwards, and a fresh clone of
/// the merge commit passes `recovery verify` (the recovery blob in the
/// commit is the one regenerated from the merged vault).
#[test]
fn git_merge_commits_the_regenerated_recovery_blob() {
    let sb = Sandbox::new("gitmerge");
    let init = sb.init_vault();
    git_cmd(&sb, &["init", "-q", "-b", "main"]);
    let bin = bin_path().to_string_lossy().into_owned();
    git_cmd(
        &sb,
        &[
            "config",
            "merge.envholster.driver",
            &format!("{bin} merge-driver %O %A %B"),
        ],
    );
    git_cmd(
        &sb,
        &[
            "config",
            "merge.envholster-blob.driver",
            &format!("{bin} merge-driver-blob %O %A %B"),
        ],
    );
    let attrs = fs::read_to_string(sb.project.join(".gitattributes")).unwrap();
    assert!(
        attrs.contains("secrets.holster merge=envholster"),
        "{attrs}"
    );

    let a = sentinel("GMA");
    let b = sentinel("GMB");
    let c = sentinel("GMC");
    sb.run(&["set", "A", "--stdin"], a.as_bytes())
        .assert_success("set A");
    // The base commit declares every name (a manifest both branches change is
    // git's ordinary text merge, not this driver's job); the branches then
    // change VALUES, which live in the vault only.
    sb.run(&["set", "B", "--stdin"], b"old-b")
        .assert_success("set B (base)");
    sb.run(&["set", "C", "--stdin"], b"old-c")
        .assert_success("set C (base)");
    git_cmd(&sb, &["add", "-A"]);
    git_cmd(&sb, &["commit", "-q", "-m", "base"]);
    git_cmd(&sb, &["checkout", "-q", "-b", "theirs"]);
    sb.run(&["set", "C", "--stdin"], c.as_bytes())
        .assert_success("set C");
    git_cmd(&sb, &["add", "-A"]);
    git_cmd(&sb, &["commit", "-q", "-m", "theirs rotates C"]);
    git_cmd(&sb, &["checkout", "-q", "main"]);
    sb.run(&["set", "B", "--stdin"], b.as_bytes())
        .assert_success("set B");
    git_cmd(&sb, &["add", "-A"]);
    git_cmd(&sb, &["commit", "-q", "-m", "ours rotates B"]);

    let merge = git_output(&sb, &sb.project, &["merge", "--no-edit", "theirs"]);
    assert!(
        merge.status.success(),
        "git merge must succeed through the drivers:\n{}\n{}",
        String::from_utf8_lossy(&merge.stdout),
        String::from_utf8_lossy(&merge.stderr)
    );
    let status = git_output(&sb, &sb.project, &["status", "--porcelain"]);
    assert_eq!(
        String::from_utf8_lossy(&status.stdout).trim(),
        "",
        "the worktree must be clean after the merge (no unstaged recovery blob)"
    );

    // A fresh clone of the merge commit: both sides' secrets, and the blob
    // in the commit is in lockstep with the vault.
    let clone = sb.root.join("clone");
    let clone_s = clone.to_string_lossy().into_owned();
    git_cmd(&sb, &["clone", "-q", ".", &clone_s]);
    for (name, want) in [("A", &a), ("B", &b), ("C", &c)] {
        let mut cmd = sb.command(&["get", name]);
        cmd.current_dir(&clone);
        let r = run_with_timeout(cmd, b"", Duration::from_secs(60));
        r.assert_success(&format!("get {name} in the clone"));
        let got = r.stdout_str();
        assert!(
            got == *want || got == format!("{want}\n"),
            "{name}: {got:?}"
        );
    }
    let ident = init.recovery_identity.to_string_lossy().into_owned();
    let mut verify = sb.command(&["recovery", "verify", "--identity", &ident]);
    verify.current_dir(&clone);
    run_with_timeout(verify, b"", Duration::from_secs(120))
        .assert_success("recovery verify in a clone of the merge commit");

    sb.cleanup();
}

/// A minimal model of Node's `util.parseEnv` / `--env-file` rules: matching
/// outer quotes are stripped; inside double quotes only `\n` is unescaped;
/// single quotes are literal; an unquoted value stops at ` #`.
fn node_like_parse(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim();
        let value = if v.len() >= 2 && v.starts_with('"') && v[1..].contains('"') {
            let end = v[1..].find('"').unwrap() + 1;
            v[1..end].replace("\\n", "\n")
        } else if v.len() >= 2 && v.starts_with('\'') && v[1..].contains('\'') {
            let end = v[1..].find('\'').unwrap() + 1;
            v[1..end].to_owned()
        } else if v.len() >= 2 && v.starts_with('`') && v[1..].contains('`') {
            // Node reads a backtick as an opening quote too.
            let end = v[1..].find('`').unwrap() + 1;
            v[1..end].to_owned()
        } else {
            v.split(" #").next().unwrap_or("").trim().to_owned()
        };
        out.insert(k.trim().to_owned(), value);
    }
    out
}

/// The `--dotenv` file must read back identically through the readers it
/// is written for (modelled on Node's parser), not only this crate's own.
#[test]
fn run_dotenv_values_survive_a_node_style_reader() {
    let sb = Sandbox::new("dotenvnode");
    sb.init_vault();
    let cases = [
        ("DOLLAR", "p$ssw0rd"),
        ("BSLASH", "a\\b"),
        ("NASTY", "val with space # hash \"q\" $x"),
        ("SPACED", "two words"),
        ("PLAIN", "sk-test-123"),
        ("APOS_ONLY", "don't panic"),
        ("MULTI", "line one\nline two"),
        ("TICKS", "`abc123`"),
    ];
    for (name, value) in cases {
        sb.run(&["set", name, "--stdin"], value.as_bytes())
            .assert_success(name);
    }
    let r = sb.run(&["run", "--dotenv", "--", "sh", "-c", "cat .env"], b"");
    r.assert_success("run --dotenv");
    let parsed = node_like_parse(&r.stdout_str());
    for (name, value) in cases {
        assert_eq!(
            parsed.get(name).map(String::as_str),
            Some(value),
            "{name} read back differently from the file:\n{}",
            r.stdout_str()
        );
    }
    // The harness's minimal reader agrees too (it does not unescape `\n`, so
    // the multi-line case is the Node model's alone).
    let ours = parse_dotenv(&r.stdout_str());
    for (name, value) in cases.iter().filter(|(_, v)| !v.contains('\n')) {
        assert_eq!(ours.get(*name).map(String::as_str), Some(*value), "{name}");
    }

    sb.cleanup();
}

// ===========================================================================
// Suite 11 — round-4 review: unencodable values, nested leftovers, media
// ===========================================================================

/// A value with a single quote AND `$`, `\`, `"` or a tab has no dotenv
/// encoding every reader agrees on. The file doors refuse it by name; the
/// environment door still delivers it.
#[test]
fn run_dotenv_refuses_a_value_readers_disagree_on() {
    let sb = Sandbox::new("unencodable");
    sb.init_vault();
    let value = "it's a $5 bill";
    sb.run(&["set", "APOS", "--stdin"], value.as_bytes())
        .assert_success("set APOS");

    let r = sb.run(&["run", "--dotenv", "--", "true"], b"");
    r.assert_failure("run --dotenv with an unencodable value");
    assert!(r.combined().contains("APOS"), "{}", r.combined());
    assert!(!sb.project.join(".env").exists(), "nothing may be written");

    let e = sb.run(&["export", "--format", "dotenv"], b"");
    e.assert_failure("export --format dotenv with an unencodable value");
    assert!(e.combined().contains("APOS"), "{}", e.combined());
    assert!(
        !e.stdout_str().contains("bill"),
        "no partial file on stdout"
    );

    let j = sb.run(&["export", "--format", "json"], b"");
    j.assert_success("export --format json");
    assert!(
        j.stdout_str().contains("it's a $5 bill"),
        "{}",
        j.stdout_str()
    );

    let env = sb.run(&["run", "--", "sh", "-c", "printf '%s' \"$APOS\""], b"");
    env.assert_success("run delivers it through the environment");
    assert_eq!(env.stdout_str(), value);

    // A carriage return anywhere (a CRLF PEM key from Windows) is refused
    // the same way: Node keeps `\r` as two characters.
    sb.run(&["rm", "APOS"], b"").assert_success("rm APOS");
    let pem = "-----BEGIN KEY-----\r\nabc\r\n-----END KEY-----\r\n";
    sb.run(
        &["set", "PEM_CRLF", "--stdin"],
        format!("{pem}\n").as_bytes(),
    )
    .assert_success("set PEM_CRLF");
    let r = sb.run(&["run", "--dotenv", "--", "true"], b"");
    r.assert_failure("run --dotenv with a CRLF value");
    assert!(r.combined().contains("PEM_CRLF"), "{}", r.combined());
    let e = sb.run(&["export", "--format", "dotenv"], b"");
    e.assert_failure("export --format dotenv with a CRLF value");
    assert!(e.combined().contains("PEM_CRLF"), "{}", e.combined());
    let env = sb.run(&["run", "--", "sh", "-c", "printf '%s' \"$PEM_CRLF\""], b"");
    env.assert_success("the environment still carries it");
    assert_eq!(env.stdout_str(), pem);
    assert!(
        r.combined().contains("carriage return"),
        "the refusal names the real cause:\n{}",
        r.combined()
    );

    // A doubled or trailing backslash: python-dotenv unescapes inside single
    // quotes, so the single-quoted form is not literal everywhere.
    sb.run(&["rm", "PEM_CRLF"], b"")
        .assert_success("rm PEM_CRLF");
    for (name, v) in [("UNC", "\\\\server\\share"), ("TRAIL", "C:\\Users\\me\\")] {
        sb.run(&["set", name, "--stdin"], v.as_bytes())
            .assert_success(name);
        let r = sb.run(&["run", "--dotenv", "--", "true"], b"");
        r.assert_failure(&format!("run --dotenv with {name}"));
        assert!(
            r.combined().contains(name) && r.combined().contains("backslash"),
            "{}",
            r.combined()
        );
        let env = sb.run(
            &["run", "--", "sh", "-c", &format!("printf '%s' \"${name}\"")],
            b"",
        );
        env.assert_success("environment delivery");
        assert_eq!(env.stdout_str(), v);
        sb.run(&["rm", name], b"").assert_success("rm");
    }

    sb.cleanup();
}

/// A signalled run leaves its `--dotenv` file behind wherever it was written;
/// `doctor` finds it through the in-flight record, not by scanning the root.
#[test]
fn doctor_reports_a_nested_leftover_after_a_signalled_run() {
    let sb = Sandbox::new("nestedleftover");
    sb.init_vault();
    sb.run(&["set", "API_KEY", "--stdin"], b"k")
        .assert_success("set");
    fs::create_dir_all(sb.project.join("apps/web")).unwrap();
    // The child kills envholster outright: no Drop runs, the file stays.
    let r = sb.run(
        &[
            "run",
            "--dotenv",
            "apps/web/.env",
            "--",
            "sh",
            "-c",
            "kill -9 $PPID",
        ],
        b"",
    );
    assert!(!r.success(), "envholster was killed by its child");
    let leftover = sb.project.join("apps/web/.env");
    assert!(leftover.is_file(), "the dotenv file survives a SIGKILL");

    let d = sb.run(&["doctor"], b"");
    assert_eq!(d.status.and_then(|s| s.code()), Some(7), "{}", d.combined());
    assert!(d.combined().contains("apps/web/.env"), "{}", d.combined());

    fs::remove_file(&leftover).unwrap();
    let d2 = sb.run(&["doctor"], b"");
    assert!(d2.success(), "{}", d2.combined());

    sb.cleanup();
}

/// `recovery create --to` refuses a destination on this machine's own disk
/// unless told explicitly; the parked identity stays put on refusal.
#[test]
fn recovery_create_refuses_a_same_disk_destination_by_default() {
    let sb = Sandbox::new("samedisk");
    let machine = sb.generate_identity("machine-one");
    sb.run(&["init", "--recipient", &machine], b"")
        .assert_success("init");
    let dest = sb.removable.join("recovery.identity");
    let dest_s = dest.to_string_lossy().into_owned();
    let r = sb.run(&["recovery", "create", "--to", &dest_s], b"");
    r.assert_failure("recovery create --to on the machine's disk");
    assert!(
        r.combined().contains("--allow-same-disk"),
        "{}",
        r.combined()
    );
    assert!(!dest.exists(), "no copy may be written on refusal");
    let d = sb.run(&["doctor"], b"");
    assert_eq!(
        d.status.and_then(|s| s.code()),
        Some(7),
        "the key is still parked"
    );

    sb.run(
        &["recovery", "create", "--to", &dest_s, "--allow-same-disk"],
        b"",
    )
    .assert_success("recovery create with the explicit override");
    assert!(dest.is_file());
    assert!(sb.run(&["doctor"], b"").success());

    sb.cleanup();
}

// ===========================================================================
// Suite 12 — round-8 review: rm scope, nested layered import, plan coverage
// ===========================================================================

/// `rm` in one environment must never delete the base value every
/// environment inherits.
#[test]
fn rm_never_falls_back_to_the_base_value() {
    let sb = Sandbox::new("rmscope");
    sb.init_vault();
    let v = sentinel("RM1");
    sb.run(&["set", "API_KEY", "--stdin"], v.as_bytes())
        .assert_success("set API_KEY in base");
    declare_var(&sb, "PORT", "3000");
    // Declare a prod environment so --env prod is legal.
    let m = sb.manifest_path();
    let text = fs::read_to_string(&m).unwrap();
    fs::write(&m, format!("{text}\n[environments]\nnames = [\"prod\"]\n")).unwrap();

    let r = sb.run(&["--env", "prod", "rm", "API_KEY"], b"");
    r.assert_failure("rm --env prod of a base-only secret");
    assert!(r.combined().contains("base"), "{}", r.combined());
    let got = sb
        .run(&["get", "API_KEY"], b"")
        .assert_success("get")
        .stdout_str();
    assert!(
        got == v || got == format!("{v}\n"),
        "the base value must survive"
    );

    sb.run(&["rm", "API_KEY"], b"").assert_success("rm in base");
    sb.run(&["get", "API_KEY"], b"").assert_failure("gone");

    sb.cleanup();
}

/// `import config/.env` must read `config/.env.local`, not a same-named
/// file in the current directory, and `--plan` must list the sibling too.
#[test]
fn import_nested_path_reads_its_own_siblings_and_plan_lists_them() {
    let sb = Sandbox::new("nestedimport");
    sb.init_vault();
    let good = sentinel("NEST-GOOD");
    let wrong = sentinel("NEST-WRONG");
    fs::create_dir_all(sb.project.join("config")).unwrap();
    fs::write(sb.project.join("config/.env"), "PORT=4000\n").unwrap();
    fs::write(
        sb.project.join("config/.env.local"),
        format!("LOCAL_KEY={good}\n"),
    )
    .unwrap();
    // A decoy at the root with the same name and a different value.
    fs::write(
        sb.project.join(".env.local"),
        format!("LOCAL_KEY={wrong}\n"),
    )
    .unwrap();

    let plan = sb.run(&["import", "config/.env", "--plan"], b"");
    plan.assert_success("import --plan");
    assert!(
        plan.combined().contains("config/.env.local"),
        "{}",
        plan.combined()
    );
    assert!(plan.combined().contains("LOCAL_KEY"), "{}", plan.combined());

    sb.run(&["import", "config/.env"], "y\n".repeat(6).as_bytes())
        .assert_success("import config/.env");
    let got = sb
        .run(&["get", "LOCAL_KEY"], b"")
        .assert_success("get")
        .stdout_str();
    assert!(
        got == good || got == format!("{good}\n"),
        "got the decoy: {got:?}"
    );
    let port = sb
        .run(&["get", "PORT"], b"")
        .assert_success("get PORT")
        .stdout_str();
    assert!(port.starts_with("4000"));

    sb.cleanup();
}

/// A directory whose name holds `=` (or anything else a `<file>=<env>`
/// string would mangle) must still get its own layered siblings.
#[test]
fn import_layered_siblings_survive_an_equals_sign_in_the_path() {
    let sb = Sandbox::new("equalsdir");
    sb.init_vault();
    let v = sentinel("EQ-LOCAL");
    fs::create_dir_all(sb.project.join("config=prod")).unwrap();
    fs::write(sb.project.join("config=prod/.env"), "PORT=5000\n").unwrap();
    fs::write(
        sb.project.join("config=prod/.env.local"),
        format!("LOCAL_KEY={v}\n"),
    )
    .unwrap();
    let plan = sb.run(&["import", "config=prod/.env", "--plan"], b"");
    plan.assert_success("import --plan with = in the directory");
    assert!(
        plan.combined().contains("config=prod/.env.local"),
        "{}",
        plan.combined()
    );
    sb.run(&["import", "config=prod/.env"], "y\n".repeat(6).as_bytes())
        .assert_success("import with = in the directory");
    let got = sb
        .run(&["get", "LOCAL_KEY"], b"")
        .assert_success("get")
        .stdout_str();
    assert!(got == v || got == format!("{v}\n"), "{got:?}");
    sb.cleanup();
}

/// Decisions are bound to the bytes they were reviewed against: a value
/// edited after `--plan` (a plain URL that now carries a credential) must
/// not be applied under the old `var` decision.
#[test]
fn apply_refuses_decisions_made_against_a_different_plan() {
    let sb = Sandbox::new("staleplan");
    sb.init_vault();
    let env_path = sb.project.join(".env");
    fs::write(
        &env_path,
        "DATABASE_URL=postgres://db.internal/app\nPORT=3000\n",
    )
    .unwrap();
    // The text plan prints a bare `plan <digest>` line meant to be copied
    // verbatim; the JSON plan carries the same digest.
    let plan = sb.run(&["import", ".env", "--plan"], b"");
    plan.assert_success("import --plan");
    let plan_line = plan
        .stdout_str()
        .lines()
        .find(|l| l.starts_with("plan "))
        .expect("plan prints its digest line")
        .to_owned();
    assert_eq!(plan_line.split_whitespace().count(), 2, "{plan_line}");
    let digest = plan_line.split_whitespace().nth(1).unwrap().to_owned();
    let json = sb.run(&["import", ".env", "--plan", "--json"], b"");
    json.assert_success("import --plan --json");
    assert!(json
        .stdout_str()
        .contains(&format!("\"digest\":\"{digest}\"")));
    let decisions = sb.project.join("decisions.txt");
    fs::write(
        &decisions,
        format!(
            "version 1\n{plan_line}\ncleanup delete_sources=no gitignore=no\n\
             decide .env DATABASE_URL var\ndecide .env PORT var\n"
        ),
    )
    .unwrap();

    // The file changes after review: the URL now carries a credential.
    let secret = sentinel("STALE");
    fs::write(
        &env_path,
        format!("DATABASE_URL=postgres://app:{secret}@db.internal/app\nPORT=3000\n"),
    )
    .unwrap();
    let r = sb.run(&["import", ".env", "--apply", "decisions.txt"], b"");
    r.assert_failure("apply with a stale plan digest");
    assert!(
        r.combined().contains("IMPORT_PLAN_STALE"),
        "{}",
        r.combined()
    );
    let manifest = fs::read_to_string(sb.manifest_path()).unwrap();
    assert!(
        !manifest.contains(&secret),
        "the credential must not reach the manifest"
    );
    assert!(
        !manifest.contains("PORT"),
        "nothing may be written on refusal"
    );

    // Restored to the reviewed bytes: the same decisions apply.
    fs::write(
        &env_path,
        "DATABASE_URL=postgres://db.internal/app\nPORT=3000\n",
    )
    .unwrap();
    sb.run(&["import", ".env", "--apply", "decisions.txt"], b"")
        .assert_success("apply against the reviewed bytes");
    assert!(fs::read_to_string(sb.manifest_path())
        .unwrap()
        .contains("PORT"));

    sb.cleanup();
}

/// A name that is both a [vars] entry and a stored secret resolves to the
/// secret everywhere: `get`, `run` and `export` must agree.
#[test]
fn get_run_and_export_agree_when_a_var_and_a_secret_share_a_name() {
    let sb = Sandbox::new("samename");
    sb.init_vault();
    let vault_copy = sentinel("SAME-VAULT");
    sb.run(&["set", "SAME", "--stdin"], vault_copy.as_bytes())
        .assert_success("set SAME");
    declare_var(&sb, "SAME", "plain-copy");

    let got = sb
        .run(&["get", "SAME"], b"")
        .assert_success("get SAME")
        .stdout_str();
    assert!(
        got == vault_copy || got == format!("{vault_copy}\n"),
        "get: {got:?}"
    );
    let ran = sb
        .run(&["run", "--", "sh", "-c", "printf '%s' \"$SAME\""], b"")
        .assert_success("run")
        .stdout_str();
    assert_eq!(ran, vault_copy, "run must deliver the secret");
    let exported = parse_dotenv(
        &sb.run(&["export"], b"")
            .assert_success("export")
            .stdout_str(),
    );
    assert_eq!(
        exported.get("SAME").map(String::as_str),
        Some(vault_copy.as_str())
    );

    // A manifest that would deliver two secrets under one name is refused
    // by run and export, and doctor names it.
    sb.run(&["set", "OTHER", "--stdin"], b"x")
        .assert_success("set OTHER");
    let m = sb.manifest_path();
    let text = fs::read_to_string(&m).unwrap();
    fs::write(
        &m,
        text.replacen(
            "name = \"OTHER\"\n",
            "name = \"OTHER\"\nenv_var = \"SAME\"\n",
            1,
        ),
    )
    .unwrap();
    let r = sb.run(&["run", "--", "true"], b"");
    r.assert_failure("run with colliding delivery names");
    assert!(
        r.combined().contains("delivered as \"SAME\""),
        "{}",
        r.combined()
    );
    sb.run(&["export"], b"")
        .assert_failure("export with colliding delivery names");
    let d = sb.run(&["doctor"], b"");
    assert_eq!(d.status.and_then(|s| s.code()), Some(7), "{}", d.combined());

    sb.cleanup();
}

/// An `env_var` alias is the name `run` delivers; `get` must resolve it to
/// the same secret, and a plain var must be readable while a running
/// `run` holds the vault lock.
#[test]
fn get_resolves_aliases_and_reads_vars_without_the_vault() {
    let sb = Sandbox::new("aliasget");
    sb.init_vault();
    let vault_copy = sentinel("ALIAS-VAULT");
    sb.run(&["set", "A", "--stdin"], vault_copy.as_bytes())
        .assert_success("set A");
    let m = sb.manifest_path();
    let text = fs::read_to_string(&m).unwrap();
    fs::write(
        &m,
        text.replacen("name = \"A\"\n", "name = \"A\"\nenv_var = \"OUT\"\n", 1),
    )
    .unwrap();
    declare_var(&sb, "OUT", "plain-copy");
    declare_var(&sb, "PORT", "3000");

    let got = sb
        .run(&["get", "OUT"], b"")
        .assert_success("get OUT")
        .stdout_str();
    assert!(
        got == vault_copy || got == format!("{vault_copy}\n"),
        "get OUT: {got:?}"
    );
    let ran = sb
        .run(&["run", "--", "sh", "-c", "printf '%s' \"$OUT\""], b"")
        .assert_success("run")
        .stdout_str();
    assert_eq!(ran, vault_copy);
    let exported = parse_dotenv(
        &sb.run(&["export"], b"")
            .assert_success("export")
            .stdout_str(),
    );
    assert_eq!(
        exported.get("OUT").map(String::as_str),
        Some(vault_copy.as_str())
    );

    // The child runs `get PORT` while its parent holds the vault lock.
    let mut cmd = sb.command(&["run", "--", "sh", "-c", "\"$EH_BIN\" get PORT"]);
    cmd.env("EH_BIN", bin_path());
    let r = run_with_timeout(cmd, b"", Duration::from_secs(60));
    r.assert_success("get of a plain var while run holds the vault");
    assert!(r.stdout_str().starts_with("3000"), "{}", r.stdout_str());

    sb.cleanup();
}

/// Remove the `[[secret]]` block declaring `name` from a manifest text.
fn drop_secret_block(text: &str, name: &str) -> String {
    let marker = format!("name = \"{name}\"\n");
    let at = text.find(&marker).expect("declaration present");
    let start = text[..at].rfind("[[secret]]").expect("block header");
    let end = text[at..]
        .find("[[secret]]")
        .map(|i| at + i)
        .unwrap_or(text.len());
    format!("{}{}", &text[..start], &text[end..])
}

/// A record stored without a declaration is delivered by no door, so the
/// three doors can never disagree about it, and doctor reports it.
#[test]
fn undeclared_records_are_delivered_nowhere_and_doctor_reports_them() {
    let sb = Sandbox::new("undeclared");
    sb.init_vault();
    let va = sentinel("UND-A");
    let vb = sentinel("UND-B");
    sb.run(&["set", "A", "--stdin"], va.as_bytes())
        .assert_success("set A");
    sb.run(&["set", "B", "--stdin"], vb.as_bytes())
        .assert_success("set B");
    let m = sb.manifest_path();
    let text = drop_secret_block(&fs::read_to_string(&m).unwrap(), "B");
    // A is now delivered as B; the stored, undeclared B must not compete.
    let text = text.replacen("name = \"A\"\n", "name = \"A\"\nenv_var = \"B\"\n", 1);
    fs::write(&m, text).unwrap();

    let got = sb
        .run(&["get", "B"], b"")
        .assert_success("get B")
        .stdout_str();
    assert!(got == va || got == format!("{va}\n"), "get B: {got:?}");
    let ran = sb
        .run(&["run", "--", "sh", "-c", "printf '%s' \"$B\""], b"")
        .assert_success("run")
        .stdout_str();
    assert_eq!(ran, va, "run must deliver A under the alias B");
    let exported = parse_dotenv(
        &sb.run(&["export"], b"")
            .assert_success("export")
            .stdout_str(),
    );
    assert_eq!(exported.get("B").map(String::as_str), Some(va.as_str()));

    let d = sb.run(&["doctor"], b"");
    assert_eq!(d.status.and_then(|s| s.code()), Some(7), "{}", d.combined());
    assert!(
        d.combined().contains("value-but-undeclared: B"),
        "{}",
        d.combined()
    );

    // A vault-only record next to a plain var of the same name: the var is
    // what every door delivers, since the record is declared nowhere.
    sb.run(&["set", "SAME", "--stdin"], b"vault-only")
        .assert_success("set SAME");
    let text = drop_secret_block(&fs::read_to_string(&m).unwrap(), "SAME");
    fs::write(&m, text).unwrap();
    declare_var(&sb, "SAME", "plain-copy");
    let got = sb
        .run(&["get", "SAME"], b"")
        .assert_success("get SAME")
        .stdout_str();
    assert!(got.starts_with("plain-copy"), "{got:?}");
    let ran = sb
        .run(&["run", "--", "sh", "-c", "printf '%s' \"$SAME\""], b"")
        .assert_success("run")
        .stdout_str();
    assert_eq!(ran, "plain-copy");
    let exported = parse_dotenv(
        &sb.run(&["export"], b"")
            .assert_success("export")
            .stdout_str(),
    );
    assert_eq!(exported.get("SAME").map(String::as_str), Some("plain-copy"));

    sb.cleanup();
}

/// Drop every `[[secret]]` block for which `keep` returns false.
fn drop_secret_blocks_where(text: &str, drop: impl Fn(&str) -> bool) -> String {
    let mut parts = text.split("[[secret]]\n");
    let head = parts.next().unwrap_or("").to_owned();
    let kept: Vec<String> = parts
        .filter(|block| !drop(block))
        .map(|block| format!("[[secret]]\n{block}"))
        .collect();
    format!("{head}{}", kept.join(""))
}

/// A record in the selected environment counts only where a declaration
/// governs it there; otherwise the declared base value wins, on every door.
#[test]
fn undeclared_env_record_never_shadows_the_declared_base_value() {
    let sb = Sandbox::new("shadow");
    sb.init_vault();
    let base_value = sentinel("SHADOW-BASE");
    sb.run(&["set", "B", "--stdin"], base_value.as_bytes())
        .assert_success("set B in base");
    sb.run(
        &["--env", "prod", "set", "B", "--stdin"],
        b"prod-undeclared",
    )
    .assert_success("set B in prod");
    let m = sb.manifest_path();
    let text = fs::read_to_string(&m).unwrap();
    let text = drop_secret_blocks_where(&text, |b| {
        b.contains("name = \"B\"") && b.contains("envs = [\"prod\"]")
    });
    assert!(text.contains("envs = [\"base\"]"), "{text}");
    fs::write(&m, text).unwrap();

    let got = sb
        .run(&["--env", "prod", "get", "B"], b"")
        .assert_success("get")
        .stdout_str();
    assert!(
        got == base_value || got == format!("{base_value}\n"),
        "get: {got:?}"
    );
    let ran = sb
        .run(
            &[
                "--env",
                "prod",
                "run",
                "--",
                "sh",
                "-c",
                "printf '%s' \"$B\"",
            ],
            b"",
        )
        .assert_success("run")
        .stdout_str();
    assert_eq!(ran, base_value, "run must deliver the declared base value");
    let exported = parse_dotenv(
        &sb.run(&["--env", "prod", "export"], b"")
            .assert_success("export")
            .stdout_str(),
    );
    assert_eq!(
        exported.get("B").map(String::as_str),
        Some(base_value.as_str())
    );
    let d = sb.run(&["doctor"], b"");
    assert_eq!(d.status.and_then(|s| s.code()), Some(7), "{}", d.combined());
    assert!(
        d.combined().contains("value-but-undeclared: B"),
        "{}",
        d.combined()
    );

    sb.cleanup();
}

/// The reciprocal case: a declaration scoped to prod, backed by a value
/// stored in base, is a supported configuration (base is fallback
/// storage) and must resolve on every door, with doctor content.
#[test]
fn prod_only_declaration_is_satisfied_by_the_base_value() {
    let sb = Sandbox::new("basefallback");
    sb.init_vault();
    let value = sentinel("FALLBACK");
    sb.run(&["set", "B", "--stdin"], value.as_bytes())
        .assert_success("set B in base");
    let m = sb.manifest_path();
    let text = fs::read_to_string(&m).unwrap();
    let text = text.replacen("envs = [\"base\"]\n", "envs = [\"prod\"]\n", 1);
    fs::write(&m, format!("{text}\n[environments]\nnames = [\"prod\"]\n")).unwrap();

    let got = sb
        .run(&["--env", "prod", "get", "B"], b"")
        .assert_success("get")
        .stdout_str();
    assert!(got == value || got == format!("{value}\n"), "get: {got:?}");
    let ran = sb
        .run(
            &[
                "--env",
                "prod",
                "run",
                "--",
                "sh",
                "-c",
                "printf '%s' \"$B\"",
            ],
            b"",
        )
        .assert_success("run")
        .stdout_str();
    assert_eq!(ran, value);
    let exported = parse_dotenv(
        &sb.run(&["--env", "prod", "export"], b"")
            .assert_success("export")
            .stdout_str(),
    );
    assert_eq!(exported.get("B").map(String::as_str), Some(value.as_str()));
    let d = sb.run(&["doctor"], b"");
    assert!(
        d.success(),
        "a base value satisfies a prod declaration:\n{}",
        d.combined()
    );

    sb.cleanup();
}

/// A base value stored at tier 1 must not satisfy a prod declaration at
/// tier 3: every door refuses, and doctor reports it, while base still
/// resolves.
#[test]
fn weaker_base_record_does_not_satisfy_a_stronger_declaration() {
    let sb = Sandbox::new("weakfallback");
    sb.init_vault();
    let value = sentinel("WEAK");
    sb.run(&["set", "B", "--stdin"], value.as_bytes())
        .assert_success("set B in base (tier 1)");
    let m = sb.manifest_path();
    let text = fs::read_to_string(&m).unwrap();
    fs::write(
        &m,
        format!(
            "{text}\n[environments]\nnames = [\"prod\"]\n\n[[secret]]\nname = \"B\"\n\
             envs = [\"prod\"]\ntier = 3\nmode = \"env-var\"\nscope = \"project\"\n"
        ),
    )
    .unwrap();

    for args in [
        &["--env", "prod", "get", "B"][..],
        &["--env", "prod", "run", "--", "true"][..],
        &["--env", "prod", "export"][..],
    ] {
        let r = sb.run(args, b"");
        r.assert_failure(&format!("{args:?} with a weaker fallback record"));
        assert!(
            r.combined().contains("tier 3"),
            "{args:?}: {}",
            r.combined()
        );
        assert!(
            !r.stdout_str().contains(&value),
            "{args:?} leaked the weaker value"
        );
    }
    let d = sb.run(&["doctor"], b"");
    assert_eq!(d.status.and_then(|s| s.code()), Some(7), "{}", d.combined());
    assert!(
        d.combined().contains("tier divergence: B"),
        "{}",
        d.combined()
    );

    // Base itself is unaffected.
    let got = sb
        .run(&["get", "B"], b"")
        .assert_success("get B in base")
        .stdout_str();
    assert!(got == value || got == format!("{value}\n"));

    sb.cleanup();
}

/// When the selected env has its own record, that record is the winner
/// on every door and the base record is never judged: base tier 1 plus a
/// prod override resolve to the prod value with doctor clean. (A prod
/// record ABOVE tier 1 needs a hardware recipient, which the sandbox has
/// none of; the ordering this exercises is the same.)
#[test]
fn selected_env_override_wins_over_the_base_record_on_every_door() {
    let sb = Sandbox::new("override");
    sb.init_vault();
    let base_value = sentinel("OVR-BASE");
    let prod_value = sentinel("OVR-PROD");
    sb.run(&["set", "B", "--stdin"], base_value.as_bytes())
        .assert_success("set B in base");
    sb.run(
        &["--env", "prod", "set", "B", "--stdin"],
        prod_value.as_bytes(),
    )
    .assert_success("set B in prod");

    let got = sb
        .run(&["--env", "prod", "get", "B"], b"")
        .assert_success("get")
        .stdout_str();
    assert!(
        got == prod_value || got == format!("{prod_value}\n"),
        "get: {got:?}"
    );
    let ran = sb
        .run(
            &[
                "--env",
                "prod",
                "run",
                "--",
                "sh",
                "-c",
                "printf '%s' \"$B\"",
            ],
            b"",
        )
        .assert_success("run")
        .stdout_str();
    assert_eq!(ran, prod_value);
    let exported = parse_dotenv(
        &sb.run(&["--env", "prod", "export"], b"")
            .assert_success("export --env prod")
            .stdout_str(),
    );
    assert_eq!(
        exported.get("B").map(String::as_str),
        Some(prod_value.as_str())
    );
    let d = sb.run(&["doctor"], b"");
    assert!(d.success(), "{}", d.combined());
    let base_got = sb
        .run(&["get", "B"], b"")
        .assert_success("get in base")
        .stdout_str();
    assert!(base_got == base_value || base_got == format!("{base_value}\n"));

    sb.cleanup();
}
