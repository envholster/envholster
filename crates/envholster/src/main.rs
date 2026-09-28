//! envholster — replace `.env` files with a vault you can commit to git.
//!
//! One binary; every command decrypts in-process with the identity at
//! `~/.config/envholster/identities/` (PLAN.md). No subcommand takes a secret
//! value on argv: `set` reads via a no-echo prompt or `--stdin` into a
//! pre-sized locked buffer; `list`/`status` never emit values; `--env`
//! resolves `--env` → `ENVHOLSTER_ENV` → `base`; headless identity
//! resolution is `--identity` → `ENVHOLSTER_IDENTITY` →
//! `ENVHOLSTER_IDENTITY_FILE` → the identity directory.
//!
//! Errors are machine-actionable: stable codes, the exact next command, and
//! a JSON error line on stderr. Exit classes: 0 success, 1 generic, 2 usage
//! (clap), 3 not-found, 4 denied, 5 locked, 6 parse, 7 doctor findings.

#![forbid(unsafe_code)]

mod commands;
mod context;
mod errors;
mod exec;
mod manifestio;
mod materialize;
mod onboarding;
mod setup;
mod setup_ui;

use std::path::PathBuf;

use clap::Parser;

use crate::context::Session;
use crate::errors::{CliError, EXIT_OK};

#[derive(clap::Parser)]
#[command(
    name = "envholster",
    version,
    about = "Replace .env files with a vault you can commit to git",
    long_about = "Replace .env files with a vault you can commit to git.\n\n\
        Secrets live encrypted in secrets.holster; plain settings live in envholster.toml; \
        `envholster run -- <cmd>` assembles the environment for your command. \
        Start with `envholster init`, then `envholster import .env`."
)]
pub struct Cli {
    /// Which environment to use (base, development, production, ...). Also
    /// read from ENVHOLSTER_ENV.
    #[arg(long, global = true)]
    pub env: Option<String>,
    /// Use this identity file instead of the ones in ~/.config/envholster/identities
    /// (CI and headless machines).
    #[arg(long, global = true)]
    pub identity: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand)]
pub enum Command {
    /// Choose projects and guide them through import, launch setup and recovery.
    #[command(args_conflicts_with_subcommands = true)]
    Setup {
        #[command(flatten)]
        options: onboarding::Options,
        #[command(subcommand)]
        action: Option<setup::SetupCommand>,
    },
    /// Create a vault in this directory (machine key, manifest, recovery key).
    Init {
        /// An age public key to enroll as a recipient (repeatable).
        #[arg(long)]
        recipient: Vec<String>,
        /// Machine loss: re-enroll this machine with the offline recovery
        /// identity (a file path, or `-` to paste it).
        #[arg(long, value_name = "IDENTITY_FILE|-")]
        recover_from: Option<String>,
    },
    /// Bring an existing .env file into the vault (secrets) and manifest (config).
    #[command(
        long_about = "Bring an existing .env file into the vault (secrets) and \
        manifest (config).\n\n\
        Use --encrypt-all to encrypt every value. Otherwise proposed plaintext settings \
        require explicit approval. With a .env path, .env.local is included automatically \
        only when no mode-specific files exist. Choose --profile nextjs or --profile vite \
        for framework precedence, or list ordered --map FILE=ENV arguments. A positional \
        .env.production or .env.production.local requires --env production or a mapping \
        for that file. Afterwards import offers source deletion and .gitignore rules, \
        leaving a comment-only .env when it deletes that file.\n\n\
        Values are never printed. Review first with --plan; apply a reviewed decisions file \
        with --apply."
    )]
    Import {
        #[command(flatten)]
        options: commands::importcmd::ImportOptions,
        /// The dotenv file to import (default: .env).
        path: Option<PathBuf>,
        /// Import a file into a specific environment: --map .env.production=production
        /// (repeatable; disables the automatic layered-file mapping).
        #[arg(long)]
        map: Vec<String>,
        /// Show what would be imported and how each line would be classified,
        /// without writing anything.
        #[arg(long, conflicts_with_all = ["apply", "detect"])]
        plan: bool,
        /// Apply a reviewed decisions file instead of answering prompts.
        #[arg(long, conflicts_with = "detect")]
        apply: Option<PathBuf>,
        /// List the dotenv files in this directory (names only; nothing is read).
        #[arg(long)]
        detect: bool,
        /// Machine-readable output for --plan / --apply / --detect.
        #[arg(long)]
        json: bool,
    },
    /// Create or update a secret (value from a no-echo prompt, or --stdin).
    Set {
        name: String,
        /// Tier for a NEW secret: 1 (default); 2 or 3 need a hardware recipient.
        #[arg(long)]
        tier: Option<u8>,
        /// Read the value from stdin instead of prompting.
        #[arg(long)]
        stdin: bool,
    },
    /// Print one value: a plain setting from envholster.toml, or a decrypted secret.
    Get { name: String },
    /// List secrets and declared settings (names and metadata, never values).
    List,
    /// Remove a secret from the selected environment.
    Rm { name: String },
    /// Print every setting and secret for the selected environment.
    Export {
        #[arg(long, value_enum, default_value_t = ExportFormat::Dotenv)]
        format: ExportFormat,
    },
    /// Run a command with the environment assembled: envholster run -- npm run dev
    #[command(long_about = "Run a command with the environment assembled.\n\n\
        Every setting from envholster.toml and every secret this machine can decrypt goes \
        into the command's environment, with ${NAME} references expanded. stdin, stdout, \
        stderr, the working directory, and the exit code pass straight through.\n\n\
        --dotenv also writes the same set to a temporary .env (mode 0600, deleted when the \
        command exits) for tools that read a file instead of the environment. A value no dotenv \
        reader encodes unambiguously (a carriage return; a single quote or line break with $, \\, \
        \" or a tab; a doubled or trailing backslash) is refused there and still reaches the \
        environment. Put the \
        command after `--`: envholster run --dotenv -- prisma migrate dev")]
    Run {
        /// Also write a temporary 0600 dotenv file (default: ./.env), removed on exit.
        #[arg(long, value_name = "PATH", num_args = 0..=1)]
        dotenv: Option<Option<PathBuf>>,
        /// Everything after `--`: the command and its arguments.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        cmd: Vec<String>,
    },
    /// Who can open the vault: enroll a teammate, CI, or a hardware key.
    Recipient {
        #[command(subcommand)]
        action: RecipientCmd,
    },
    /// The offline recovery key: move it off this machine, or verify it.
    Recovery {
        #[command(subcommand)]
        action: RecoveryCmd,
    },
    /// This machine's keys.
    Identity {
        #[command(subcommand)]
        action: IdentityCmd,
    },
    /// Vault, environments, cells, and badges (never values).
    Status {
        /// One JSON document instead of the human view.
        #[arg(long)]
        json: bool,
    },
    /// Check this machine and project; exit 7 when something needs fixing.
    Doctor,
    /// git merge driver for secrets.holster (wired up by init/import; git calls it).
    #[command(hide = true)]
    MergeDriver {
        base: PathBuf,
        ours: PathBuf,
        theirs: PathBuf,
    },
    /// git merge driver for secrets.holster.recovery.age (git calls it).
    #[command(hide = true)]
    MergeDriverBlob {
        base: PathBuf,
        ours: PathBuf,
        theirs: PathBuf,
    },
}

#[derive(clap::Subcommand)]
pub enum RecipientCmd {
    /// Enroll an age public key (age1..., age1yubikey1..., age1se1...).
    Add {
        encoded: String,
        /// A name for this recipient (a person, a machine, "ci", "yubikey").
        #[arg(long)]
        label: String,
        /// software (default) for age1... keys; hardware for age1yubikey1.../age1se1...
        #[arg(long, value_enum, default_value_t = ClassArg::Software)]
        class: ClassArg,
        /// Limit the recipient to these environments (repeatable; default: all).
        #[arg(long)]
        env: Vec<String>,
        /// Highest tier this recipient may open (software: 1; hardware: 3).
        #[arg(long)]
        max_tier: Option<u8>,
    },
    /// List enrolled recipients.
    List {
        #[arg(long)]
        json: bool,
    },
}

#[derive(clap::Subcommand)]
pub enum RecoveryCmd {
    /// Move the recovery key to paper or removable media and prove the copy works.
    Create {
        /// Write the identity file to this path (removable media).
        #[arg(long, value_name = "PATH", conflicts_with = "paper")]
        to: Option<PathBuf>,
        /// Show the identity once for a paper copy (re-entry proves it was written down).
        #[arg(long)]
        paper: bool,
        /// Accept a --to path on this machine's own disk (refused otherwise, because
        /// losing the machine would then lose the recovery key too).
        #[arg(long, requires = "to")]
        allow_same_disk: bool,
    },
    /// Prove the stored recovery key opens every cell and matches the recovery blob.
    Verify,
}

#[derive(clap::Subcommand)]
pub enum IdentityCmd {
    /// Generate an X25519 identity file (0600) under ~/.config/envholster/identities.
    Generate {
        /// File name for the identity (default: local).
        #[arg(long, default_value = "local")]
        label: String,
    },
    /// List identity files and their public keys.
    List,
    /// Copy an existing age identity file into the identity directory.
    Import { path: PathBuf },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ClassArg {
    Software,
    Hardware,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ExportFormat {
    /// KEY=value lines.
    Dotenv,
    /// One JSON document with per-entry metadata.
    Json,
    /// `export KEY='value'` lines for `eval`.
    Shell,
}

fn main() {
    // plan/03 §3.4: RLIMIT_CORE={0,0} in all profiles; PR_SET_DUMPABLE(0) on
    // Linux — before anything touches secret material.
    envholster_mem::harden_process();
    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(code) => code,
        Err(error) => {
            error.emit();
            error.exit
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli) -> Result<i32, CliError> {
    // Instruction setup must work without opening an identity or a vault.
    if let Command::Setup { action, options } = &cli.command {
        return setup::run(action.as_ref(), cli.env.as_deref(), options, &cli.identity);
    }
    let mut session = Session::new(&cli.env, &cli.identity)?;
    match &cli.command {
        Command::Setup { .. } => unreachable!("setup is handled before identity discovery"),
        Command::Init {
            recipient,
            recover_from,
        } => {
            commands::init::run(&mut session, recipient, recover_from.as_deref())?;
            Ok(EXIT_OK)
        }
        Command::Import {
            options,
            path,
            map,
            plan,
            apply,
            detect,
            json,
        } => {
            if *detect {
                commands::importcmd::detect(*json)?;
            } else {
                // No path means `.env` in the current directory — the file
                // every tool means by "the env file". `import` itself picks up
                // the layered siblings (.env.local, .env.development,
                // .env.production) when they exist beside it.
                let default_path = PathBuf::from(".env");
                let path: &std::path::Path = path.as_deref().unwrap_or(&default_path);
                if *plan {
                    commands::importcmd::plan(&session, path, map, *json, options)?;
                } else if let Some(decisions) = apply {
                    commands::importcmd::apply(&mut session, path, map, decisions, *json, options)?;
                } else {
                    commands::importcmd::run(&mut session, path, map, options)?;
                }
            }
            Ok(EXIT_OK)
        }
        Command::Set { name, tier, stdin } => {
            commands::secret::set(&mut session, name, *tier, *stdin)?;
            Ok(EXIT_OK)
        }
        Command::Get { name } => {
            commands::secret::get(&mut session, name)?;
            Ok(EXIT_OK)
        }
        Command::List => {
            commands::secret::list(&mut session)?;
            Ok(EXIT_OK)
        }
        Command::Rm { name } => {
            commands::secret::rm(&mut session, name)?;
            Ok(EXIT_OK)
        }
        Command::Export { format } => {
            commands::exportcmd::run(&mut session, format)?;
            Ok(EXIT_OK)
        }
        Command::Run { dotenv, cmd } => commands::run::run(&mut session, dotenv.clone(), cmd),
        Command::Recipient { action } => {
            match action {
                RecipientCmd::Add {
                    encoded,
                    label,
                    class,
                    env,
                    max_tier,
                } => commands::recipient::add(&mut session, encoded, label, class, env, *max_tier)?,
                RecipientCmd::List { json } => commands::recipient::list(&mut session, *json)?,
            }
            Ok(EXIT_OK)
        }
        Command::Recovery { action } => {
            match action {
                RecoveryCmd::Create {
                    to,
                    paper,
                    allow_same_disk,
                } => commands::recovery::create(
                    &mut session,
                    to.as_deref(),
                    *paper,
                    *allow_same_disk,
                )?,
                RecoveryCmd::Verify => commands::recovery::verify(&mut session)?,
            }
            Ok(EXIT_OK)
        }
        Command::Identity { action } => {
            match action {
                IdentityCmd::Generate { label } => commands::identity::generate(label)?,
                IdentityCmd::List => commands::identity::list()?,
                IdentityCmd::Import { path } => commands::identity::import(path)?,
            }
            Ok(EXIT_OK)
        }
        Command::Status { json } => {
            commands::status::run(&mut session, *json)?;
            Ok(EXIT_OK)
        }
        Command::Doctor => commands::doctor::run(&mut session),
        Command::MergeDriver { base, ours, theirs } => {
            commands::merge_driver::run(&mut session, base, ours, theirs)
        }
        Command::MergeDriverBlob { ours, .. } => commands::merge_driver::run_blob(ours),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_takes_no_value_on_argv() {
        let cli = Cli::try_parse_from(["envholster", "set", "API_KEY", "--stdin"]).unwrap();
        match cli.command {
            Command::Set { name, tier, stdin } => {
                assert_eq!(name, "API_KEY");
                assert_eq!(tier, None);
                assert!(stdin);
            }
            _ => panic!("expected set"),
        }
        // A second positional would be a value on argv: refused by the tree.
        assert!(Cli::try_parse_from(["envholster", "set", "API_KEY", "sk-live"]).is_err());
    }

    #[test]
    fn run_dotenv_takes_an_optional_path_before_the_command() {
        let cli =
            Cli::try_parse_from(["envholster", "run", "--dotenv", "--", "sh", "-c", "x"]).unwrap();
        match cli.command {
            Command::Run { dotenv, cmd } => {
                assert_eq!(dotenv, Some(None));
                assert_eq!(cmd, vec!["sh", "-c", "x"]);
            }
            _ => panic!("expected run"),
        }
        let cli = Cli::try_parse_from([
            "envholster",
            "run",
            "--dotenv",
            ".env.tmp",
            "--",
            "npm",
            "run",
            "dev",
        ])
        .unwrap();
        match cli.command {
            Command::Run { dotenv, cmd } => {
                assert_eq!(dotenv, Some(Some(PathBuf::from(".env.tmp"))));
                assert_eq!(cmd, vec!["npm", "run", "dev"]);
            }
            _ => panic!("expected run"),
        }
        let cli = Cli::try_parse_from(["envholster", "run", "--", "env"]).unwrap();
        match cli.command {
            Command::Run { dotenv, cmd } => {
                assert_eq!(dotenv, None);
                assert_eq!(cmd, vec!["env"]);
            }
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn recipient_add_defaults_to_software_class() {
        let cli =
            Cli::try_parse_from(["envholster", "recipient", "add", "age1abc", "--label", "ci"])
                .unwrap();
        match cli.command {
            Command::Recipient {
                action:
                    RecipientCmd::Add {
                        class,
                        max_tier,
                        env,
                        ..
                    },
            } => {
                assert_eq!(class, ClassArg::Software);
                assert_eq!(max_tier, None);
                assert!(env.is_empty());
            }
            _ => panic!("expected recipient add"),
        }
    }

    #[test]
    fn export_defaults_to_dotenv_and_recovery_create_is_exclusive() {
        let cli = Cli::try_parse_from(["envholster", "export"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Export {
                format: ExportFormat::Dotenv
            }
        ));
        assert!(Cli::try_parse_from([
            "envholster",
            "recovery",
            "create",
            "--paper",
            "--to",
            "/Volumes/usb/k.txt",
        ])
        .is_err());
        let cli = Cli::try_parse_from(["envholster", "init", "--recover-from", "-"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Init { recover_from: Some(ref s), .. } if s == "-"
        ));
    }

    #[test]
    fn removed_verbs_are_gone() {
        for verb in [
            "add",
            "edit",
            "rotate",
            "check",
            "daemon",
            "lock",
            "unlock",
            "ssh",
            "grant",
            "approval",
            "audit",
            "service",
            "mcp",
            "integrate",
            "pool",
            "request-secrets",
        ] {
            assert!(
                Cli::try_parse_from(["envholster", verb]).is_err(),
                "{verb} should not parse"
            );
        }
    }
}
