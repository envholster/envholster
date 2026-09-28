# Install

## Release installer

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://github.com/envholster/envholster/releases/latest/download/install.sh | sh
```

The installer picks the binary for macOS (Apple silicon or Intel) or glibc
Linux (x86-64 or ARM64), verifies the signed release manifest and the binary's
checksum with the system OpenSSL, and installs into `~/.local/bin`. It needs
curl and OpenSSL, and no sudo, Rust or Node. Linux binaries are built on
Ubuntu 22.04, so they run on Ubuntu 22.04, Debian 12 and newer; older glibc and
musl systems such as Alpine need a source build.

If `~/.local/bin` is not on your PATH, the installer adds a marked line to your
shell configuration and prints the command to load it now. `--no-path` leaves
shell files alone. It never replaces a binary it did not install.

To read the script before running it:

```sh
curl --proto '=https' --tlsv1.2 -fsSLO https://github.com/envholster/envholster/releases/latest/download/install.sh
less install.sh
sh install.sh
```

[Verifying a release](../SECURITY.md#verifying-a-release) checks a binary by
hand.

## From source

```sh
git clone https://github.com/envholster/envholster && cd envholster
sh scripts/install.sh
```

This builds with the pinned Rust toolchain and locked dependencies, installs
into Cargo's root (`--root DIR` to change it), and opens setup. It does not edit
shell profiles; add the printed `bin` directory to your PATH if asked.

## Guided setup

Both installers open `envholster setup` in an interactive terminal. You can run
it again at any time; it resumes where it stopped.

1. **Pick your projects folder.** Browse with the arrow keys or paste a path.
   Setup remembers it.
2. **Select projects.** Space toggles, `/` searches, Enter continues.
   Dependency and hidden folders are skipped, and unselected projects are left
   alone.
3. **Review the plan.** For each project: the files to import, the number of
   values, the launch command, the instruction files it will write, any files
   it will keep because git tracks them, and scripts it will not wrap. Setup
   reads `package.json` to detect Next.js, Vite and the package manager; it
   never runs project code.
4. **Choose where recovery files go.** Use a folder outside every project,
   ideally removable storage. Each project gets its own private recovery file.
   Saving on this computer needs explicit confirmation.
5. **Choose coding-agent guidance** for the Codex, Claude Code or Cursor
   installs it finds. This is optional and advisory.
6. **Protect and verify.** Setup creates each vault, encrypts every value,
   verifies what it stored, wires the `dev` script, and proves the recovery
   file opens the vault. Only then does it remove the originals, leaving a
   short note in `.env`. Files that git tracks are kept, because deleting a
   committed file leaves its values in history and can break builds that read
   it; setup says how to finish once nothing depends on them.

Setup wraps an npm-compatible `dev` script and its `predev` and `postdev`
hooks, so you keep typing `npm run dev`. It does not wrap `build`, `start` or
`preview`; its plan shows how to run them through `envholster run`, such as
`envholster --env production run -- npm run build` for Next.js and Vite.
Yarn scripts, custom shells, monorepo packages and non-JavaScript commands need
their launch command wired by hand, and setup prints it.

Setup leaves a project's files untouched and reports it for review when
scripts read dotenv files directly (such as `node --env-file`), or when a file
uses interpolation, backslashes, backticks, duplicate names or ambiguous
comments. Import those with `envholster import`, described in the
[migration guide](MIGRATION.md). It never removes `.env.example`, nested dotenv
files, unrecognized files, git history or backups.

### Without prompts

```sh
envholster setup --root ~/Projects --plan
envholster setup --root ~/Projects --project web --project api --yes \
  --recovery-dir /Volumes/Backup/envholster --no-agents
```

`--plan` shows the plan and changes no project files (the first run creates a
local key used to fingerprint plans). `--yes` needs explicit
`--project` selections or `--root … --all`. `--plain` uses numbered menus for
screen readers. `--keep-sources` keeps every original and reports the project
as incomplete. `--recovery-file PATH` reuses an existing recovery key for one
project, and `--allow-same-disk` accepts a recovery folder on this computer.
Pass setup options to an installer after `--`.

Setup keeps a small journal per project with paths, choices and keyed
fingerprints, never values. On a rerun it rechecks the vault, launch files and
recovery copy before doing anything else. If a source file changed since the
plan, it is kept; `--restart` reviews a fresh plan while keeping the vault and
recovery key. Run `envholster doctor` in a project to check everything setup
configured.

## Upgrade, roll back, remove

Run the installer again to upgrade. With a downloaded `install.sh`:

```sh
sh install.sh --no-setup                   # upgrade
sh install.sh --version v0.2.0 --no-setup  # a specific version
sh install.sh --rollback                   # the previous binary
```

The installer keeps one previous binary for rollback and refuses to replace a
binary whose receipt does not match. A saved installer keeps trusting the key
it embeds, so a key rotation means reviewing a new installer.

To remove Env Holster, first undo project wrappers and any global agent
guidance, then uninstall:

```sh
envholster setup project --remove
envholster setup agents --app codex,claude,cursor --remove
sh install.sh --uninstall
```

Uninstall keeps vaults, identities, recovery files and project configuration.
For a source install, use `cargo uninstall envholster`.
