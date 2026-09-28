# Agent and launch setup

Env Holster can teach coding agents to start your app through `envholster run`
instead of reading keys or recreating a `.env`. The guidance applies only to
projects with both `envholster.toml` and `secrets.holster`.

It is advisory. Your app still receives raw values, and an agent running as your
user can still decrypt the vault. Nothing here installs a command interceptor,
sandbox or secret broker. Run the agent itself outside the environment that
receives keys.

## Global guidance

```sh
envholster setup agents                                     # apps it detects
envholster setup agents --app codex,claude,cursor           # chosen apps
envholster setup agents --app codex,claude,cursor --check
envholster setup agents --app codex,claude,cursor --remove
```

Without `--app`, setup looks for each app's configuration directory or
executable on PATH. It never runs an agent.

| App | What it installs |
|---|---|
| Codex | Skill at `~/.agents/skills/envholster/SKILL.md`, and a marked block in the global `AGENTS.md` (or a nonempty `AGENTS.override.md`) under `CODEX_HOME`, default `~/.codex` |
| Claude Code | Skill at `~/.claude/skills/envholster/SKILL.md` and rule at `~/.claude/rules/envholster.md`, under `CLAUDE_CONFIG_DIR` if set |
| Cursor | The same shared skill as Codex; the project rule comes from project setup |

Codex and Cursor share one skill file, and removing one app's guidance keeps it
for the other. Cursor may also show the Claude copy; both say the same thing.
Cursor's global User Rules live in its settings UI, which setup does not edit.
Local skills do not reach remote or cloud agents.

Restart agent sessions afterward. `--check` confirms the files are in place; it
cannot prove an app loaded them or that a model follows them, so try a
development launch in a throwaway project first.

## Project instructions

Guided setup writes these for you. To add them to a project you migrated by
hand:

```sh
envholster setup project --env development
envholster setup project --check
```

Choose `base` or an environment declared in `envholster.toml`;
`ENVHOLSTER_ENV` is ignored here. Setup records the choice in a marked block in
`AGENTS.md` (or a nonempty `AGENTS.override.md`) and `CLAUDE.md`, and in
`.cursor/rules/envholster.mdc`. Commit these files.

The instructions tell agents to use the project's existing launch scripts, keep
the working directory and arguments, and never wrap a command twice. If a
launch fails, agents should report the error and use names-only diagnostics
rather than exporting keys, writing a `.env`, or launching without the wrapper.
The recorded environment guides local launches; it is not an access policy, so
choose environments for builds, tests and deploys separately.

## Wrap an npm script

```sh
envholster setup project --env development --npm-script dev
npm run dev -- --port 3000
```

This rewrites only the named scripts in the root `package.json`, so `npm run
dev` goes through Env Holster. Repeat `--npm-script` to wrap more. The original
command is saved under `envholsterSetup` in `package.json` so it can be checked
and restored, which means that metadata contains the original command text:
keep credentials out of scripts. Node.js is needed for this step; setup never
runs package scripts or installs packages.

The wrapper runs the original script in `/bin/sh` with its arguments, preserving
quotes, shell operators, the working directory and the exit status for npm's
default shell. Custom `script-shell` settings and monorepo packages need manual
wiring. Hooks such as `predev` run outside a wrapped `dev` unless you wrap them
too; guided setup does this for existing development hooks. Never wrap package
installation or the agent itself. For other tools, launch explicitly:

```sh
envholster --env development run -- pnpm dev
envholster --env development run -- python manage.py runserver
```

Setup refuses to wrap a script that already contains an Env Holster wrapper.

## Updating and removing

Rerunning setup with the same choices changes nothing. Text outside the marked
blocks is preserved. Setup checks every file before writing and stops rather
than overwrite a conflicting skill, a hand-edited block or script, a symlink or
a hard link. Writes are atomic, and a failed run tries to restore the files it changed and
says so if it cannot.

```sh
envholster setup project --remove
envholster setup agents --app codex,claude,cursor --remove
```

Removal restores the original npm commands and keeps unrelated `package.json`
edits. To change a project's recorded environment, remove its setup and run it
again. Neither command touches vaults, identities or the binary. `--check`
exits 0 when everything matches and 7 when setup is missing.

The file locations follow the official documentation for
[Codex skills](https://learn.chatgpt.com/docs/build-skills) and
[AGENTS.md](https://learn.chatgpt.com/docs/agent-configuration/agents-md),
[Claude Code skills](https://code.claude.com/docs/en/skills) and
[memory](https://code.claude.com/docs/en/memory), and Cursor
[skills](https://cursor.com/docs/skills) and [rules](https://cursor.com/docs/rules).
