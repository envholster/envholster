---
name: envholster
description: Launch development apps that use an Envholster vault, including npm run dev, pnpm dev, yarn dev, bun run dev, and other commands that need dotenv credentials. Use only when the command's project contains envholster.toml and secrets.holster, or when the user explicitly asks about Envholster launch setup.
---

# Launch an Envholster app

1. Locate the nearest `envholster.toml` and `secrets.holster` above the command's
   working directory. If neither exists, leave the project's workflow alone.
   If only one exists, report incomplete setup. Never initialize a replacement
   vault to work around a launch failure.
2. Read the project's Envholster launch block in `AGENTS.md` or `CLAUDE.md` and
   the relevant package script. Use its explicit environment. Without a launch
   block or another explicit project instruction, ask which environment to use.
   Never infer production from `build`, `start`, a branch name, or an ambient
   `ENVHOLSTER_ENV` value.
3. For a selected package script already starting with `envholster`, use the
   ordinary package command, such as `npm run dev -- --port 3000`. Do not wrap it
   again. Otherwise launch the authorized app with
   `envholster --env <chosen-environment> run -- <original-command-and-arguments>`.
   Preserve the working directory, package manager, arguments, and shell
   semantics. Quote any shell expression as a single child command rather than
   wrapping only one side of a pipeline. Do not read or execute command text
   extracted from a secret.
4. Use this workflow for app processes that need credentials. Do not wrap the
   coding agent, an interactive shell, package installation, linting, or every
   terminal command. Build, test, migration, and deployment tasks need their own
   explicit environment choice when it differs from the local launch block.
5. Diagnose failures with `envholster setup project --check`, `envholster status`,
   or `envholster list`, which show configuration or names. Do not use `get`,
   `export`, `printenv`, environment dumps, or identity-file reads to debug a
   missing credential. Do not print secrets, add them to instructions, write a
   replacement `.env`, or fall back to an unwrapped launch after a vault error.
   Report the error and the required setup or unlock action.

Use environment injection by default. `--dotenv` creates temporary plaintext
and requires an explicit user decision for a tool that truly needs a file.
An app can read and disclose every value delivered to it. Skills are launch
guidance, not access control; Envholster v1 does not isolate a malicious agent
running as the same OS user. Avoid requesting or logging secret values.
