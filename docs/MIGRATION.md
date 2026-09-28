# Migrating dotenv projects

This guide covers `envholster import` for projects you migrate by hand. Guided
setup (`envholster setup`) runs the same import for you; see the
[install guide](INSTALL.md).

## Import a file

```sh
envholster init
envholster import .env --encrypt-all
```

`--encrypt-all` encrypts every value. Without it, import proposes which
settings could stay in plaintext in `envholster.toml` and writes them only after
you approve the list. The review shows names, never values.

Classification leans toward encryption. A name with a secret marker stays
encrypted even when its value looks like configuration, so `AUTH_TIMEOUT_MS`
and `NEXTAUTH_URL` default to secrets. HTTP(S) URLs with paths, query strings,
fragments or user information default to secrets; database and other URLs do
only when they contain a password. Public prefixes such as `NEXT_PUBLIC_` do
not override these rules; choose `var` in a reviewed decisions file (below) to
keep a setting in plaintext. Reimporting keeps existing secret declarations.

After importing, import asks before deleting the source file and adding ignore
rules. When nobody can answer, as when a coding agent runs it, it keeps the file
and adds the rules. A deleted `.env` is replaced by a comment-only note so tools
that expect the file still find one.

## File precedence

Files are applied left to right; the rightmost definition of a name wins, and
missing files are skipped.

| Import mode | Lowest to highest priority |
|---|---|
| No profile | `.env`, `.env.local` into the selected environment (normally `base`) |
| `--profile nextjs`, development or production | `.env`, `.env.MODE`, `.env.local`, `.env.MODE.local` |
| `--profile nextjs`, test | `.env`, `.env.test`, `.env.test.local` |
| `--profile vite` | `.env`, `.env.local`, `.env.MODE`, `.env.MODE.local` |
| `--map FILE=ENV` | The positional file, then each mapping in order |

The profiles follow the load order documented by
[Next.js](https://nextjs.org/docs/app/guides/environment-variables#environment-variable-load-order)
and [Vite](https://vite.dev/guide/env-and-mode#env-files). They require the
path to be named `.env`, including nested paths such as `config/.env`, which
may be absent if its siblings exist.

- **Next.js** declares `development`, `production` and `test` even when only
  `.env` exists. `.env.local` is copied to development and production but not
  test, matching Next.js.
- **Vite** declares `development`, `production` and any other modes it finds.
  A mode named `base` must be mapped under another name, because `base` is the
  vault's shared environment.

Without a profile, finding a mode-specific file such as `.env.production` or
`.env.development.local` stops the import before anything is written. Choose a
profile or list mappings. A positional mode-specific file needs a matching
`--env` or a mapping for that file:

```sh
envholster --env production import .env.production.local --encrypt-all
envholster import .env.production.local --map .env.production.local=prod --encrypt-all
```

`--map` turns off automatic sibling loading, and it cannot be combined with
`--profile`. Mapping the same file twice changes its environment rather than
importing it twice. Import reports sibling dotenv files it did not use and
files that remain afterward; it does not search beyond that folder.

## Choose the environment at launch

```sh
envholster --env development run -- npm run dev
envholster --env production run -- npm run build
envholster --env test run -- npm test
envholster --env staging run -- npm run build -- --mode staging   # Vite mode
```

`NODE_ENV` and `--mode` do not select the vault environment. Without `--env`,
Env Holster uses `ENVHOLSTER_ENV` if it is set, and otherwise `base`. Managed
values take priority over variables of the same name in the parent shell.
Names starting with `NEXT_PUBLIC_` or `VITE_` can end up in browser bundles;
encrypting them at rest does not make them secret once delivered to a browser.

## Review before applying

```sh
envholster import .env --profile nextjs --plan --encrypt-all
envholster import .env --profile nextjs --plan --json --encrypt-all
```

A plan lists sources, target environments, names, value lengths and
suggestions, and writes nothing to the project. Its digest binds the exact file
contents and environment mapping with a key kept on this machine. To apply a
reviewed plan without prompts, write a decisions file:

```text
version 1
plan <digest from the current plan>
cleanup delete_sources=yes gitignore=yes
decide .env DATABASE_URL secret 1
decide .env PORT var
```

Give exactly one decision for every file and name: `secret 1`, `secret 2`,
`secret 3`, `var` or `skip`. Only `var` stores plaintext. Apply it with the same
profile or mappings, and without `--encrypt-all`:

```sh
envholster import .env --profile nextjs --apply decisions.txt
```

A changed file or mapping invalidates the plan. Duplicate names within a file
need editing and a new plan, or a `skip`. Paths containing spaces cannot be
written in a decisions file; import those interactively.

A name that is a secret in any environment stays encrypted everywhere, so a
plaintext override cannot hide behind a secret fallback; interactive import
promotes such overrides and `--apply` rejects conflicting `var` decisions.
Import never changes the tier of an existing secret.

## Finish

1. Run `envholster list` and start the app in each environment you use.
2. Run `envholster recovery create`, then `envholster doctor`.
3. Restart running apps after changing secrets.
4. Rotate any credential that was ever committed or shared. Deleting a file
   does not erase backups or git history.

The vault is saved before the manifest is written and before any source file is
deleted, but these are separate steps, not one transaction. If a step fails,
the error names the files involved; keep the originals until the app and
`recovery verify` both pass.
