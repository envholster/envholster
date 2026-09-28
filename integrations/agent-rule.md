For development launches, check whether the command's project has
`envholster.toml` and `secrets.holster`. In a managed project, follow the
Envholster skill and the project's Envholster launch block. Use its explicit
environment with `envholster --env <environment> run -- <app-command>`.
Run package scripts that already wrap Envholster normally, without a second
wrapper. Preserve the working directory and arguments. If the environment is
unspecified, ask before launching. Leave unmanaged projects alone.

Keep the coding agent outside the injected environment. Do not obtain values
with `get`, `export`, environment dumps, or identity-file reads, and do not
recreate `.env` files as a fallback. Use names-only diagnostics. A skill guides
launches; it does not enforce an agent security boundary.
