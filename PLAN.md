# Plan

## What 0.2 is

A single-user CLI for macOS and Linux that does one job: take secrets out of
plaintext project files without changing how apps get their environment, and
make recovery dependable. Secrets live in an encrypted `secrets.holster`;
settings you approve stay in `envholster.toml`; `run` decrypts locally and
hands raw values to the child. The format already supports several recipients
and tiers, but that does not make this a team product.

It protects committed files from readers without a key and cuts accidental
exposure in editor and agent workflows. It does not stop code running as you:
such code can read a software key, call the CLI, or change the app. A rule in an
agent's prompt is not an isolation boundary.

## Next: a boundary for agents

The next milestone makes a stolen or misused credential worth much less. It
needs three controls working together:

1. **Trusted custody.** Root credentials live outside the agent's filesystem
   and user, with a defined way to unlock them.
2. **Workload isolation.** Authorization binds to a workload the agent cannot
   impersonate or modify after approval, with filesystem, process and network
   limits where the policy needs them.
3. **Scoped use.** A workload asks a broker for a capability limited by
   upstream, operation, project, lifetime and budget, instead of fetching a
   root key.

A daemon alone does not provide these, and neither does swapping a key for an
unrestricted proxy token. The plan is to start with one provider and an
end-to-end boundary tested against credential extraction, unauthorized
operations, cross-project access and replay. Use and denials get recorded
without values, and revocation stops new use while acknowledging credentials
already issued. Raw environment injection stays available as a disclosed
compatibility mode.

## Later: sharing

Users and devices, project membership, recipient lifecycle, short-lived
credentials, provider rotation, attributable use and organization policy.
Encrypting a shared file cannot revoke access to history, so this comes after
the agent boundary, and only once migrations, multi-app use and recovery work
reliably for individuals.

## Principles

- **Keep the formats stable.** Changes to cell authentication or saving need a
  versioned migration, test vectors, recovery drills and an independent
  cryptographic review.
- **Describe only what ships.** Docs and claims cover landed, tested behavior.
- **Dependencies need human approval.**

No independent security review has happened yet; one is planned before 1.0.
