# Contributing

Thanks for helping. Env Holster is one Rust workspace, and every change goes
through the same checks CI runs.

## Build and test

You need macOS 13+ or Linux. `rust-toolchain.toml` pins the toolchain, and
rustup installs it automatically.

```sh
cargo build --workspace --locked
cargo test --workspace --locked
scripts/gate.sh
```

The gate runs formatting, build, tests, clippy with warnings denied,
`cargo deny`, `cargo audit`, the unsafe-code check, a cold recovery drill with
`age` and `jq`, and the installer and onboarding tests. A check whose tool is
missing reports SKIP, and a SKIP is not a pass. The package-script tests need
Node.js.

## Ground rules

- **Describe only what ships.** Docs, including [PLAN.md](PLAN.md) and
  [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md), must match the code. Fix whichever is
  wrong in the same change.
- **Dependencies need human approval.** The lockfile is committed and
  crypto-adjacent crates are pinned exactly. Changes to the root `Cargo.toml` or
  `Cargo.lock` need a `Dependency-Change-Approved-By:` trailer.
- **Never print a secret**, including in tests and failure messages. Use
  synthetic values.
- **Comments explain why**, not what.

## Issues

Use the issue forms. Report anything with security impact privately, as
described in [SECURITY.md](SECURITY.md).
