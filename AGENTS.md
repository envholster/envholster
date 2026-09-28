# Agent instructions

Env Holster is a single-binary Rust CLI for macOS and Linux that replaces `.env` files with an encrypted vault you can commit to git. The workspace has three crates: `envholster-mem` (locked memory for secret bytes), `envholster-core` (the vault format, encryption and recovery), and `envholster` (the CLI).

After every code change, before reporting done, run `scripts/gate.sh`, the same checks CI runs. It checks that any edit to the root `Cargo.toml` or `Cargo.lock` carries a human sign-off, then runs `cargo fmt --all --check`, `cargo build --workspace --locked`, `cargo test --workspace --locked`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo deny check`, `cargo audit`, the `forbid(unsafe_code)` check, `scripts/recovery-drill.sh`, and the signed-installer and onboarding terminal tests. A check whose tool is missing is reported as SKIP, and a SKIP is not a pass.

Do not add or upgrade dependencies. If a change needs one, stop and say so. Never print or log a secret value, including in tests. Comments explain why, not what.
