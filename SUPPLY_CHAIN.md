# Supply chain

What protects the build and release today, and where the limits are. These are
mechanisms, not certifications.

| Control | Status |
|---|---|
| Dependencies | `Cargo.lock` is committed and every build and test uses `--locked`. Crypto-adjacent crates are pinned exactly in `Cargo.toml`. |
| Dependency approval | Additions and upgrades need human approval. Gate check G0 compares the root `Cargo.toml` and `Cargo.lock` with history and requires a sign-off, as a commit trailer or environment variable. It checks for the marker, not who approved, and it catches changes in pull requests and local runs: on a push straight to `main` it compares the commit with itself. |
| Toolchain | `rust-toolchain.toml` pins Rust 1.96.0. |
| Advisories and licenses | `cargo deny check` and `cargo audit` run in every gate, with policy and exceptions in `deny.toml`. A pass is an advisory check, not an audit. Scheduled monitoring is not set up. |
| CI | `.github/workflows/ci.yml` runs the full gate on macOS and Linux. Third-party actions are pinned to commit SHAs and checkout never persists its token. |
| Unsafe code | `envholster-core` and `envholster` forbid unsafe code. `envholster-mem` holds the locked-memory, signal and terminal code. The check covers this workspace, not its dependencies. |
| Releases | A manual workflow runs the full gate on each of the four targets, builds the binaries, and signs a SHA-256 manifest that binds the source commit and workflow run. Signing needs the maintainer's approval in a protected environment. Build jobs never see the key, and the gate and build steps run without a token. Details: [docs/RELEASING.md](docs/RELEASING.md). |
| Provenance | Each binary, `install.sh` and the public key get a GitHub build provenance attestation (SLSA build provenance, via a SHA-pinned `actions/attest`). |
| Installer | Embeds the release public key and verifies the signature and checksum with the system OpenSSL before running a downloaded binary. The script itself is trusted through GitHub HTTPS. |
| Reproducible builds | Not established. |
| Network use | No telemetry or updater exists. No automated egress test proves it. Your app and optional age plugins are separate programs. |
| Independent review | None yet. One is planned before 1.0. |

## Unsafe code in dependencies

`envholster-mem` uses `memsec` for guarded allocation and `libc` for OS calls,
and other dependencies contain unsafe code too. Before any stronger security
claim, the allocator's failure behavior, locked-memory transitions,
zero-on-free, signal safety, process groups and terminal handling need
independent review at the shipped versions.

## Checking it yourself

```sh
scripts/gate.sh
scripts/recovery-drill.sh
```

The recovery drill decrypts committed test vaults with stock `age` and `jq`
only, using no Env Holster code. To verify a published release, follow
[SECURITY.md](SECURITY.md#verifying-a-release).
