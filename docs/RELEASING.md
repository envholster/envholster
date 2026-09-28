# Releasing

How a release is built, signed and published, so that one maintainer can cut it
safely and anyone can verify it with `curl` and OpenSSL.

## What a release contains

| Asset | Purpose |
|---|---|
| `envholster-vX.Y.Z-<target>` | Binaries for `aarch64-apple-darwin`, `x86_64-apple-darwin`, `aarch64-unknown-linux-gnu` and `x86_64-unknown-linux-gnu` |
| `install.sh` | The installer, with the release public key embedded |
| `release-public.pem` | The same public key, for manual checks |
| `release-manifest.txt` | Version, source commit, workflow run and the SHA-256 of every asset |
| `release-manifest.sig` | RSA-3072 signature over the manifest |
| `SHA256SUMS` | The same digests for `sha256sum -c`; unsigned and for convenience only |

The signed manifest is the trust root. Each binary, `install.sh` and the public
key also get a GitHub build provenance attestation.

## Trust model

The installer accepts a release only if the manifest is signed by the key it
embeds. The private key exists in two places: the `RELEASE_SIGNING_KEY` secret
of the protected `release` environment, and an offline backup.

- **Signing needs the maintainer.** The sign job runs in the `release`
  environment and waits for approval after all four builds pass the full gate.
- **Build jobs cannot sign or tamper with each other.** They never see the key.
  The gate and the build run without a token; only the separate upload step
  gets one, and checkout never persists it.
- **Swapped drafts are caught.** The signer re-downloads every draft binary and
  refuses to sign if a digest differs from what its build job reported.
- **Published releases do not change.** Immutable releases lock assets and the
  tag, and a ruleset restricts who can create or move `v*` tags.
- **Provenance is public.** Only the sign job can mint attestations, and it runs
  no dependency code.

The limits: someone who controls the maintainer's GitHub account and can approve
the environment can publish a signed release; a malicious dependency runs during
the build like any build script; builds are not reproducible. A signature shows
who published a build, not that it matches the source.

## Pipeline

1. `prepare` checks that the tag is `vX.Y.Z`, points at the checked-out commit
   and matches the workspace version, and that `release/public-key.pem` parses.
   It creates a draft release.
2. Four build jobs run `scripts/gate.sh` on their native runner, build with
   `--locked`, upload the binary to the draft and report its digest.
3. `sign` waits for approval, re-checks every digest, embeds the public key in
   `install.sh`, writes and signs the manifest, verifies its own signature,
   uploads the metadata and attests every asset.
4. The maintainer checks the draft and publishes it by hand.

## One-time repository setup

On GitHub's Free plan, required reviewers, environment secrets, rulesets and
attestations work only in public repositories, so make the repository public
first.

1. **Create the signing key** on a trusted machine, outside the checkout:

   ```sh
   mkdir -p ~/secure && python3 scripts/release-key.py --private-key ~/secure/envholster-release.pem
   ```

   Commit the generated `release/public-key.pem`, back up the private key
   offline, and publish the fingerprint in SECURITY.md and on envholster.com:

   ```sh
   openssl pkey -pubin -in release/public-key.pem -outform DER | openssl dgst -sha256
   ```

2. **Create the `release` environment:** the maintainer as required reviewer,
   no administrator bypass, deployments limited to `main`, and the secret
   `RELEASE_SIGNING_KEY` holding the private key's PEM text. Leave "prevent
   self-review" off; with one maintainer it would block every release.
3. **Turn on immutable releases.**
4. **Add a tag ruleset for `v*`** that restricts creation, updates and deletion
   to the maintainer and blocks force pushes.
5. **Turn on** private vulnerability reporting, secret scanning with push
   protection, and Dependabot alerts.

## Cutting a release

1. Update `CHANGELOG.md`. A version change in `Cargo.toml` also changes
   `Cargo.lock`, so that commit needs a `Dependency-Change-Approved-By:` trailer.
2. Merge to `main` with CI green on macOS and Linux.
3. Tag and push: `git tag -a v0.2.0 -m "v0.2.0" && git push origin v0.2.0`.
4. Run the workflow from `main`:
   `gh workflow run release.yml --ref main -f tag=v0.2.0`.
5. Approve the `release` environment when `sign` asks.
6. Download the draft with `gh release download v0.2.0 --dir draft`, follow the
   manual checks in [SECURITY.md](../SECURITY.md#verifying-a-release), and run
   the binary through `setup`, `run` and `recovery verify` on a fresh Mac and a
   fresh Linux machine.
7. Write the release notes from the changelog and publish the draft.
8. Run the one-line installer on a fresh machine right away. Published releases
   cannot be edited, so a problem means a new patch version.

## Pinned actions

Each third-party action is pinned to a full commit SHA, with its tag in a
comment. Changing one is a dependency change.

- `actions/checkout` v7.0.1 (`3d3c42e5aac5ba805825da76410c181273ba90b1`), with
  `persist-credentials: false` everywhere.
- `actions/attest` v4.2.2 (`1e69f48acb82d1966a394da916b4c1698aa569d6`), in the
  sign job only.

## Not yet, and why

- **musl Linux builds.** The `ubuntu-22.04` runners retire in April 2027; a
  static musl target with its own gate run should land before then.
- **Homebrew.** A tap with one formula pointing at the release binaries, updated
  by hand at first.
- **macOS notarization.** Not needed for `curl | sh` or Homebrew installs, which
  do not set the quarantine flag.
- **SBOM.** The committed `Cargo.lock` plus a commit-bound signature covers
  0.2; `cargo auditable` is the likely next step.
- **Offline signing.** Signing on a hardware key after checking the build would
  stop a hijacked GitHub account from publishing alone, at the cost of a manual
  step per release.
- **cargo-dist.** Not used: it owns and regenerates the release workflow and
  would replace the per-target gate, the signed manifest and the installer.
