# Security

## Reporting a vulnerability

Please do not open a public issue. Report privately through
[GitHub's private vulnerability reporting](https://github.com/envholster/envholster/security/advisories/new).

Include what an attacker gains, the steps to reproduce, the OS and
`envholster --version`, and whether the attack needs code running as the user.
Expect a first reply within five working days. This is a one-maintainer
project, so treat that as an estimate.

In scope: decrypting without a matching identity, opening a higher-tier cell
with a software key, tampering or downgrade of the formats, credentials
classified as plaintext without review, diagnostics that reveal values,
recovery verification that passes when it should fail, and cleanup that fails
within the documented lifecycle.

## Review status

Env Holster has **not** had an independent security review. One is planned
before 1.0. The [vault](docs/ENVELOPE-SPEC.md) and
[recovery](docs/RECOVERY-SPEC.md) formats are specified and the code is open;
review of the cryptography, recovery path, secret lifetimes and signal handling
is welcome.

## Threat model

Env Holster is a single-user local vault, and git history is treated as hostile.
The committed files are designed to protect values from anyone who lacks an
enrolled identity.

**Visible to anyone who can read the repository:** secret names, environments,
tiers and modes (the `api-key` mode marks a recognized provider key),
recipients and their labels, plain settings in `envholster.toml`, other header
metadata, and the length of each encrypted cell. Cells hold one environment and
tier and are not padded, so a snapshot shows each cell's total size, comparing
commits shows how much a single changed value grew or shrank, and a cell with
one secret shows roughly that value's length.

**Not protected against:**

- **Code running as you.** It can read a software identity and decrypt the
  vault at any time, run `envholster get`, modify your app, or capture its
  output. File mode 0600 and memory zeroization are not boundaries against the
  same user or root.
- **The app you launch.** `run` gives raw values to the child. Its code,
  dependencies and subprocesses can read and send them, and its output is not
  redacted. Whether other processes can read its environment depends on the OS.
- **Deliberate disclosure.** `get` and `export` print values. `run --dotenv`
  writes a 0600 plaintext file while the child runs. It forwards INT, TERM, HUP
  and QUIT to the child and removes the file when the child exits; a child that
  ignores those signals keeps it in place, SIGKILL, a crash or power loss can
  leave it behind, and detached descendants are not contained.
- **Past exposure.** A key that could open a commit always can: there is no
  recipient removal yet, and removal could never revoke old commits. Deleting a
  file does not erase git history or backups. Rotate exposed values
  with their provider.

**Recovery.** The recovery identity is a master key. `init` parks it on local
disk until `recovery create` proves an offline copy and removes the parked
file; `doctor` reports it until then. `recovery verify` authenticates every
stored cell and compares the whole recovery snapshot with the vault. There is
no external freshness authority: a valid older vault and recovery pair can be
replayed, and verification checks consistency with the vault you supply, not an
attested history.

There is no request broker, agent sandbox, per-use policy, revocable capability
or audit log in this version, and the `api-key` label adds none of them. Access
with an enrolled identity, output a child chooses to print, and a child's use of
credentials it was given are disclosed limits, not vulnerabilities.

## Verifying a release

Each release publishes four native binaries, `install.sh`, the release public
key, `SHA256SUMS`, and `release-manifest.txt` with its signature
`release-manifest.sig`. The manifest records the version, source commit,
workflow run and SHA-256 of every asset, signed with a dedicated RSA-3072 key
held in a protected GitHub environment. The installer embeds the public key and
checks the signature and checksum with the system OpenSSL before running
anything it downloaded. The installer script itself is trusted through GitHub
HTTPS, so download and read it first if your policy requires that.

To check a binary by hand, set the version and target:

```sh
V=v0.2.0 T=aarch64-apple-darwin
base=https://github.com/envholster/envholster/releases/download/$V
curl -fsSL -O "$base/release-manifest.txt" -O "$base/release-manifest.sig" -O "$base/envholster-$V-$T"
curl -fsSL -o release-key.pem "https://raw.githubusercontent.com/envholster/envholster/$V/release/public-key.pem"
openssl pkey -pubin -in release-key.pem -outform DER | openssl dgst -sha256
openssl dgst -sha256 -verify release-key.pem -signature release-manifest.sig release-manifest.txt
grep " envholster-$V-$T\$" release-manifest.txt
openssl dgst -sha256 "envholster-$V-$T"
```

The fingerprint from the `openssl pkey` line must match the one below, the
signature check must print `Verified OK`, and the last two digests must be
equal. A key downloaded next to a binary is not an independent trust anchor,
which is why the fingerprint is also published on
[envholster.com](https://envholster.com).

```text
17205b925898b5a3d14a3c7f7aa34f366081d773b88aff6537f2a591081799c4
```

Each binary, `install.sh` and the public key also carry a GitHub build
provenance attestation:

```sh
gh attestation verify "envholster-$V-$T" -R envholster/envholster
```

Signatures and attestations show who published a build and which workflow
produced it; they do not make builds reproducible. How releases are made is in
[docs/RELEASING.md](docs/RELEASING.md), and build controls are in
[SUPPLY_CHAIN.md](SUPPLY_CHAIN.md).
