# Changelog

## 0.2.0

The first public release. It has not had an independent security review; see
[SECURITY.md](SECURITY.md).

- **Guided setup** (`envholster setup`) migrates many projects in one reviewed
  pass. It encrypts every value, saves and verifies a separate recovery key,
  wires the `dev` script, and only then removes the plaintext files. It keeps
  files that git tracks, names the build scripts it leaves unwrapped, and lists
  the instruction files it writes.
- **Manual commands:** `init`, `import`, `run`, `set`, `get`, `list`, `rm`,
  `export`, `recipient`, `identity`, `recovery`, `status` and `doctor`.
- **Framework profiles** for Next.js and Vite import layered dotenv files in
  each framework's order.
- **`run --dotenv`** writes a temporary 0600 `.env` for tools that read a file,
  and removes it when the command exits.
- **Recovery** with a separate key and a committed snapshot that restores with
  stock `age` and `jq`.
- **Signed installer** that verifies the release manifest and checksum with the
  system OpenSSL, plus GitHub build provenance attestations for the binaries,
  the installer and the public key.
