# Release signing key

`public-key.pem` is the public half of the RSA-3072 key that signs every release
manifest. The installer embeds it and refuses anything signed by another key.
Its SHA-256 fingerprint is published in
[SECURITY.md](../SECURITY.md#verifying-a-release) and on envholster.com.

The private half lives only in the protected `release` environment and an
offline backup. `scripts/release-key.py --private-key PATH` generates a key
pair, writing the public half here and never printing the private half; it
refuses to run while `public-key.pem` exists.

Rotating the key is a reviewed source change that ships a new installer.
Installers already downloaded fail closed on signatures from the new key. The
manifest records the source commit and workflow run; that is signed publisher
provenance, not an independent build attestation. See
[docs/RELEASING.md](../docs/RELEASING.md) for the full process.
