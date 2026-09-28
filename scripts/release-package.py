#!/usr/bin/env python3
"""Package already-gated binaries; never display signing-key material."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

TARGETS = ("aarch64-apple-darwin", "x86_64-apple-darwin",
           "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu")


def package(args):
    if not re.fullmatch(r"v\d+\.\d+\.\d+", args.version):
        raise ValueError("Version must be vX.Y.Z")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source):
        raise ValueError("Source must be an immutable commit SHA")
    if not re.fullmatch(r"https://github.com/envholster/envholster/actions/runs/\d+", args.run_url):
        raise ValueError("Expected the release workflow run URL")
    assets = Path(args.assets)
    key = Path(args.public_key).read_text()
    if not key.startswith("-----BEGIN PUBLIC KEY-----\n") or not key.endswith("-----END PUBLIC KEY-----\n"):
        raise ValueError("Expected a reviewed PEM public key")
    source = Path(__file__).resolve().parent / "install.sh"
    installer = source.read_text()
    if installer.count("RELEASE_PUBLIC_KEY_NOT_CONFIGURED") != 1 or installer.count("source_checkout=yes") != 1:
        raise ValueError("Installer trust-key slot is missing or duplicated")
    outputs = [assets / name for name in ("install.sh", "release-public.pem", "release-manifest.txt", "release-manifest.sig", "SHA256SUMS")]
    if any(p.exists() or p.is_symlink() for p in outputs):
        raise ValueError("Use a fresh asset directory; release metadata is never overwritten")
    binaries = [assets / f"envholster-{args.version}-{target}" for target in TARGETS]
    if any(not p.is_file() or p.is_symlink() or p.stat().st_size == 0 for p in binaries):
        raise ValueError("All four nonempty native binaries are required")
    expected = json.loads(Path(args.expected_digests).read_text())
    if not isinstance(expected, dict) or set(expected) != set(TARGETS):
        raise ValueError("All four trusted build digests are required")
    for target, binary in zip(TARGETS, binaries):
        digest = expected[target]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError("A draft binary does not match its build-job digest")
    installer = installer.replace("source_checkout=yes", "source_checkout=no")
    outputs[0].write_text(installer.replace("RELEASE_PUBLIC_KEY_NOT_CONFIGURED", key.rstrip()))
    outputs[1].write_text(key)
    records = ["envholster-release-v1", f"version {args.version}", f"source {args.source}", f"workflow {args.run_url}"]
    for path in binaries + outputs[:2]:
        records.append(f"asset {hashlib.sha256(path.read_bytes()).hexdigest()} {path.name}")
    outputs[2].write_text("\n".join(records) + "\n")
    # Convenience copy for `sha256sum -c`; the signed manifest stays the trust root.
    sums = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}" for path in binaries + outputs[:2]]
    outputs[4].write_text("\n".join(sums) + "\n")
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", args.private_key,
                    "-out", str(outputs[3]), str(outputs[2])], check=True, capture_output=True)
    subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(outputs[1]),
                    "-signature", str(outputs[3]), str(outputs[2])], check=True, capture_output=True)
    print("Packaged four binaries, installer, public key, checksums and verified signed manifest.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("version", "source", "run-url", "assets", "private-key", "public-key", "expected-digests"):
        parser.add_argument("--" + name, required=True)
    try:
        package(parser.parse_args())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        # OpenSSL diagnostics and input files may contain key material.
        parser.exit(1, f"Release packaging failed ({type(error).__name__}); no assets should be published.\n")
