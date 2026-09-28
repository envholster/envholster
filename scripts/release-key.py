#!/usr/bin/env python3
"""Maintainer-only, explicit creation of a release key outside the checkout."""
import argparse
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--private-key", type=Path, required=True)
args = parser.parse_args()
repo = Path(__file__).resolve().parents[1]
private = args.private_key.expanduser().absolute()
public = repo / "release/public-key.pem"
os.umask(0o077)
if private.parent.resolve().is_relative_to(repo) or private.exists() or private.is_symlink() or public.exists():
    parser.exit(1, "Choose a new private-key path outside the checkout. Existing keys are never overwritten.\n")
if not private.parent.is_dir():
    parser.exit(1, "Create the private storage directory first.\n")
try:
    with private.open("xb") as destination:
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"],
                       stdout=destination, stderr=subprocess.DEVNULL, check=True)
    with public.open("xb") as destination:
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout"],
                       stdout=destination, stderr=subprocess.DEVNULL, check=True)
except (OSError, subprocess.CalledProcessError):
    parser.exit(1, "Key provisioning failed. Inspect the destination files before retrying; key material was not displayed.\n")
print("Private key saved with mode 0600 outside the checkout. Review and commit release/public-key.pem.")
print("Register the private key as RELEASE_SIGNING_KEY in the protected GitHub release environment. Keep an offline backup.")
