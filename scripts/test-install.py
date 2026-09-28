#!/usr/bin/env python3
"""Offline installer tests with temporary signing keys and no secret output."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True

REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_package", REPO / "scripts/release-package.py")
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


class Installer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory(prefix="envholster-test-keys-")
        cls.private = Path(cls.keys.name) / "private.pem"
        cls.public = Path(cls.keys.name) / "public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(cls.private)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(cls.private), "-pubout", "-out", str(cls.public)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="envholster-installer-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.user = self.root / "home"
        self.user.mkdir()
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.trace = self.root / "executed"
        self.downloads = self.root / "downloads"
        self.install_root = self.root / "install with spaces and 'quotes'"
        self.env = {"PATH": str(self.tools) + os.pathsep + os.environ["PATH"], "HOME": str(self.user), "TMPDIR": str(self.root),
                    "SHELL": "/bin/zsh", "FIXTURE_ROOT": str(self.root), "FIXTURE_TRACE": str(self.trace), "FIXTURE_DOWNLOADS": str(self.downloads), "FIXTURE_SYSTEM": "Darwin", "FIXTURE_ARCH": "arm64"}
        self.executable("uname", '#!/bin/sh\ncase "$1" in -s) echo "$FIXTURE_SYSTEM" ;; -m) echo "$FIXTURE_ARCH" ;; esac\n')
        self.executable("curl", f"#!{sys.executable}\n" + '''import os, pathlib, shutil, sys
args = sys.argv[1:]
assert "--proto" in args and "--proto-redir" in args
url = next(x for x in args if x.startswith("https://github.com/"))
with open(os.environ["FIXTURE_DOWNLOADS"], "a") as trace: trace.write(url + "\\n")
parts = url.split("/")
version = "v0.2.0" if "latest" in parts else parts[-2]
source = pathlib.Path(os.environ["FIXTURE_ROOT"]) / version / parts[-1]
if not source.is_file(): sys.exit(22)
shutil.copyfile(source, args[args.index("--output") + 1])
''')
        self.assets = self.release("v0.2.0")
        self.installer = self.root / "install.sh"
        shutil.copyfile(self.assets / "install.sh", self.installer)

    def executable(self, name, text):
        path = self.tools / name
        path.write_text(text)
        path.chmod(0o700)

    def release(self, version):
        assets = self.root / version
        assets.mkdir()
        for target in PACKAGE.TARGETS:
            path = assets / f"envholster-{version}-{target}"
            path.write_text(f'''#!/bin/sh
printf '%s\\n' "$*" >> "$FIXTURE_TRACE"
if [ "${{1:-}}" = --version ]; then printf 'envholster {version}\\n'; exit 0; fi
if [ -t 0 ]; then printf 'setup-tty\\n' >> "$FIXTURE_TRACE"; fi
''')
        digests = self.root / (version + "-expected.json")
        digests.write_text(json.dumps({target: hashlib.sha256((assets / f"envholster-{version}-{target}").read_bytes()).hexdigest() for target in PACKAGE.TARGETS}))
        args = [sys.executable, str(REPO / "scripts/release-package.py"), "--version", version, "--source", "a" * 40,
                "--run-url", "https://github.com/envholster/envholster/actions/runs/1", "--assets", str(assets),
                "--private-key", str(self.private), "--public-key", str(self.public), "--expected-digests", str(digests)]
        result = subprocess.run(args, capture_output=True)
        self.assertEqual(result.returncode, 0, "fixture packaging failed; output withheld")
        return assets

    def run_install(self, *args):
        return subprocess.run(["/bin/sh", str(self.installer), "--root", str(self.install_root), *args],
                              env=self.env, cwd=self.root, stdin=subprocess.DEVNULL, capture_output=True, timeout=20)

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, "installer failed; output withheld")

    def test_verified_install_setup_and_safe_path_quoting(self):
        self.assert_success(self.run_install("--", "--root", str(self.root), "--all", "--yes"))
        self.assertTrue(self.trace.read_text().startswith("--version\nsetup --root "))
        profile = self.user / ".zshrc"
        self.assertIn("# envholster installer", profile.read_text())
        result = subprocess.run(["/bin/sh", "-c", '. "$HOME/.zshrc"; command -v envholster'], env=self.env, capture_output=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.decode().strip(), str(self.install_root / "bin/envholster"))
        self.assert_success(self.run_install("--no-setup"))
        self.assertEqual(profile.read_text().count("# envholster installer"), 1)

    def test_tampered_binary_never_executes(self):
        (self.assets / "envholster-v0.2.0-aarch64-apple-darwin").write_text("tampered\n")
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertFalse(self.trace.exists())
        self.assertFalse(self.install_root.exists())

    def test_tampered_manifest_never_executes(self):
        with (self.assets / "release-manifest.txt").open("a") as output:
            output.write("asset " + "0" * 64 + " forged\n")
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertFalse(self.trace.exists())

    def test_signer_refuses_asset_replacement_after_build(self):
        for name in ["install.sh", "release-public.pem", "release-manifest.txt", "release-manifest.sig", "SHA256SUMS"]:
            (self.assets / name).unlink()
        (self.assets / "envholster-v0.2.0-aarch64-apple-darwin").write_text("replacement after build\n")
        result = subprocess.run([sys.executable, str(REPO / "scripts/release-package.py"), "--version", "v0.2.0", "--source", "a" * 40,
                                 "--run-url", "https://github.com/envholster/envholster/actions/runs/1", "--assets", str(self.assets),
                                 "--private-key", str(self.private), "--public-key", str(self.public),
                                 "--expected-digests", str(self.root / "v0.2.0-expected.json")], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.assets / "release-manifest.sig").exists())

    def test_bash_login_and_interactive_shell_paths(self):
        self.env["SHELL"] = "/bin/bash"
        self.assert_success(self.run_install("--no-setup"))
        self.assertIn("# envholster installer", (self.user / ".bashrc").read_text())
        self.assertIn("# envholster installer", (self.user / ".profile").read_text())

    def test_failed_download_preserves_existing_installation(self):
        self.assert_success(self.run_install("--no-setup", "--no-path"))
        binary = self.install_root / "bin/envholster"
        original = hashlib.sha256(binary.read_bytes()).hexdigest()
        self.release("v0.3.0")
        (self.root / "v0.3.0/envholster-v0.3.0-aarch64-apple-darwin").unlink()
        self.assertNotEqual(self.run_install("--version", "v0.3.0").returncode, 0)
        self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), original)

    def test_upgrade_rollback_and_uninstall_preserve_user_data(self):
        self.assert_success(self.run_install("--no-setup"))
        original = (self.install_root / "bin/envholster").read_bytes()
        self.release("v0.3.0")
        self.assert_success(self.run_install("--version", "v0.3.0", "--no-setup"))
        self.assertNotEqual((self.install_root / "bin/envholster").read_bytes(), original)
        self.assert_success(self.run_install("--rollback"))
        self.assertEqual((self.install_root / "bin/envholster").read_bytes(), original)
        keep = self.user / ".config/envholster/identity"
        keep.parent.mkdir(parents=True)
        keep.write_text("preserve this fixture\n")
        with (self.user / ".zshrc").open("a") as profile: profile.write("# user instruction\n")
        self.assert_success(self.run_install("--uninstall"))
        self.assertTrue(keep.exists())
        self.assertFalse((self.install_root / "bin/envholster").exists())
        self.assertNotIn("# envholster installer", (self.user / ".zshrc").read_text())
        self.assertIn("# user instruction", (self.user / ".zshrc").read_text())

    def test_unmanaged_binary_and_changed_backup_are_preserved(self):
        binary = self.install_root / "bin/envholster"
        binary.parent.mkdir(parents=True)
        binary.write_text("user managed\n")
        self.assertNotEqual(self.run_install().returncode, 0)
        self.assertEqual(binary.read_text(), "user managed\n")
        binary.unlink()
        self.assert_success(self.run_install("--no-setup"))
        self.release("v0.3.0")
        self.assert_success(self.run_install("--version", "v0.3.0", "--no-setup"))
        (binary.parent / ".envholster-previous").write_text("edited backup\n")
        self.assertNotEqual(self.run_install("--rollback").returncode, 0)

    def test_all_platform_selections_and_unsupported_arch(self):
        for system, arch, target in [("Darwin", "x86_64", "x86_64-apple-darwin"), ("Linux", "x86_64", "x86_64-unknown-linux-gnu"), ("Linux", "aarch64", "aarch64-unknown-linux-gnu")]:
            self.env.update(FIXTURE_SYSTEM=system, FIXTURE_ARCH=arch)
            self.assert_success(self.run_install("--no-setup", "--no-path"))
            self.assertIn(target, self.downloads.read_text())
        self.env["FIXTURE_ARCH"] = "unsupported"
        self.assertNotEqual(self.run_install().returncode, 0)

    def test_piped_installer_gives_setup_a_controlling_terminal(self):
        # Public instructions use bare `sh`; adjacent repository files cannot
        # switch the signed installer to executing a local source helper.
        local = self.root / "workspace"
        local.mkdir()
        (self.root / "crates/envholster").mkdir(parents=True)
        (self.root / "crates/envholster/Cargo.toml").write_text("[package]\n")
        (local / "install-source.sh").write_text('touch "$FIXTURE_ROOT/unexpected-source"\n')
        pid, fd = pty.fork()
        if pid == 0:
            os.chdir(local)
            command = f"cat {shlex.quote(str(self.installer))} | sh -s -- --root {shlex.quote(str(self.install_root))} --no-path"
            os.execve("/bin/sh", ["sh", "-c", command], self.env)
        deadline = time.monotonic() + 20
        status = None
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([fd], [], [], 0.1)
                if ready:
                    try: os.read(fd, 65536)
                    except OSError: pass
                child, result = os.waitpid(pid, os.WNOHANG)
                if child:
                    status = result
                    break
            if status is None:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
            self.assertEqual(status, 0, "piped installer failed; terminal output withheld")
            self.assertIn("setup-tty", self.trace.read_text())
            self.assertFalse((self.root / "unexpected-source").exists())
        finally:
            os.close(fd)


if __name__ == "__main__":
    unittest.main()
