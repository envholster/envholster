#!/usr/bin/env python3
"""Exercise the real terminal wizard in disposable projects; withhold terminal output."""
import argparse
import os
from pathlib import Path
import pty
import select
import signal
import tempfile
import termios
import time


class Terminal:
    def __init__(self, binary, root, args):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(root / "projects")
            env = {"HOME": str(root / "home"), "XDG_CONFIG_HOME": str(root / "home/.config"),
                   "TMPDIR": str(root), "TERM": "xterm-256color", "PATH": os.environ["PATH"]}
            os.execve(binary, [str(binary), "setup", *args], env)
        self.original = termios.tcgetattr(self.fd)
        self.buffer = b""
        self.status = None

    def expect(self, text):
        deadline = time.monotonic() + 15
        target = text.encode()
        while target not in self.buffer:
            if time.monotonic() > deadline:
                raise AssertionError(f"Wizard did not reach {text!r}; terminal output withheld")
            ready, _, _ = select.select([self.fd], [], [], 0.1)
            if ready:
                try:
                    data = os.read(self.fd, 65536)
                except OSError:
                    raise AssertionError("Wizard exited unexpectedly; terminal output withheld") from None
                self.buffer += data
        self.buffer = self.buffer.split(target, 1)[1]

    def send(self, keys):
        os.write(self.fd, keys)

    def finish(self, expected):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.fd], [], [], 0.1)
            if ready:
                try: self.buffer += os.read(self.fd, 65536)
                except OSError: pass
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = status
                break
        assert self.status is not None, "Wizard did not exit"
        assert os.waitstatus_to_exitcode(self.status) == expected, "Wizard exit status was unexpected; output withheld"
        restored = termios.tcgetattr(self.fd)
        assert restored[3] & (termios.ECHO | termios.ICANON | termios.ISIG) == self.original[3] & (termios.ECHO | termios.ICANON | termios.ISIG), "Terminal modes were not restored"

    def close(self):
        if self.status is None:
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)
        os.close(self.fd)


def exercise(binary):
    with tempfile.TemporaryDirectory(prefix="envholster-ui-test-") as directory:
        root = Path(directory).resolve()
        (root / "home").mkdir()
        for name in ["alpha app", "beta app", "leave alone"]:
            app = root / "projects" / name
            app.mkdir(parents=True)
            (app / ".env").write_text("TOKEN=fixture-private-ui\n")
        terminal = Terminal(binary, root, ["--no-agents", "--recovery-dir", str(root / "recovery"), "--allow-same-disk"])
        try:
            terminal.expect("Where do you keep your projects?")
            terminal.send(b"\r")
            terminal.expect("Which projects should Envholster protect?")
            terminal.send(b"/beta\r ")
            terminal.expect("1 selected")
            terminal.send(b"/\x7f\x7f\x7f\x7f\r\x1b[A ")
            terminal.expect("2 selected")
            terminal.send(b"\r")
            terminal.expect("Protect these 2 project(s) with this plan?")
            terminal.send(b"y\n")
            terminal.expect("Ready to code")
            terminal.send(b"\r")
            terminal.finish(0)
            for name in ["alpha app", "beta app"]:
                assert (root / "projects" / name / ".env").read_text().startswith("# Managed by Env Holster."), "Selected project was not onboarded"
            assert not (root / "projects/leave alone/secrets.holster").exists(), "Unselected project changed"
        finally:
            terminal.close()
        for external in [False, True]:
            terminal = Terminal(binary, root, ["--no-agents"])
            try:
                terminal.expect("Where do you keep your projects?")
                if external: os.kill(terminal.pid, signal.SIGTERM)
                else: terminal.send(b"\x03")
                terminal.expect("Setup cancelled")
                terminal.finish(1)
            finally:
                terminal.close()
        terminal = Terminal(binary, root, ["--plain", "--no-agents"])
        try:
            terminal.expect("Choose a number")
            terminal.send(b"1\n")
            terminal.expect("Which projects should Envholster protect?")
            terminal.send(b"1,2\n")
            terminal.expect("Protect these 2 project(s) with this plan?")
            terminal.send(b"n\n")
            terminal.finish(0)
        finally:
            terminal.close()
    print("PASS: folder picker, search, multi-select, full onboarding, plaintext preservation, plain menus, Ctrl-C, SIGTERM and terminal restoration")


def exercise_folder_input(binary):
    with tempfile.TemporaryDirectory(prefix="envholster-folder-input-") as directory:
        root = Path(directory).resolve()
        (root / "home").mkdir()
        projects = root / "projects" / "Developer's Projects (QA)"
        app = projects / "app"
        app.mkdir(parents=True)
        (app / ".env").write_text("TOKEN=fixture-private-folder-input\n")
        terminal = Terminal(binary, root, ["--no-agents"])
        try:
            terminal.expect("Where do you keep your projects?")
            terminal.send(b"\x1b[B\x1b[B\r")
            terminal.expect("Paste a folder path, or drag a folder here:")
            terminal.send((str(root / "missing folder") + "\n").encode())
            terminal.expect("That folder could not be opened.")
            terminal.expect("Paste a folder path, or drag a folder here:")
            terminal.send(b"\n")
            terminal.expect("Where do you keep your projects?")
            terminal.send(b"\x1b[B\x1b[B\r")
            terminal.expect("Paste a folder path, or drag a folder here:")
            dragged = "".join("\\" + char if char in " '()" else char for char in str(projects))
            terminal.send((dragged + "\n").encode())
            terminal.expect("Where do you keep your projects? · " + str(projects))
            terminal.send(b"\r")
            terminal.expect("Which projects should Envholster protect?")
            terminal.send(b"\r")
            terminal.expect("Protect these 1 project(s) with this plan?")
            terminal.send(b"y\n")
            terminal.expect("Where should recovery copies go?")
            terminal.send(b"\x1b[B\r")
            terminal.expect("Recovery folder path:")
            terminal.send((str(app / "recovery") + "\n").encode())
            terminal.expect("Choose a recovery folder outside all selected projects")
            assert not (app / "recovery").exists(), "Rejected recovery folder was created"
            assert not (app / "secrets.holster").exists(), "Project changed before recovery was chosen"
            terminal.expect("Recovery folder path:")
            terminal.send(b"\n")
            terminal.expect("Where should recovery copies go?")
            terminal.send(b"\x1b[B\r")
            terminal.expect("Recovery folder path:")
            terminal.send((str(root / "recovery copies") + "\n").encode())
            terminal.expect("Save here now and move the recovery files offline afterward?")
            terminal.send(b"y\n")
            terminal.expect("Ready to code")
            terminal.send(b"\r")
            terminal.finish(0)
            assert (app / ".env").read_text().startswith("# Managed by Env Holster."), "Project did not finish after correcting the path"
        finally:
            terminal.close()
    print("PASS: dragged paths with punctuation and recovery-folder correction without restarting setup")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path(__file__).resolve().parents[1] / "target/debug/envholster")
    options = parser.parse_args()
    exercise(options.binary.resolve())
    exercise_folder_input(options.binary.resolve())
