#!/usr/bin/env python3
"""Synthetic operator-supplied credential validation checks.

No real authentication target is contacted. The SMB and SSH authenticators are
fake local scripts; the only socket in the fixture is a loopback listener that
accepts and immediately closes. These checks assert the gating, binding,
accounting, and secret-handling rules, not any endpoint's answer.
"""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "edamame-ng.sh"
SECRET = "s3cr3t-canary-value"
CAPTURE_CANARY = "capture-canary-must-not-be-used"
ACCOUNT = "EDALAB\\edatest"
MASKED = "E***t"


def write_exec(path, body):
    path.write_text(body)
    path.chmod(0o755)


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def start_listener(port):
    """Accept and drop connections so the TCP precheck succeeds."""
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(8)
    stop = threading.Event()

    def loop():
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
                conn.close()
            except (socket.timeout, OSError):
                continue
        server.close()

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    return stop


def run(home, fake_bin, ledger, *args, secret=None, stdin_text=None, expect=None):
    env = {
        "PATH": f"{fake_bin}:/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(home / "tmp"),
        "XDG_CACHE_HOME": str(home / "cache"),
        "LANG": "C",
    }
    for key in ("EDAMAME_FAKE_SMB_EXIT", "EDAMAME_FAKE_SMB_SLEEP", "EDAMAME_FAKE_SSH_EXIT",
                "EDAMAME_FAKE_PASSWORD_ENV", "EDAMAME_FAKE_LEDGER_PATH"):
        if key in os.environ:
            env[key] = os.environ[key]
    proc = subprocess.run(
        ["bash", str(SCRIPT), *args],
        env=env, capture_output=True, text=True, timeout=60,
        input=secret if secret is not None else stdin_text,
    )
    if expect is not None:
        assert proc.returncode == expect, (
            f"expected exit {expect}, got {proc.returncode}\n"
            f"args={args}\nstdout={proc.stdout}\nstderr={proc.stderr}"
        )
    return proc


def main():
    with tempfile.TemporaryDirectory(prefix="edamame-cred-") as temp:
        base = Path(temp)
        home = base / "home"
        (home / "tmp").mkdir(parents=True)
        (home / "cache").mkdir()
        (home / "runs").mkdir()
        fake = base / "fake-bin"
        fake.mkdir()
        timeout_binary = shutil.which("timeout")
        assert timeout_binary, "the credential test needs a bounded timeout tool"
        (fake / "timeout").symlink_to(timeout_binary)
        runs = home / "runs"
        ledger = home / "cache" / "ledger.tsv"
        record = base / "adapter-record.txt"

        write_exec(fake / "uname", "#!/bin/sh\necho Linux\n")
        write_exec(fake / "hostname", "#!/bin/sh\necho fixture-host\n")
        write_exec(fake / "id", "#!/bin/sh\necho 1000\n")
        # Fake authenticator. It records the argument vector, the descriptor
        # number, and the password length, never the password itself.
        write_exec(fake / "smbclient", f"""#!/bin/sh
{{
  printf 'ARGV:'
  for a in "$@"; do printf ' [%s]' "$a"; done
  printf '\\n'
  printf 'ENV_PASSWORD_PRESENT:%s\\n' "$([ -n "${{EDAMAME_FAKE_PASSWORD_ENV:-}}" ] && echo yes || echo no)"
  printf 'PASSWD_FD:%s\\n' "${{PASSWD_FD:-missing}}"
  printf 'STDIN_PASSWORD_LEN:%s\\n' "$(cat | tr -d '\\n' | wc -c | tr -d ' ')"
  if [ -n "${{EDAMAME_FAKE_LEDGER_PATH:-}}" ]; then
    printf 'LEDGER_AT_AUTH:%s\\n' "$(awk -F '\\t' 'NR==2{{print $5}}' "$EDAMAME_FAKE_LEDGER_PATH")"
  fi
}} >> "{record}"
if [ -n "${{EDAMAME_FAKE_SMB_SLEEP:-}}" ]; then sleep "$EDAMAME_FAKE_SMB_SLEEP"; fi
exit "${{EDAMAME_FAKE_SMB_EXIT:-0}}"
""")
        write_exec(fake / "sshpass", f"""#!/bin/sh
{{
  printf 'SSHPASS_ARGV:'
  for a in "$@"; do printf ' [%s]' "$a"; done
  printf '\\n'
  printf 'SSHPASS_STDIN_LEN:%s\\n' "$(cat | tr -d '\\n' | wc -c | tr -d ' ')"
}} >> "{record}"
exit "${{EDAMAME_FAKE_SSH_EXIT:-0}}"
""")
        write_exec(fake / "ssh", f"""#!/bin/sh
printf 'SSH_ARGV:' >> "{record}"
for a in "$@"; do printf ' [%s]' "$a" >> "{record}"; done
printf '\\n' >> "{record}"
exit 0
""")

        def cred(*extra, **kwargs):
            args = [
                "--verify-credential", "--output-dir", str(runs),
                "--cred-ledger", str(ledger),
            ]
            for item in extra:
                args.append(item)
            return run(home, fake, ledger, *args, **kwargs)

        def invocations():
            if not record.exists():
                return 0
            return record.read_text().count("ARGV:")

        # --- argument validation -------------------------------------------
        proc = cred("--cred-account", ACCOUNT, "--cred-endpoint", "127.0.0.1:445",
                    expect=2, secret=SECRET)
        assert "needs --cred-account, --cred-endpoint, and --cred-service" in proc.stderr
        cred("--cred-endpoint", "127.0.0.1:445", "--cred-service", "smb",
             secret=SECRET, expect=2)

        cred("--cred-account", "bad account", "--cred-endpoint", "127.0.0.1:445",
             "--cred-service", "smb", secret=SECRET, expect=2)
        cred("--cred-account", ACCOUNT, "--cred-endpoint", "host;rm -rf /",
             "--cred-service", "smb", secret=SECRET, expect=2)
        cred("--cred-account", ACCOUNT, "--cred-endpoint", "127.0.0.1:0",
             "--cred-service", "smb", secret=SECRET, expect=2)
        cred("--cred-account", ACCOUNT, "--cred-endpoint", "127.0.0.1:445",
             "--cred-service", "telnet", secret=SECRET, expect=2)
        cred("--cred-account", "EDALAB\\edatest", "--cred-endpoint", "127.0.0.1:22",
             "--cred-service", "ssh", secret=SECRET, expect=2)
        cred("--cred-account", ACCOUNT, "--cred-endpoint", "127.0.0.1:445",
             "--cred-service", "smb", "--cred-timeout", "9999", secret=SECRET, expect=2)
        assert invocations() == 0, "argument refusals must not reach an authenticator"

        # --- no authenticator installed -------------------------------------
        bare = base / "bare-bin"
        bare.mkdir()
        for tool in ("uname", "hostname", "id"):
            write_exec(bare / tool, (fake / tool).read_text())
        run(home, bare, ledger, "--verify-credential", "--output-dir", str(runs),
            "--cred-ledger", str(ledger), "--cred-account", ACCOUNT,
            "--cred-endpoint", "127.0.0.1:445", "--cred-service", "smb",
            secret=SECRET, expect=2)
        assert not record.exists(), "no authenticator may run without a secret"

        # --- unreachable endpoint consumes no authentication attempt ---------
        dead = free_port()
        proc = cred("--cred-account", ACCOUNT, "--cred-endpoint", f"127.0.0.1:{dead}",
                    "--cred-service", "smb", "--cred-secret-stdin",
                    secret=SECRET, expect=3)
        assert "No authentication was attempted" in proc.stderr
        assert invocations() == 0
        assert "endpoint-unreachable" in _latest_attempt(runs)

        # --- first attempt is allowed and is recorded -----------------------
        port = free_port()
        stop = start_listener(port)
        env_export = os.environ.get("EDAMAME_TEST_SMB_EXIT")
        del env_export
        os.environ["EDAMAME_FAKE_SMB_EXIT"] = "0"
        os.environ["EDAMAME_FAKE_LEDGER_PATH"] = str(ledger)
        proc = cred("--cred-account", ACCOUNT, "--cred-endpoint", f"127.0.0.1:{port}",
                    "--cred-service", "smb", "--cred-secret-stdin",
                    secret=SECRET + "\n", expect=0)
        assert f"Accepted: {MASKED}" in proc.stdout, proc.stdout
        assert invocations() == 1
        assert "LEDGER_AT_AUTH:1" in record.read_text(), "the attempt must be reserved before authentication"
        assert "[-m]" not in record.read_text(), "do not pass an unsupported Samba protocol name"
        assert "[-N]" not in record.read_text(), "do not suppress the supplied descriptor password"
        row = _latest_attempt(runs)
        assert row.split("\t")[3] == MASKED, row
        assert row.split("\t")[4] == "unverified-single-attempt", row
        assert SECRET not in row

        # --- the second attempt for the same account and endpoint is refused
        record.unlink(missing_ok=True)
        proc = cred("--cred-account", ACCOUNT, "--cred-endpoint", f"127.0.0.1:{port}",
                    "--cred-service", "smb", "--cred-secret-stdin",
                    secret=SECRET, expect=2)
        assert "Refused" in proc.stderr and "1 of 1 permitted attempts" in proc.stderr
        assert invocations() == 0, "a refused attempt must not reach the authenticator"
        assert "limit-reached" in _latest_attempt(runs)

        # Two simultaneous invocations of a fresh key must share one budget.
        race_ledger = home / "cache" / "race-ledger.tsv"
        record.unlink(missing_ok=True)
        race_env = {
            "PATH": f"{fake}:/usr/bin:/bin", "HOME": str(home),
            "TMPDIR": str(home / "tmp"), "XDG_CACHE_HOME": str(home / "cache"),
            "LANG": "C", "EDAMAME_FAKE_SMB_EXIT": "0",
            "EDAMAME_FAKE_SMB_SLEEP": "0.2",
            "EDAMAME_FAKE_LEDGER_PATH": str(race_ledger),
        }
        race_args = ["bash", str(SCRIPT), "--verify-credential", "--output-dir", str(runs),
                     "--cred-ledger", str(race_ledger), "--cred-account", ACCOUNT,
                     "--cred-endpoint", f"127.0.0.1:{port}", "--cred-service", "smb",
                     "--cred-secret-stdin"]
        racers = [subprocess.Popen(race_args, env=race_env, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True) for _ in range(2)]
        outcomes = [p.communicate(SECRET + "\n", timeout=60) for p in racers]
        assert sorted(p.returncode for p in racers) == [0, 2], outcomes
        assert record.read_text().count("ARGV:") == 1, "concurrent checks reached the authenticator twice"
        assert race_ledger.read_text().splitlines()[1].split("\t")[4] == "1"
        record.unlink(missing_ok=True)

        # SMB account names are case-insensitive; changing their case cannot
        # create another budget. A damaged matching row must fail closed.
        cred("--cred-account", ACCOUNT.lower(), "--cred-endpoint", f"127.0.0.1:{port}",
             "--cred-service", "smb", "--cred-secret-stdin", secret=SECRET, expect=2)
        assert invocations() == 0
        corrupt = home / "cache" / "corrupt-ledger.tsv"
        lines = ledger.read_text().splitlines()
        fields = lines[1].split("\t")
        fields[4] = "bad-count"
        corrupt.write_text(lines[0] + "\n" + "\t".join(fields) + "\n")
        damaged = run(home, fake, corrupt, "--verify-credential", "--output-dir", str(runs),
                      "--cred-ledger", str(corrupt), "--cred-account", ACCOUNT,
                      "--cred-endpoint", f"127.0.0.1:{port}", "--cred-service", "smb",
                      "--cred-secret-stdin", secret=SECRET, expect=2)
        assert "corrupt or duplicate" in damaged.stderr
        assert invocations() == 0

        # --- binding: a different account, port, or service is a separate key
        port2 = free_port()
        stop_b = start_listener(port2)
        ledger2 = home / "cache" / "ledger2.tsv"
        run(home, fake, ledger2, "--verify-credential", "--output-dir", str(runs),
            "--cred-ledger", str(ledger2), "--cred-account", "EDALAB\\other",
            "--cred-endpoint", f"127.0.0.1:{port}", "--cred-service", "smb",
            "--cred-secret-stdin", secret=SECRET, expect=0)
        run(home, fake, ledger2, "--verify-credential", "--output-dir", str(runs),
            "--cred-ledger", str(ledger2), "--cred-account", ACCOUNT,
            "--cred-endpoint", f"127.0.0.1:{port2}", "--cred-service", "smb",
            "--cred-secret-stdin", secret=SECRET, expect=0)
        # The service is part of the key, so the SSH route is not capped by the
        # SMB attempt above. Supplying a known_hosts entry is required first.
        ssh_dir = home / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "known_hosts").write_text(f"[127.0.0.1]:{port} ssh-ed25519 AAAAC3NzaC1\n")
        (ssh_dir / "known_hosts").chmod(0o600)
        run(home, fake, ledger2, "--verify-credential", "--output-dir", str(runs),
            "--cred-ledger", str(ledger2), "--cred-account", "edatest",
            "--cred-endpoint", f"127.0.0.1:{port}", "--cred-service", "ssh",
            "--cred-secret-stdin", secret=SECRET, expect=0)
        assert len({line.split("\t")[0] for line in
                    ledger2.read_text().splitlines()[1:]}) == 3, ledger2.read_text()
        for line in ledger2.read_text().splitlines()[1:]:
            assert line.split("\t")[4] == "1", line
        stop_b.set()
        (ssh_dir / "known_hosts").unlink()
        binding_text = record.read_text()
        ssh_lines = [line for line in binding_text.splitlines() if line.startswith("SSHPASS_ARGV")]
        assert ssh_lines, binding_text
        for line in ssh_lines:
            assert "NumberOfPasswordPrompts=1" in line, line
            assert "StrictHostKeyChecking=yes" in line, line
            assert "PubkeyAuthentication=no" in line, line
            assert line.rstrip().endswith("[true]"), line
            assert "edatest@127.0.0.1" in line, line
        assert f"SSHPASS_STDIN_LEN:{len(SECRET)}" in binding_text, binding_text
        assert "[-d] [0]" in binding_text, "the SSH secret must travel on a file descriptor, not in argv"
        for line in binding_text.splitlines():
            if "_ARGV" in line or line.startswith("SSH_ARGV"):
                assert SECRET not in line, line

        # --- an operator policy is recorded but cannot raise the one-attempt cap ---
        policy = home / "policy.txt"
        policy.write_text("lockout_threshold=2\nreset=automatic\n")
        policy.chmod(0o600)
        ledger3 = home / "cache" / "ledger3.tsv"

        def policy_cred():
            return run(home, fake, ledger3, "--verify-credential", "--output-dir", str(runs),
                       "--cred-ledger", str(ledger3), "--cred-lockout-file", str(policy),
                       "--cred-account", ACCOUNT, "--cred-endpoint", f"127.0.0.1:{port}",
                       "--cred-service", "smb", "--cred-secret-stdin", secret=SECRET)

        os.environ["EDAMAME_FAKE_SMB_EXIT"] = "1"
        first = policy_cred()
        assert first.returncode == 1, f"{first.returncode}\n{first.stdout}\n{first.stderr}"
        proc = policy_cred()
        assert proc.returncode == 2, proc.stderr
        assert "1 of 1 permitted attempts" in proc.stderr
        row = _latest_attempt(runs)
        assert row.split("\t")[4] == "operator-policy-threshold-2", row
        assert len(row.split("\t")[5]) == 64, "policy digest must be recorded"

        # An existing lock fails closed, including one left by a killed run.
        locked_ledger = home / "cache" / "locked-ledger.tsv"
        (home / "cache" / "locked-ledger.tsv.lock").mkdir(mode=0o700)
        before = invocations()
        locked = run(home, fake, locked_ledger, "--verify-credential", "--output-dir", str(runs),
                     "--cred-ledger", str(locked_ledger), "--cred-account", ACCOUNT,
                     "--cred-endpoint", f"127.0.0.1:{port}", "--cred-service", "smb",
                     "--cred-secret-stdin", secret=SECRET, expect=2)
        assert "stale lock" in locked.stderr
        assert invocations() == before, "a busy ledger must block authentication"
        (home / "cache" / "locked-ledger.tsv.lock").rmdir()

        # --- an unverifiable or tampered policy is refused -------------------
        weak = home / "weak.txt"
        weak.write_text("no threshold here\n")
        weak.chmod(0o600)
        run(home, fake, ledger3, "--verify-credential", "--output-dir", str(runs),
            "--cred-ledger", str(home / "cache" / "l4.tsv"),
            "--cred-lockout-file", str(weak), "--cred-account", ACCOUNT,
            "--cred-endpoint", f"127.0.0.1:{port}", "--cred-service", "smb",
            "--cred-secret-stdin", secret=SECRET, expect=2)
        open_policy = home / "open.txt"
        open_policy.write_text("lockout_threshold=5\n")
        open_policy.chmod(0o666)
        run(home, fake, ledger3, "--verify-credential", "--output-dir", str(runs),
            "--cred-ledger", str(home / "cache" / "l5.tsv"),
            "--cred-lockout-file", str(open_policy), "--cred-account", ACCOUNT,
            "--cred-endpoint", f"127.0.0.1:{port}", "--cred-service", "smb",
            "--cred-secret-stdin", secret=SECRET, expect=2)
        run(home, fake, ledger3, "--verify-credential", "--output-dir", str(runs),
            "--cred-ledger", str(home / "cache" / "l6.tsv"),
            "--cred-lockout-file", str(home / "absent.txt"),
            "--cred-account", ACCOUNT, "--cred-endpoint", f"127.0.0.1:{port}",
            "--cred-service", "smb", "--cred-secret-stdin", secret=SECRET, expect=2)

        # --- secret handling -------------------------------------------------
        # Samba reads the operator secret from descriptor 0. No temporary
        # plaintext authentication file is created.
        text = record.read_text()
        assert "PASSWD_FD:0" in text, text
        assert f"STDIN_PASSWORD_LEN:{len(SECRET)}" in text, text
        assert "[-U] [edatest]" in text, text
        assert "[-W] [EDALAB]" in text, text
        assert "ENV_PASSWORD_PRESENT:no" in text, "the secret must not travel in the environment"
        # The secret must appear in no command vector or environment; SMB and
        # SSH receive it only on a standard-input descriptor.
        vectors = [line for line in text.splitlines() if "_ARGV" in line]
        assert vectors, text
        for line in vectors:
            assert SECRET not in line, line

        # A secret-shaped value sitting in collector output is never used.
        capture = runs / "fake-capture" / "linpeas-output.txt"
        capture.parent.mkdir(parents=True, exist_ok=True)
        capture.write_text(f"[+] password: {CAPTURE_CANARY}\n[+] user: hunter2\n")
        record.unlink(missing_ok=True)
        ledger4 = home / "cache" / "ledger4.tsv"
        os.environ["EDAMAME_FAKE_SMB_EXIT"] = "0"
        run(home, fake, ledger4, "--verify-credential", "--output-dir", str(runs),
            "--cred-ledger", str(ledger4), "--cred-account", ACCOUNT,
            "--cred-endpoint", f"127.0.0.1:{port}", "--cred-service", "smb",
            "--cred-secret-stdin", secret=SECRET, expect=0)
        text = record.read_text()
        assert CAPTURE_CANARY not in text and "hunter2" not in text, text

        # No artifact in the run tree contains the secret.
        for path in runs.rglob("*"):
            if path.is_file():
                assert SECRET.encode() not in path.read_bytes(), path

        # --- ssh refuses an unverified host key without running ssh ----------
        record.unlink(missing_ok=True)
        ssh_port = free_port()
        stop2 = start_listener(ssh_port)
        proc = run(home, fake, home / "cache" / "l7.tsv", "--verify-credential",
                   "--output-dir", str(runs), "--cred-ledger", str(home / "cache" / "l7.tsv"),
                   "--cred-account", "edatest", "--cred-endpoint", f"127.0.0.1:{ssh_port}",
                   "--cred-service", "ssh", "--cred-secret-stdin", secret=SECRET, expect=2)
        assert "Host key verification is not weakened" in proc.stderr, proc.stderr
        assert "host-key-unverified" in _latest_attempt(runs)
        assert not record.exists(), "ssh must not run without a known_hosts entry"
        stop2.set()

        # --- no secret input path and empty secret are refused ---------------
        run(home, fake, home / "cache" / "l8.tsv", "--verify-credential",
            "--output-dir", str(runs), "--cred-ledger", str(home / "cache" / "l8.tsv"),
            "--cred-account", ACCOUNT, "--cred-endpoint", f"127.0.0.1:{port}",
            "--cred-service", "smb", stdin_text="", expect=2)
        run(home, fake, home / "cache" / "l9.tsv", "--verify-credential",
            "--output-dir", str(runs), "--cred-ledger", str(home / "cache" / "l9.tsv"),
            "--cred-account", ACCOUNT, "--cred-endpoint", f"127.0.0.1:{port}",
            "--cred-service", "smb", "--cred-secret-stdin", secret="\n", expect=2)

        # --- an existing foreign ledger file is never overwritten ------------
        foreign = home / "cache" / "foreign.tsv"
        foreign.write_text("someone elses data\n")
        run(home, fake, foreign, "--verify-credential", "--output-dir", str(runs),
            "--cred-ledger", str(foreign), "--cred-account", ACCOUNT,
            "--cred-endpoint", f"127.0.0.1:{port}", "--cred-service", "smb",
            "--cred-secret-stdin", secret=SECRET, expect=2)
        assert foreign.read_text() == "someone elses data\n"

        # --- private modes ----------------------------------------------------
        assert (ledger.stat().st_mode & 0o777) == 0o600, oct(ledger.stat().st_mode)
        result_dirs = list((runs / "credentials").iterdir())
        assert result_dirs, "a private credential result directory is expected"
        for path in result_dirs:
            assert (path.stat().st_mode & 0o777) == 0o700, path

        # --- a CVE query and credential validation are mutually exclusive -----
        run(home, fake, home / "cache" / "l10.tsv", "--verify-credential",
            "--output-dir", str(runs), "--cred-ledger", str(home / "cache" / "l10.tsv"),
            "--cve", "CVE-2025-32463", "--cred-account", ACCOUNT,
            "--cred-endpoint", f"127.0.0.1:{port}", "--cred-service", "smb",
            secret=SECRET, expect=2)
        stop.set()

    print("Credential validation gating, binding, accounting, and secret handling passed")


def _latest_attempt(runs):
    dirs = sorted((runs / "credentials").iterdir(), key=lambda p: p.name)
    rows = [line for line in dirs[-1].joinpath("attempts.tsv").read_text().splitlines()[1:] if line]
    assert rows, "expected a recorded attempt"
    return rows[-1]


if __name__ == "__main__":
    main()
