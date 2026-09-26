#!/usr/bin/env python3
"""Synthetic Linux runner checks; no privilege change or network access."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def write(path, body):
    path.write_text(body)
    path.chmod(0o755)


def run(script, env, *args, check=True):
    return subprocess.run(
        ["bash", str(script), *args], env=env, capture_output=True, text=True,
        timeout=30, check=check,
    )


with tempfile.TemporaryDirectory(prefix="edamame-test-") as temp:
    base = Path(temp)
    fake = base / "fake-bin"
    fake.mkdir()
    home = base / "home"
    home.mkdir()
    tools = base / "tools"
    tools.mkdir()
    runs = base / "runs"
    marker = base / "enumerations"
    write(fake / "uname", "#!/bin/sh\necho Linux\n")
    write(fake / "hostname", "#!/bin/sh\necho fixture-host\n")
    write(fake / "id", "#!/bin/sh\necho 0\n")
    write(fake / "timeout", "#!/bin/sh\nshift\ncase \"$*\" in *linpeas.sh*) if [ -n \"${EDAMAME_TEST_TIMEOUT_FAIL:-}\" ]; then echo 'CVE-2026-99999 partial'; exit 124; fi;; esac\nexec \"$@\"\n")
    write(fake / "sudo", "#!/bin/sh\n[ -z \"${EDAMAME_TEST_NO_SUDO:-}\" ] || exit 1\nif [ \"$1\" = -n ] && [ \"$2\" = /bin/bash ]; then exit 0; fi\nexit 1\n")
    write(fake / "docker", "#!/bin/sh\nexit 1\n")
    write(fake / "getcap", "#!/bin/sh\nexit 1\n")
    write(fake / "find", "#!/bin/sh\nif [ \"$1\" = \"$EDAMAME_TEST_RUNS\" ]; then exec /usr/bin/find \"$@\"; fi\nexit 0\n")
    write(fake / "curl", """#!/usr/bin/env python3
import hashlib, os, pathlib, sys
args=sys.argv[1:]
if os.environ.get('EDAMAME_TEST_CURL_MARKER'):
    pathlib.Path(os.environ['EDAMAME_TEST_CURL_MARKER']).write_text('called')
if os.environ.get('EDAMAME_TEST_CURL_FAIL'):
    sys.exit(22)
url=next(arg for arg in args if arg.startswith('https://'))
asset='linpeas.sh' if 'peass-ng' in url else 'lse.sh'
fixture=pathlib.Path(os.environ['EDAMAME_TEST_ASSETS'])/asset
if '-w' in args:
    print(url.replace('/releases/latest','/releases/tag/v1'),end='')
elif '/expanded_assets/' in url:
    h=hashlib.sha256(fixture.read_bytes()).hexdigest()
    html='' if asset=='lse.sh' and os.environ.get('EDAMAME_TEST_NO_LSE_DIGEST') else f'<clipboard-copy id="clipboard-button-sha256:{h}" aria-label="Copy to clipboard digest for {asset}">'
    pathlib.Path(args[args.index('-o')+1]).write_text(html)
elif '/download/' in url:
    pathlib.Path(args[args.index('-o')+1]).write_bytes(fixture.read_bytes())
else:
    sys.exit(22)
""")
    for name, output in (
        ("linpeas.sh", "CVE-2026-12345\nCVE-2025-32463\nCVE-2023-4911\npassword=keep-private\n"),
        ("lse.sh", "writable test location\n"),
    ):
        asset = tools / name
        binary_prefix = "printf '\\000'\n" if name == "linpeas.sh" else ""
        write(asset, f"#!/bin/sh\n{binary_prefix}printf '%s\\n' '{output.rstrip()}'\necho run >> '{marker}'\n")
        (tools / (name + ".sha256")).write_text(hashlib.sha256(asset.read_bytes()).hexdigest() + "\n")

    env = dict(os.environ, HOME=str(home), XDG_CACHE_HOME=str(base / "cache"),
               EDAMAME_TEST_RUNS=str(runs), EDAMAME_TEST_ASSETS=str(tools),
               PATH=f"{fake}:{os.environ['PATH']}")
    stdout = run(ROOT / "edamame-ng.sh", env, "--scan", "--no-shell",
                 "--output-dir", str(runs), "--tool-dir", str(tools)).stdout
    assert "Edamame-NG  /  Linux" in stdout
    assert "[FOUND] linpeas-screening" in stdout, stdout
    assert stdout.index("[FOUND]") < stdout.index("[SAVED] linpeas-output.txt")
    run_dir = next(runs.iterdir())
    assert (run_dir / "linpeas-output.txt").read_text().find("keep-private") >= 0
    assert "keep-private" not in stdout
    verbose_runs = base / "verbose-runs"
    verbose = run(ROOT / "edamame-ng.sh", env, "--scan", "--verbose", "--no-shell",
                  "--output-dir", str(verbose_runs), "--tool-dir", str(tools))
    verbose_dir = next(verbose_runs.iterdir())
    assert "password=keep-private" in verbose.stdout
    assert "including possible credentials" in verbose.stderr
    assert verbose.stdout.index("[FOUND]") < verbose.stdout.index("[SAVED] linpeas-output.txt")
    assert "password=keep-private" in (verbose_dir / "linpeas-output.txt").read_text()
    assert "linpeas\tchecked" in (verbose_dir / "coverage.tsv").read_text()
    assert (run_dir / "lse-output.txt").is_file()
    assert "CVE-2026-12345\thttps://www.cve.org/CVERecord?id=CVE-2026-12345" in (
        run_dir / "cve-candidates.tsv").read_text()
    index = (run_dir / "cve-index.tsv").read_text()
    assert "CVE-2026-12345\tunindexed" in index
    assert "CVE-2025-32463\tindexed-review-only\tlinux" in index
    assert "CVE-2023-4911\tindexed-review-only\tlinux\tglibc" in index
    details = (run_dir / "cve-details.tsv").read_text()
    assert "CVE-2025-32463\tpublished\t" in details
    assert '"lessThan":"1.9.17p1"' in details
    assert "CVE-2026-12345\tunindexed\t\t\t\tnot-in-local-details" in details
    assert "sudo-shell" in (run_dir / "success.tsv").read_text()
    assert "CVE-2025-32463 tested lab build\tunsupported\texplicit lab opt-in not supplied" in (
        run_dir / "coverage.tsv").read_text()
    coverage = (run_dir / "coverage.tsv").read_text()
    assert "Docker Escape\tunsupported\tno independent Docker escape proof" in coverage
    assert "Kernel & exploit checks\tunsupported\tCVE text is a review lead" in coverage
    assert "Environment abuse\tunsupported\tno independent privilege proof" in coverage
    assert "Path abuse\tunsupported\tno independent privilege proof" in coverage
    assert "cve-2025-32463-lab" not in (run_dir / "attempts.tsv").read_text()
    assert len(marker.read_text().splitlines()) == 4
    resumed = run(ROOT / "edamame-ng.sh", env, "--resume", "--no-shell",
                  "--output-dir", str(runs)).stdout
    assert "Edamame-NG  /  Linux" in resumed
    assert "[RESUME] sudo-shell" in resumed
    assert len(marker.read_text().splitlines()) == 4
    query = run(ROOT / "edamame-ng.sh", env, "--cve", "CVE-2025-32463").stdout
    assert "Edamame-NG  /  Linux" not in query
    automatic = run(ROOT / "edamame-ng.sh", env, "--no-shell", "--output-dir", str(runs)).stdout
    assert "[RESUME] sudo-shell" in automatic
    assert len(marker.read_text().splitlines()) == 4
    saved = run_dir / "success.tsv"
    original = saved.read_text()
    saved.write_text(original.replace("fixture-host", "other-host"))
    foreign = run(ROOT / "edamame-ng.sh", env, "--resume", run_dir.name,
                  "--output-dir", str(runs), "--no-shell", check=False)
    assert foreign.returncode == 2 and "another host" in foreign.stderr
    saved.write_text(original.replace("sudo-shell", "unreviewed-recipe"))
    unknown = run(ROOT / "edamame-ng.sh", env, "--resume", run_dir.name,
                  "--output-dir", str(runs), "--no-shell", check=False)
    assert unknown.returncode == 2 and "Unknown saved recipe" in unknown.stderr
    saved.write_text(original.replace("sudo-shell", "cve-2025-32463-lab"))
    not_opted_in = run(ROOT / "edamame-ng.sh", env, "--resume", run_dir.name,
                       "--output-dir", str(runs), "--no-shell", check=False)
    assert not_opted_in.returncode == 2 and "requires --enable-cve-2025-32463-lab" in not_opted_in.stderr
    not_fixture = run(ROOT / "edamame-ng.sh", env, "--resume", run_dir.name,
                      "--output-dir", str(runs), "--no-shell",
                      "--enable-cve-2025-32463-lab", check=False)
    assert not_fixture.returncode == 1 and "no longer works" in not_fixture.stderr
    saved.write_text(original)
    invalid = run(ROOT / "edamame-ng.sh", env, "--resume", "..",
                  "--output-dir", str(runs), "--no-shell", check=False)
    assert invalid.returncode == 2 and "Invalid run ID" in invalid.stderr
    denied_env = dict(env, EDAMAME_TEST_NO_SUDO="1")
    denied = run(ROOT / "edamame-ng.sh", denied_env, "--resume", run_dir.name,
                 "--output-dir", str(runs), "--no-shell", check=False)
    assert denied.returncode == 1 and "no longer works" in denied.stderr
    assert len(marker.read_text().splitlines()) == 4
    duplicate_catalog = base / "duplicate-catalog"
    shutil.copytree(ROOT / "catalog", duplicate_catalog)
    with (duplicate_catalog / "curated-eop.tsv").open("a") as supplement:
        supplement.write("CVE-2025-32463\twindows\tincorrect-duplicate\t\thttps://example.invalid/\n")
    duplicate_runs = base / "duplicate-runs"
    run(ROOT / "edamame-ng.sh", env, "--scan", "--no-shell",
        "--output-dir", str(duplicate_runs), "--tool-dir", str(tools),
        "--catalog-dir", str(duplicate_catalog))
    duplicate_index = (next(duplicate_runs.iterdir()) / "cve-index.tsv").read_text()
    assert "CVE-2025-32463\tindexed-review-only\tlinux\tSudo" in duplicate_index
    lab_runs = base / "lab-runs"
    run(ROOT / "edamame-ng.sh", denied_env, "--scan", "--no-shell",
        "--enable-cve-2025-32463-lab", "--output-dir", str(lab_runs),
        "--tool-dir", str(tools))
    lab_dir = next(lab_runs.iterdir())
    assert "cve-2025-32463-lab\tprerequisite-not-met" in (
        lab_dir / "attempts.tsv").read_text()
    online_runs = base / "online-runs"
    run(ROOT / "edamame-ng.sh", env, "--scan", "--no-shell", "--output-dir", str(online_runs))
    online = next(online_runs.iterdir())
    assert "linpeas.sh\tv1" in (online / "tools.tsv").read_text()
    failed_env = dict(env, EDAMAME_TEST_CURL_FAIL="1")
    run(ROOT / "edamame-ng.sh", failed_env, "--scan", "--no-shell", "--output-dir", str(online_runs))
    cached = max(online_runs.iterdir(), key=lambda path: path.name)
    assert "linpeas.sh\tcache" in (cached / "tools.tsv").read_text()
    network_marker = base / "network-called"
    offline_env = dict(env, EDAMAME_TEST_CURL_MARKER=str(network_marker))
    offline_runs = base / "offline-runs"
    run(ROOT / "edamame-ng.sh", offline_env, "--scan", "--offline", "--no-shell",
        "--output-dir", str(offline_runs))
    offline = next(offline_runs.iterdir())
    assert "linpeas.sh\tcache" in (offline / "tools.tsv").read_text()
    assert not network_marker.exists(), "offline scan made a network request"
    legacy_runs = base / "legacy-runs"
    legacy_env = dict(env, EDAMAME_TEST_NO_LSE_DIGEST="1")
    run(ROOT / "edamame-ng.sh", legacy_env, "--scan", "--no-shell", "--output-dir", str(legacy_runs))
    legacy = next(legacy_runs.iterdir())
    assert "lse.sh\tv1" in (legacy / "tools.tsv").read_text()
    assert "legacy-release-no-published-digest" in (legacy / "tools.tsv").read_text()
    partial_runs = base / "partial-runs"
    partial_env = dict(env, EDAMAME_TEST_TIMEOUT_FAIL="1", EDAMAME_TEST_NO_SUDO="1")
    partial = run(ROOT / "edamame-ng.sh", partial_env, "--scan", "--no-shell",
                  "--output-dir", str(partial_runs), "--tool-dir", str(tools))
    partial_dir = next(partial_runs.iterdir())
    assert "linpeas\tpartial" in (partial_dir / "coverage.tsv").read_text()
    assert "Situational Awareness and Initial Enumeration\tunsupported" in (
        partial_dir / "coverage.tsv").read_text()
    assert "CVE-2026-99999" in (partial_dir / "linpeas-output.txt").read_text()
    assert partial.stdout.index("[FOUND]") < partial.stdout.index("[SAVED] linpeas-output.txt")
    assert not (partial_dir / "success.tsv").exists()
    verbose_partial_runs = base / "verbose-partial-runs"
    verbose_partial = run(ROOT / "edamame-ng.sh", partial_env, "--scan", "-v", "--no-shell",
                          "--output-dir", str(verbose_partial_runs), "--tool-dir", str(tools))
    verbose_partial_dir = next(verbose_partial_runs.iterdir())
    assert "CVE-2026-99999 partial" in verbose_partial.stdout
    assert "linpeas\tpartial" in (verbose_partial_dir / "coverage.tsv").read_text()
    no_success = run(ROOT / "edamame-ng.sh", partial_env, "--resume", "--no-shell",
                     "--output-dir", str(partial_runs), check=False)
    assert no_success.returncode == 2
    bad_runs = base / "bad-digest-runs"
    bad_cache = base / "fresh-cache"
    (tools / "linpeas.sh.sha256").write_text("0" * 64 + "\n")
    bad_env = dict(env, XDG_CACHE_HOME=str(bad_cache))
    bad = run(ROOT / "edamame-ng.sh", bad_env, "--scan", "--no-shell",
              "--output-dir", str(bad_runs), "--tool-dir", str(tools))
    bad_dir = next(bad_runs.iterdir())
    assert "linpeas.sh\tmissing" in (bad_dir / "tools.tsv").read_text()
    assert not (bad_dir / "linpeas-output.txt").exists()
    assert "checksum failed" in bad.stderr
    link = base / "linked-runs"
    link.symlink_to(runs, target_is_directory=True)
    linked = run(ROOT / "edamame-ng.sh", env, "--scan", "--no-shell",
                 "--output-dir", str(link), "--tool-dir", str(tools), check=False)
    assert linked.returncode == 2 and "symbolic links" in linked.stderr
    slow_tools = base / "slow-tools"
    slow_tools.mkdir()
    for name in ("linpeas.sh", "lse.sh"):
        asset = slow_tools / name
        write(asset, "#!/bin/sh\necho CVE-2024-123456\nsleep 3\necho completed-after-shell\n")
        (slow_tools / (name + ".sha256")).write_text(hashlib.sha256(asset.read_bytes()).hexdigest() + "\n")
    fast_runs = base / "fast-runs"
    start = time.monotonic()
    fast = run(ROOT / "edamame-ng.sh", env, "--scan", "--offline",
               "--output-dir", str(fast_runs), "--tool-dir", str(slow_tools))
    assert time.monotonic() - start < 2.5, fast.stdout
    fast_dir = next(fast_runs.iterdir())
    assert "linpeas\tpartial" in (fast_dir / "coverage.tsv").read_text()
    assert fast.stdout.index("[FOUND]") < fast.stdout.index("[SAVED] linpeas-output.txt")
    finished_runs = base / "finished-runs"
    start = time.monotonic()
    finished = run(ROOT / "edamame-ng.sh", env, "--scan", "--offline", "--finish-bg-enum",
                   "--output-dir", str(finished_runs), "--tool-dir", str(slow_tools), check=False)
    assert finished.returncode == 0, finished.stdout + finished.stderr
    assert time.monotonic() - start >= 2.5
    finished_dir = next(finished_runs.iterdir())
    assert "linpeas\tchecked" in (finished_dir / "coverage.tsv").read_text()
    assert "completed-after-shell" in (finished_dir / "linpeas-output.txt").read_text()
    print("Linux scan, alert order, partial capture, digest failures, cache, masking, resume rejection, and path guards passed")
