#!/usr/bin/env python3
"""Synthetic Linux runner checks; no privilege change or network access."""
import hashlib
import os
from pathlib import Path
import shutil
import shlex
import signal
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


def wait_for_paths(paths, process=None):
    deadline = time.monotonic() + 10
    while not all(path.exists() for path in paths):
        if process is not None and process.poll() is not None:
            raise AssertionError("fixture exited before descendants were ready")
        assert time.monotonic() < deadline, paths
        time.sleep(0.02)


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
    write(fake / "timeout", "#!/bin/sh\nif [ \"$1\" = --foreground ]; then shift 3; fi\nshift\ncase \"$*\" in *linpeas.sh*) if [ -n \"${EDAMAME_TEST_TIMEOUT_FAIL:-}\" ]; then echo 'CVE-2026-99999 partial'; exit 124; fi;; esac\nexec \"$@\"\n")
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
    assert "CVE-2026-12345\tunindexed\t\t\t\tdetails-not-installed" in details
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
    (duplicate_catalog / "local-eop.tsv").unlink()
    curated_runs = base / "curated-runs"
    run(ROOT / "edamame-ng.sh", env, "--scan", "--no-shell",
        "--output-dir", str(curated_runs), "--tool-dir", str(tools),
        "--catalog-dir", str(duplicate_catalog))
    curated_index = (next(curated_runs.iterdir()) / "cve-index.tsv").read_text()
    assert "CVE-2023-4911\tindexed-review-only\tlinux\tglibc" in curated_index
    (duplicate_catalog / "curated-eop.tsv").unlink()
    general_runs = base / "general-runs"
    run(ROOT / "edamame-ng.sh", env, "--scan", "--no-shell",
        "--output-dir", str(general_runs), "--tool-dir", str(tools),
        "--catalog-dir", str(duplicate_catalog))
    general_index = (next(general_runs.iterdir()) / "cve-index.tsv").read_text()
    assert "CVE-2025-32463\tpublished-general" in general_index
    # Optional complete sidecar stays lazy and scans each touched gzip shard
    # once, including multiple CVE candidates sharing a thousand-ID bucket.
    import json
    detail_catalog = base / 'complete-catalog'
    shutil.copytree(ROOT / 'tests/fixtures/cve-details/catalog', detail_catalog)
    detail_source = json.loads((detail_catalog / 'all-cve-details-source.json').read_text())
    generation = detail_catalog / 'all-cve-details' / detail_source['shards_sha256']
    (generation / '2021/1.tsv.gz').unlink()  # Unused payload must not be read.
    detail_tools = base / 'detail-tools'
    shutil.copytree(tools, detail_tools)
    write(detail_tools / 'linpeas.sh', '#!/bin/sh\nprintf "CVE-2020-0001\\nCVE-2020-0002\\nCVE-2020-01000\\n"\n')
    (detail_tools / 'linpeas.sh.sha256').write_text(hashlib.sha256((detail_tools / 'linpeas.sh').read_bytes()).hexdigest() + '\n')
    gzip_marker = base / 'gzip-reads'
    system_gzip = shutil.which('gzip')
    assert system_gzip
    write(fake / 'gzip', f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{gzip_marker}"\nexec "{system_gzip}" "$@"\n')
    detail_runs = base / 'detail-runs'
    detail_scan = run(ROOT / 'edamame-ng.sh', env, '--scan', '--offline', '--no-shell',
                      '--output-dir', str(detail_runs), '--tool-dir', str(detail_tools), '--catalog-dir', str(detail_catalog))
    detail_text = (next(detail_runs.iterdir()) / 'cve-details.tsv').read_text()
    assert len(detail_text.splitlines()) == 4
    assert 'CVE-2020-0001\tpublished\t' in detail_text and 'CVE-2020-01000\trejected\t' in detail_text
    assert 'Conflicting ADP claim' in detail_text
    assert len(gzip_marker.read_text().splitlines()) == 2
    assert sum('/2020/0.tsv.gz' in line for line in gzip_marker.read_text().splitlines()) == 1
    (generation / '2020/0.tsv.gz').unlink()
    damaged_runs = base / 'damaged-details-runs'
    damaged_scan = run(ROOT / 'edamame-ng.sh', env, '--scan', '--offline', '--no-shell',
                       '--output-dir', str(damaged_runs), '--tool-dir', str(detail_tools), '--catalog-dir', str(detail_catalog))
    damaged_text = (next(damaged_runs.iterdir()) / 'cve-details.tsv').read_text()
    assert damaged_text.count('integrity-failed') == 2 and damaged_text.count('source-metadata-unreviewed') == 1
    assert 'integrity checks' in damaged_scan.stderr
    (fake / 'gzip').unlink()

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

    # Use real process groups and GNU timeout for lifecycle regressions, even
    # when the wider suite runs with a synthetic Linux uname on macOS.
    real_timeout = shutil.which("timeout", path=os.environ["PATH"])
    real_ps = shutil.which("ps", path=os.environ["PATH"])
    assert real_timeout and real_ps
    write(fake / "timeout", f'''#!/bin/sh
if [ "$1" = --foreground ]; then
    shift 4
    exec {shlex.quote(real_timeout)} --foreground -k 1 "${{EDAMAME_TEST_LIMIT:-600}}" "$@"
fi
exec {shlex.quote(real_timeout)} "$@"
''')
    original_sudo = (fake / "sudo").read_text()
    write(fake / "sudo", '''#!/bin/sh
if [ -n "${EDAMAME_TEST_READY_DIR:-}" ]; then
    for name in linpeas lse; do
        count=0
        while [ ! -f "$EDAMAME_TEST_READY_DIR/$name.ready" ]; do
            count=$((count+1))
            [ "$count" -lt 100 ] || exit 1
            sleep 0.05
        done
    done
fi
''' + original_sudo.split("\n", 1)[1])
    lifecycle_tools = base / "lifecycle-tools"
    lifecycle_tools.mkdir()
    for name in ("linpeas", "lse"):
        asset = lifecycle_tools / f"{name}.sh"
        write(asset, f'''#!/bin/bash
echo CVE-2024-123456
bash -c '
    trap "" TERM
    printf "%s\\n" "$$" > "$1.pid"
    ps -p "$$" -o pgid= > "$1.group"
    : > "$1.ready"
    sleep 3
    echo delayed-marker > "$1.late"
    echo delayed-output
' fixture "$EDAMAME_TEST_READY_DIR/{name}" &
if [ -n "${{EDAMAME_TEST_ROOT_EXITS:-}}" ]; then exit 0; fi
wait
''')
        (lifecycle_tools / f"{name}.sh.sha256").write_text(
            hashlib.sha256(asset.read_bytes()).hexdigest() + "\n")

    def descendant_alive(pid):
        state = subprocess.run([real_ps, "-p", str(pid), "-o", "stat="],
                               capture_output=True, text=True, check=False).stdout.strip()
        return bool(state) and not state.startswith("Z")

    timeout_wrapper = (fake / "timeout").read_text()
    write(fake / "timeout", "#!/bin/sh\nexit 125\n")
    unsupported_runs = base / "unsupported-capture-runs"
    unsupported = run(ROOT / "edamame-ng.sh", env, "--scan", "--offline", "--no-shell",
                      "--output-dir", str(unsupported_runs), "--tool-dir", str(lifecycle_tools))
    unsupported_dir = next(unsupported_runs.iterdir())
    assert "unsupported timeout or ps options" in unsupported.stderr
    assert "linpeas\tunavailable" in (unsupported_dir / "coverage.tsv").read_text()
    assert not (unsupported_dir / "linpeas-output.txt").exists()
    assert "[SAVED] linpeas-output.txt" not in unsupported.stdout
    write(fake / "timeout", timeout_wrapper)

    for case in ("stop", "timeout", "root-exits", "signal", "startup-signal", "cleanup-failure"):
        state_dir = base / f"lifecycle-{case}"
        state_dir.mkdir()
        lifecycle_runs = base / f"lifecycle-{case}-runs"
        lifecycle_env = dict(env, EDAMAME_TEST_READY_DIR=str(state_dir))
        args = ["bash", str(ROOT / "edamame-ng.sh"), "--scan", "--offline",
                "--output-dir", str(lifecycle_runs), "--tool-dir", str(lifecycle_tools)]
        if case in ("timeout", "root-exits", "signal"):
            args.append("--no-shell")
        if case == "timeout":
            lifecycle_env["EDAMAME_TEST_LIMIT"] = "1"
        if case == "root-exits":
            lifecycle_env["EDAMAME_TEST_ROOT_EXITS"] = "1"
        if case == "startup-signal":
            write(fake / "ps", f'''#!/bin/sh
if [ "$1" = -p ] && [ "$6" = lstart= ] &&
   [ ! -f "$EDAMAME_TEST_READY_DIR/supervisor.pid" ]; then
    printf '%s\\n' "$2" > "$EDAMAME_TEST_READY_DIR/supervisor.pid"
    : > "$EDAMAME_TEST_READY_DIR/startup-paused"
    while [ ! -f "$EDAMAME_TEST_READY_DIR/startup-release" ]; do sleep 0.02; done
fi
exec {shlex.quote(real_ps)} "$@"
''')
        if case == "cleanup-failure":
            write(fake / "ps", f'''#!/bin/sh
if [ "$1" = -e ] && [ -f "$EDAMAME_TEST_READY_DIR/linpeas.ready" ] &&
   [ -f "$EDAMAME_TEST_READY_DIR/lse.ready" ]; then exit 1; fi
exec {shlex.quote(real_ps)} "$@"
''')
        process = subprocess.Popen(args, env=lifecycle_env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        try:
            if case == "startup-signal":
                wait_for_paths([state_dir / "startup-paused"], process)
                assert not list(state_dir.glob("*.ready")), "collector started before authorization"
                process.send_signal(signal.SIGTERM)
                (state_dir / "startup-release").touch()
            else:
                wait_for_paths([state_dir / "linpeas.ready", state_dir / "lse.ready"], process)
            if case == "signal":
                process.send_signal(signal.SIGTERM)
            captured_stdout, captured_stderr = process.communicate(timeout=15)
            expected_code = 143 if case in ("signal", "startup-signal") else 1 if case == "cleanup-failure" else 0
            assert process.returncode == expected_code, (case, captured_stdout, captured_stderr)
            lifecycle_dir = next(lifecycle_runs.iterdir())
            if case == "startup-signal":
                supervisor = int((state_dir / "supervisor.pid").read_text())
                supervisor_state = subprocess.run([real_ps, "-p", str(supervisor), "-o", "stat="],
                                                  capture_output=True, text=True, check=False).stdout.strip()
                assert not supervisor_state, "unapproved supervisor was not terminated and reaped"
                assert not list(state_dir.glob("*.ready")), "collector started after cancellation"
                assert not list(state_dir.glob("*.late"))
                assert "[SAVED]" not in captured_stdout
                assert not list(lifecycle_dir.glob("*-output.txt"))
                continue
            snapshots = {}
            for name in ("linpeas", "lse"):
                pid = int((state_dir / f"{name}.pid").read_text())
                assert not descendant_alive(pid), (case, name, "descendant survived")
                output = lifecycle_dir / f"{name}-output.txt"
                if case in ("signal", "cleanup-failure"):
                    assert not output.exists(), (case, name)
                    assert f"[SAVED] {name}-output.txt" not in captured_stdout
                else:
                    snapshots[output] = output.read_bytes()
                    assert f"{name}\tpartial" in (lifecycle_dir / "coverage.tsv").read_text()
                    assert captured_stdout.index("[FOUND]") < captured_stdout.index(f"[SAVED] {name}-output.txt")
            if case == "cleanup-failure":
                assert "cleanup-failed" in (lifecycle_dir / "coverage.tsv").read_text()
                assert "cleanup could not be confirmed" in captured_stderr
            # Wait beyond the child's planned write, not merely until root exit.
            time.sleep(3.1)
            assert not list(state_dir.glob("*.late")), (case, "late descendant write")
            for output, before in snapshots.items():
                assert output.read_bytes() == before, (case, "final output changed")
        finally:
            (state_dir / "startup-release").touch()
            # Never leak a failing fixture; target only its recorded child group.
            for pid_file in state_dir.glob("*.pid"):
                pid = int(pid_file.read_text())
                if pid_file.name == "supervisor.pid" and descendant_alive(pid):
                    os.kill(pid, signal.SIGKILL)
                group_file = pid_file.with_suffix(".group")
                if group_file.exists() and descendant_alive(pid):
                    group = int(group_file.read_text())
                    if group != os.getpgrp() and os.getpgid(pid) == group:
                        os.killpg(group, signal.SIGKILL)
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
            if (fake / "ps").exists():
                (fake / "ps").unlink()
    print("Linux scan, alert order, partial capture, digest failures, cache, masking, resume rejection, and path guards passed")
    print("Collector descendants stopped before finalization: stop, timeout, root exit, signal, startup signal, and failed confirmation passed")
