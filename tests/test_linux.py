#!/usr/bin/env python3
"""Synthetic Linux runner checks; no privilege change or network access."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def write(path, body):
    path.write_text(body)
    path.chmod(0o755)


def run(script, env, *args):
    return subprocess.run(
        ["bash", str(script), *args], env=env, capture_output=True, text=True,
        timeout=30, check=True,
    ).stdout


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
    write(fake / "timeout", "#!/bin/sh\nshift\nexec \"$@\"\n")
    write(fake / "sudo", "#!/bin/sh\nif [ \"$1\" = -n ] && [ \"$2\" = /bin/bash ]; then exit 0; fi\nexit 1\n")
    write(fake / "docker", "#!/bin/sh\nexit 1\n")
    write(fake / "getcap", "#!/bin/sh\nexit 1\n")
    write(fake / "find", "#!/bin/sh\nif [ \"$1\" = \"$EDAMAME_TEST_RUNS\" ]; then exec /usr/bin/find \"$@\"; fi\nexit 0\n")
    write(fake / "curl", """#!/usr/bin/env python3
import hashlib, os, pathlib, sys
args=sys.argv[1:]
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
        ("linpeas.sh", "CVE-2026-12345\npassword=keep-private\n"),
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
                 "--output-dir", str(runs), "--tool-dir", str(tools))
    assert "[FOUND] linpeas-screening" in stdout, stdout
    assert stdout.index("[FOUND]") < stdout.index("[SAVED] linpeas-output.txt")
    run_dir = next(runs.iterdir())
    assert (run_dir / "linpeas-output.txt").read_text().find("keep-private") >= 0
    assert "keep-private" not in stdout
    assert (run_dir / "lse-output.txt").is_file()
    assert "CVE-2026-12345\thttps://www.cve.org/CVERecord?id=CVE-2026-12345" in (
        run_dir / "cve-candidates.tsv").read_text()
    assert "sudo-shell" in (run_dir / "success.tsv").read_text()
    assert len(marker.read_text().splitlines()) == 2
    resumed = run(ROOT / "edamame-ng.sh", env, "--resume", "--no-shell",
                  "--output-dir", str(runs))
    assert "[RESUME] sudo-shell" in resumed
    assert len(marker.read_text().splitlines()) == 2
    online_runs = base / "online-runs"
    run(ROOT / "edamame-ng.sh", env, "--scan", "--no-shell", "--output-dir", str(online_runs))
    online = next(online_runs.iterdir())
    assert "linpeas.sh\tv1" in (online / "tools.tsv").read_text()
    failed_env = dict(env, EDAMAME_TEST_CURL_FAIL="1")
    run(ROOT / "edamame-ng.sh", failed_env, "--scan", "--no-shell", "--output-dir", str(online_runs))
    cached = max(online_runs.iterdir(), key=lambda path: path.name)
    assert "linpeas.sh\tcache" in (cached / "tools.tsv").read_text()
    legacy_runs = base / "legacy-runs"
    legacy_env = dict(env, EDAMAME_TEST_NO_LSE_DIGEST="1")
    run(ROOT / "edamame-ng.sh", legacy_env, "--scan", "--no-shell", "--output-dir", str(legacy_runs))
    legacy = next(legacy_runs.iterdir())
    assert "lse.sh\tv1" in (legacy / "tools.tsv").read_text()
    assert "legacy-release-no-published-digest" in (legacy / "tools.tsv").read_text()
    print("Linux synthetic scan, alert order, digest, legacy LSE, cache, masking, and resume passed")
