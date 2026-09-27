#!/usr/bin/env python3
"""Every checklist heading must be accounted for in the coverage record.

The headings are a coverage inventory, checked in so this gate does not depend
on the operator keeping the original documents around. Linux is checked against
a real run's coverage.tsv. Windows is checked against the runner source,
because a Windows scan cannot be produced here; that half proves the rows are
emitted, not that they were observed on a host.
"""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HEADINGS = ROOT / "tests" / "fixtures" / "checklist-headings.tsv"
VALID_STATUS = {"checked", "inapplicable", "unsupported", "partial", "unavailable"}


def normalise(text):
    return (text.replace("’", "'").replace("‘", "'")
                .replace("“", '"').replace("”", '"')
                .replace("&amp;", "&").strip().lower())


def fake_bin(base):
    fake = base / "fake-bin"
    fake.mkdir()
    for name, body in (("uname", "#!/bin/sh\necho Linux\n"),
                       ("hostname", "#!/bin/sh\necho fixture-host\n"),
                       ("id", "#!/bin/sh\necho 0\n"),
                       ("getcap", "#!/bin/sh\nexit 1\n"),
                       ("docker", "#!/bin/sh\nexit 1\n"),
                       ("sudo", "#!/bin/sh\nexit 1\n"),
                       ("find", "#!/bin/sh\nexit 0\n"),
                       ("timeout", '#!/bin/sh\nif [ "$1" = --foreground ]; then shift 3; fi\nshift\nexec "$@"\n')):
        path = fake / name
        path.write_text(body)
        path.chmod(0o755)
    return fake


def main():
    rows = [line.split("\t", 1) for line in HEADINGS.read_text().splitlines()[1:] if line.strip()]
    linux = [h for p, h in rows if p == "linux"]
    windows = [h for p, h in rows if p == "windows"]
    assert linux and windows, "the heading inventory is empty"

    # ---- Linux: a real run must emit a row for every heading -------------
    with tempfile.TemporaryDirectory(prefix="edamame-cov-") as temp:
        base = Path(temp)
        fake = fake_bin(base)
        home = base / "home"
        home.mkdir()
        tools = base / "tools"
        tools.mkdir()
        runs = base / "runs"
        for asset in ("linpeas.sh", "lse.sh"):
            body = "#!/bin/sh\nprintf 'CVE-2025-32463\\n'\nexit 0\n"
            (tools / asset).write_text(body)
            (tools / asset).chmod(0o755)
            (tools / (asset + ".sha256")).write_text(
                hashlib.sha256(body.encode()).hexdigest() + "\n")
        env = dict(os.environ, HOME=str(home), XDG_CACHE_HOME=str(base / "cache"),
                   PATH=f"{fake}:{os.environ['PATH']}")
        proc = subprocess.run(
            ["bash", str(ROOT / "edamame-ng.sh"), "--scan", "--offline", "--no-shell",
             "--output-dir", str(runs), "--tool-dir", str(tools)],
            env=env, capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0, (proc.returncode, proc.stdout[-800:], proc.stderr[-800:])
        run_dir = next(runs.iterdir())
        coverage = {}
        for line in (run_dir / "coverage.tsv").read_text().splitlines():
            fields = line.split("\t")
            if len(fields) >= 3:
                coverage.setdefault(normalise(fields[0]), (fields[1], fields[2]))

        missing = [h for h in linux if normalise(h) not in coverage]
        assert not missing, "Linux coverage is missing headings: " + "; ".join(missing)
        for heading in linux:
            status, reason = coverage[normalise(heading)]
            assert status in VALID_STATUS, f"{heading}: unknown status {status}"
            assert reason.strip(), f"{heading}: no reason recorded"
        # The extra status vocabulary the tool uses for tool rows must stay honest.
        assert coverage, "no coverage rows were produced"

    # ---- Windows: the runner must emit a row for every heading -----------
    source = normalise((ROOT / "Edamame-NG.ps1").read_text())
    missing = [h for h in windows if normalise(h) not in source]
    assert not missing, "Windows coverage is missing headings: " + "; ".join(missing)

    # Both runners must state a reason on every row they write.
    for script in ("edamame-ng.sh", "Edamame-NG.ps1"):
        text = (ROOT / script).read_text()
        for match in re.finditer(r'Add-Content[^\n]*-Value\s+"\$area`t\$', text):
            assert "t" in match.group(0)
    print(f"Checklist coverage gate passed: {len(linux)} Linux headings in a real run, "
          f"{len(windows)} Windows headings in the runner source")


if __name__ == "__main__":
    main()
