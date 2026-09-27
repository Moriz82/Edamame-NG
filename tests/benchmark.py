#!/usr/bin/env python3
"""Measure query latency, scan cost, collector overlap, and child memory.

This reports numbers; it makes no correctness claim. The runner refuses to run
off Linux, so a fake uname stands in and the collectors are local fixtures.

Peak memory is measured in a fresh helper process per measurement, because
getrusage reports a high-water mark across every child a process has ever
reaped and would otherwise be polluted by earlier measurements.
"""
import hashlib
import json
import os
from pathlib import Path
import resource
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "edamame-ng.sh"
FIXTURE_SLEEP_S = 2


def one(argv):
    """Run a single command in this fresh process and report its cost."""
    env = json.loads(os.environ["EDAMAME_BENCH_ENV"])
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.monotonic()
    proc = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=300)
    wall = time.monotonic() - start
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    # getrusage reports KiB on Linux and bytes on macOS; normalise to KiB.
    rss = after.ru_maxrss / 1024 if sys.platform == "darwin" else after.ru_maxrss
    print(json.dumps({
        "wall_s": round(wall, 4),
        "cpu_s": round((after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime), 4),
        "peak_child_rss_kib": rss,
        "exit": proc.returncode,
    }))


def measure(argv, env):
    child_env = dict(env, EDAMAME_BENCH_ENV=json.dumps(
        {k: v for k, v in env.items() if isinstance(v, str)}))
    proc = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--one", *argv],
                          env=child_env, capture_output=True, text=True, timeout=360)
    if proc.returncode != 0:
        raise RuntimeError(f"measurement helper failed: {proc.stderr[-800:]}")
    return json.loads(proc.stdout)


def write_exec(path, body):
    path.write_text(body)
    path.chmod(0o755)


def summarize(samples):
    ordered = sorted(samples)
    return {
        "n": len(ordered),
        "min_ms": round(ordered[0] * 1000, 1),
        "median_ms": round(statistics.median(ordered) * 1000, 1),
        "p95_ms": round(ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))] * 1000, 1),
        "max_ms": round(ordered[-1] * 1000, 1),
    }


def fixture_env(base):
    """Fake PATH, two collector fixtures that timestamp start and end."""
    fake = base / "fake-bin"
    fake.mkdir()
    home = base / "home"
    home.mkdir()
    tools = base / "tools"
    tools.mkdir()
    write_exec(fake / "uname", "#!/bin/sh\necho Linux\n")
    write_exec(fake / "hostname", "#!/bin/sh\necho fixture-host\n")
    write_exec(fake / "id", "#!/bin/sh\necho 0\n")
    write_exec(fake / "getcap", "#!/bin/sh\nexit 1\n")
    write_exec(fake / "docker", "#!/bin/sh\nexit 1\n")
    write_exec(fake / "sudo", "#!/bin/sh\nexit 1\n")
    write_exec(fake / "find", "#!/bin/sh\nexit 0\n")
    write_exec(fake / "timeout", '#!/bin/sh\nif [ "$1" = --foreground ]; then shift 3; fi\nshift\nexec "$@"\n')
    for asset in ("linpeas.sh", "lse.sh"):
        body = (
            "#!/bin/sh\n"
            f"printf '%s {asset}-start\\n' \"$(date +%s)\" >> '{base / 'spans'}'\n"
            f"sleep {FIXTURE_SLEEP_S}\n"
            "printf 'CVE-2025-32463\\n'\n"
            f"printf '%s {asset}-end\\n' \"$(date +%s)\" >> '{base / 'spans'}'\n"
            "exit 0\n"
        )
        path = tools / asset
        path.write_text(body)
        path.chmod(0o755)
        (tools / (asset + ".sha256")).write_text(
            hashlib.sha256(path.read_bytes()).hexdigest() + "\n")
    env = {k: v for k, v in os.environ.items() if isinstance(v, str)}
    env.update(HOME=str(home), XDG_CACHE_HOME=str(base / "cache"),
               PATH=f"{fake}:{env['PATH']}")
    return env, tools


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--one":
        one(sys.argv[2:])
        return

    report = {"catalog": {}, "fixture": {"collector_sleep_s": FIXTURE_SLEEP_S}}
    index_rows = index_bytes = 0
    for year_file in sorted((ROOT / "catalog" / "cve-ids").glob("*.tsv")):
        data = year_file.read_bytes()
        index_rows += data.count(b"\n") - 1
        index_bytes += len(data)
    report["catalog"]["index_records"] = index_rows
    report["catalog"]["index_bytes"] = index_bytes
    report["catalog"]["complete_pack_installed"] = (
        ROOT / "catalog" / "all-cve-details" / "installed").is_file()

    with tempfile.TemporaryDirectory(prefix="edamame-bench-") as temp:
        base = Path(temp)
        env, tools = fixture_env(base)
        spans = base / "spans"

        # A baseline run costs nothing, so it isolates process start.
        report["startup"] = measure(["bash", str(SCRIPT), "--help"], env)

        classes = {
            "local_candidate": ["CVE-2025-32463", "CVE-2021-36934"],
            "general_published": ["CVE-2021-44228", "CVE-2023-4911", "CVE-2014-0160"],
            "unindexed": ["CVE-2026-99999", "CVE-1999-00001"],
        }
        report["cve_lookup"] = {}
        for name, ids in classes.items():
            samples = []
            for _ in range(5):
                for cve in ids:
                    samples.append(measure(["bash", str(SCRIPT), "--cve", cve], env)["wall_s"])
            report["cve_lookup"][name] = summarize(samples)

        report["cve_details"] = {}
        for name, cve in (("local_sidecar", "CVE-2025-32463"),
                          ("sparse_fallback", "CVE-2021-44228")):
            samples = []
            for _ in range(5):
                samples.append(measure(["bash", str(SCRIPT), "--cve-details", cve], env)["wall_s"])
            report["cve_details"][name] = summarize(samples)

        report["poc_lookup"] = summarize([
            measure(["bash", str(SCRIPT), "--poc", "CVE-2025-32463"], env)["wall_s"]
            for _ in range(5)])

        if spans.exists():
            spans.unlink()
        scan_runs = base / "scan-runs"
        scan = measure(
            ["bash", str(SCRIPT), "--scan", "--offline", "--no-shell",
             "--output-dir", str(scan_runs), "--tool-dir", str(tools)], env)
        scan["collector_fixture_sleep_s"] = FIXTURE_SLEEP_S
        report["scan"] = scan

        events = []
        if spans.exists():
            for line in spans.read_text().splitlines():
                parts = line.split()
                events.append((int(parts[0]), parts[-1]))
        events.sort()
        starts = [s for s, label in events if label.endswith("start")]
        ends = [s for s, label in events if label.endswith("end")]
        if starts and ends:
            report["scan"]["collector_start_spread_s"] = max(starts) - min(starts)
            report["scan"]["collector_span_s"] = max(ends) - min(starts)
            report["scan"]["collectors_overlapped"] = (
                sum(1 for s in starts if s < min(ends)) == len(starts))
        else:
            report["scan"]["collectors_overlapped"] = "not-observed"

    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
