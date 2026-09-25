#!/usr/bin/env python3
"""Offline catalog generation, lookup, and asset integrity checks."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import io
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PWSH = ROOT / ".local-tools/pwsh/pwsh"
LINUX_RUNNER = (ROOT / "edamame-ng.sh").read_text()
EXPECTED_POC = re.search(r"^CVE_POC_SHA='([0-9a-f]{64})'$", LINUX_RUNNER, re.M)
assert EXPECTED_POC and EXPECTED_POC.group(1) == hashlib.sha256(
    (ROOT / "catalog/pocs/CVE-2025-32463/sudo-chwoot.sh").read_bytes()).hexdigest()


def run(args, env=None, check=True):
    return subprocess.run(args, cwd=ROOT, env=env, text=True, capture_output=True,
                          timeout=20, check=check)


with tempfile.TemporaryDirectory(prefix="edamame-catalog-") as root:
    work = Path(root)
    source = work / "kev.json"
    output = work / "catalog"
    data = {
        "catalogVersion": "test", "dateReleased": "2026-09-25T00:00:00Z", "count": 3,
        "vulnerabilities": [
            dict(cveID="CVE-2025-32463", vendorProject="Sudo", product="Sudo",
                 vulnerabilityName="Sudo Privilege Escalation", shortDescription="local escalation",
                 dateAdded="2025-01-01"),
            dict(cveID="CVE-2021-36934", vendorProject="Microsoft", product="Windows",
                 vulnerabilityName="Windows Privilege Escalation", shortDescription="local escalation",
                 dateAdded="2025-01-02"),
            dict(cveID="CVE-2025-00000", vendorProject="Other", product="Server",
                 vulnerabilityName="Remote Code Execution", shortDescription="remote only",
                 dateAdded="2025-01-03"),
        ],
    }
    source.write_text(json.dumps(data))
    command = ["python3", "scripts/update_catalog.py", "--input", str(source),
               "--output", str(output)]
    run(command)
    first = (output / "local-eop.tsv").read_bytes()
    run(command)
    assert first == (output / "local-eop.tsv").read_bytes()
    assert len(first.splitlines()) == 3
    assert json.loads((output / "source.json").read_text())["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    data["vulnerabilities"][2]["cveID"] = "CVE-2021-36934"
    source.write_text(json.dumps(data))
    assert run(command, check=False).returncode != 0

    inner_bytes = io.BytesIO()
    with zipfile.ZipFile(inner_bytes, 'w', zipfile.ZIP_DEFLATED) as inner:
        for cve, state in (("CVE-2021-44228", "PUBLISHED"),
                           ("CVE-2026-99999", "REJECTED")):
            inner.writestr(f"cves/{cve[4:8]}/{cve}.json",
                           json.dumps({"cveMetadata": {"cveId": cve, "state": state}}))
    baseline = work / '2026-09-25_all_CVEs_at_midnight.zip.zip'
    with zipfile.ZipFile(baseline, 'w', zipfile.ZIP_STORED) as outer:
        outer.writestr('cves.zip', inner_bytes.getvalue())
    all_output = work / 'all-cves'
    all_command = ["python3", "scripts/build_cve_ids.py", "--input", str(baseline),
                   "--output", str(all_output), "--expected-sha256",
                   hashlib.sha256(baseline.read_bytes()).hexdigest()]
    run(all_command)
    first_ids = (all_output / 'cve-ids/2021.tsv').read_bytes()
    run(all_command)
    assert first_ids == (all_output / 'cve-ids/2021.tsv').read_bytes()
    assert 'CVE-2026-99999\trejected' in (all_output / 'cve-ids/2026.tsv').read_text()
    assert json.loads((all_output / 'cve-ids-source.json').read_text())['record_count'] == 2
    assert json.loads((all_output / 'cve-ids-source.json').read_text())['published_digest_verified']
    assert run(all_command[:-1] + ['0' * 64], check=False).returncode != 0

    fake = work / "bin"
    fake.mkdir()
    (fake / "uname").write_text("#!/bin/sh\necho Linux\n")
    (fake / "uname").chmod(0o755)
    (fake / "curl").write_text(f"#!/bin/sh\ntouch '{work / 'network-attempt'}'\nexit 99\n")
    (fake / "curl").chmod(0o755)
    for name in ("sha256sum", "shasum"):
        (fake / name).write_text(f"#!/bin/sh\ntouch '{work / 'checksum-hijack'}'\nexit 99\n")
        (fake / name).chmod(0o755)
    env = dict(os.environ, PATH=f"{fake}:{os.environ['PATH']}", LOCALAPPDATA=str(work))
    linux = run(["bash", "edamame-ng.sh", "--cve", "CVE-2025-32463"], env).stdout
    assert "indexed-review-only\tlinux" in linux
    assert "indexed-review-only\tlinux\tglibc" in run(
        ["bash", "edamame-ng.sh", "--cve", "CVE-2023-4911"], env).stdout
    curated_ids = (
        "CVE-2023-2640", "CVE-2023-32629", "CVE-2024-0132", "CVE-2024-21626",
        "CVE-2025-31133", "CVE-2025-52565", "CVE-2025-52881",
    )
    assert len({line.split("\t")[0] for line in (ROOT / "catalog/curated-eop.tsv").read_text().splitlines()[1:]}) == 9
    for identifier in curated_ids:
        assert f"{identifier}\tindexed-review-only\tlinux\t" in run(
            ["bash", "edamame-ng.sh", "--cve", identifier], env).stdout
    assert "unindexed" in run(["bash", "edamame-ng.sh", "--cve", "CVE-2099-99999"], env).stdout
    assert "published-general" in run(["bash", "edamame-ng.sh", "--cve", "CVE-2021-44228"], env).stdout
    bundled = run(["bash", "edamame-ng.sh", "--poc", "CVE-2025-32463"], env).stdout
    assert "verified-bundle" in bundled and "exact-build-only" in bundled
    assert "reference-only" in run(["bash", "edamame-ng.sh", "--poc", "CVE-2021-4034"], env).stdout
    assert "unreviewed-crash-risk" in run(["bash", "edamame-ng.sh", "--poc", "CVE-2024-1086"], env).stdout
    assert "reference-only" in run(["bash", "edamame-ng.sh", "--poc", "CVE-2023-21768"], env).stdout
    assert "not-indexed" in run(["bash", "edamame-ng.sh", "--poc", "CVE-2099-99999"], env).stdout
    assert run(["bash", "edamame-ng.sh", "--cve", "bad-id"], env, False).returncode == 2

    if PWSH.is_file():
        windows = run([str(PWSH), "-NoProfile", "-File", "Edamame-NG.ps1",
                       "-Cve", "CVE-2021-36934"], env).stdout
        assert "indexed-review-only\twindows" in windows
        assert "indexed-review-only\tlinux\tglibc" in run(
            [str(PWSH), "-NoProfile", "-File", "Edamame-NG.ps1",
             "-Cve", "CVE-2023-4911"], env).stdout
        for identifier in curated_ids:
            assert f"{identifier}\tindexed-review-only\tlinux\t" in run(
                [str(PWSH), "-NoProfile", "-File", "Edamame-NG.ps1",
                 "-Cve", identifier], env).stdout
        poc = run([str(PWSH), "-NoProfile", "-File", "Edamame-NG.ps1",
                   "-Poc", "CVE-2025-32463"], env).stdout
        assert "verified-bundle" in poc
        assert "unreviewed-kernel-crash-risk" in run(
            [str(PWSH), "-NoProfile", "-File", "Edamame-NG.ps1",
             "-Poc", "CVE-2023-21768"], env).stdout
        assert "not-indexed" in run([str(PWSH), "-NoProfile", "-File", "Edamame-NG.ps1",
                                     "-Poc", "CVE-2099-99999"], env).stdout
    assert not (work / "network-attempt").exists()
    assert not (work / "checksum-hijack").exists()

    copied = work / "tampered"
    shutil.copytree(ROOT / "catalog", copied)
    with (copied / "curated-eop.tsv").open("a") as supplement:
        supplement.write("CVE-2025-32463\twindows\tincorrect-duplicate\t\thttps://example.invalid/\n")
    assert "indexed-review-only\tlinux\tSudo" in run(
        ["bash", "edamame-ng.sh", "--cve", "CVE-2025-32463",
         "--catalog-dir", str(copied)], env).stdout
    if PWSH.is_file():
        assert "indexed-review-only\tlinux\tSudo" in run(
            [str(PWSH), "-NoProfile", "-File", "Edamame-NG.ps1",
             "-Cve", "CVE-2025-32463", "-CatalogDir", str(copied)], env).stdout
    (copied / "curated-eop.tsv").unlink()
    assert "published-general" in run(["bash", "edamame-ng.sh", "--cve", "CVE-2023-4911",
                               "--catalog-dir", str(copied)], env).stdout
    (copied / "pocs/CVE-2025-32463/sudo-chwoot.sh").write_text("tampered\n")
    assert run(["bash", "edamame-ng.sh", "--poc", "CVE-2025-32463",
                "--catalog-dir", str(copied)], env, False).returncode == 2
    if PWSH.is_file():
        assert run([str(PWSH), "-NoProfile", "-File", "Edamame-NG.ps1",
                    "-Poc", "CVE-2025-32463", "-CatalogDir", str(copied)], env, False).returncode != 0

print("Offline CVE catalog, deterministic build, cross-platform lookup, and PoC digest checks passed")
