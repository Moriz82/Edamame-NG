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

if (ROOT / ".git").exists():
    for asset in ("catalog/local-eop-details.tsv", "catalog/cve-ids/2025.tsv",
                  "catalog/pocs/CVE-2025-32463/sudo-chwoot.sh"):
        stored = subprocess.check_output(["git", "show", f"HEAD:{asset}"], cwd=ROOT)
        windows_checkout = subprocess.check_output(
            ["git", "-c", "core.autocrlf=true", "cat-file", "--filters", f"HEAD:{asset}"],
            cwd=ROOT)
        assert windows_checkout == stored, f"Windows checkout changes pinned catalog bytes: {asset}"


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
                           ("CVE-2026-99999", "REJECTED"),
                           ("CVE-2025-32463", "PUBLISHED")):
            record = {"cveMetadata": {"cveId": cve, "state": state}}
            if cve == "CVE-2025-32463":
                record["containers"] = {"cna": {
                    "descriptions": [{"lang": "en", "value": "  Local\nreview  lead.  "}],
                    "affected": [{"vendor": "Sudo project", "product": "Sudo",
                                  "versions": [{"version": "1.9.14", "lessThan": "1.9.17p1",
                                                "status": "affected"}]}],
                    "references": [{"url": "https://www.sudo.ws/security/advisories/"}],
                }}
            inner.writestr(f"cves/{cve[4:8]}/{cve}.json",
                           json.dumps(record))
    baseline = work / '2026-09-25_all_CVEs_at_midnight.zip.zip'
    with zipfile.ZipFile(baseline, 'w', zipfile.ZIP_STORED) as outer:
        outer.writestr('cves.zip', inner_bytes.getvalue())
    all_output = work / 'all-cves'
    all_output.mkdir()
    (all_output / 'local-eop.tsv').write_text(
        'cve\tplatform\tproduct\tkev_date\treference\n'
        'CVE-2025-32463\tlinux\tSudo\t\thttps://www.cve.org/CVERecord?id=CVE-2025-32463\n')
    (all_output / 'curated-eop.tsv').write_text('cve\tplatform\tproduct\tkev_date\treference\n')
    all_command = ["python3", "scripts/build_cve_ids.py", "--input", str(baseline),
                   "--output", str(all_output), "--expected-sha256",
                   hashlib.sha256(baseline.read_bytes()).hexdigest(), '--with-local-details']
    run(all_command)
    first_ids = (all_output / 'cve-ids/2021.tsv').read_bytes()
    first_details = (all_output / 'local-eop-details.tsv').read_bytes()
    run(all_command)
    assert first_ids == (all_output / 'cve-ids/2021.tsv').read_bytes()
    assert first_details == (all_output / 'local-eop-details.tsv').read_bytes()
    assert 'CVE-2026-99999\trejected' in (all_output / 'cve-ids/2026.tsv').read_text()
    assert json.loads((all_output / 'cve-ids-source.json').read_text())['record_count'] == 3
    assert json.loads((all_output / 'cve-ids-source.json').read_text())['published_digest_verified']
    assert json.loads((all_output / 'cve-ids-source.json').read_text())['state_counts'] == {
        'published': 2, 'rejected': 1, 'reserved': 0}
    assert b'Local review lead.' in first_details and b'"lessThan":"1.9.17p1"' in first_details
    assert json.loads((all_output / 'local-eop-details-source.json').read_text())['selected_count'] == 1
    assert run(all_command[:all_command.index('--expected-sha256')] + [
        '--expected-sha256', '0' * 64, '--with-local-details'], check=False).returncode != 0
    (all_output / 'curated-eop.tsv').write_text(
        'cve\tplatform\tproduct\tkev_date\treference\nCVE-2099-99999\tlinux\tMissing\t\thttps://example.invalid\n')
    assert run(all_command, check=False).returncode != 0
    (all_output / 'curated-eop.tsv').write_text('cve\tplatform\tproduct\tkev_date\treference\n')

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
    details = run(["bash", "edamame-ng.sh", "--cve-details", "CVE-2025-32463"], env).stdout
    assert 'source-metadata-unreviewed' in details and '"lessThan":"1.9.17p1"' in details
    assert 'details-not-installed' in run(["bash", "edamame-ng.sh", "--cve-details", "CVE-2021-44228"], env).stdout
    assert run(["bash", "edamame-ng.sh", "--cve", "CVE-2025-32463",
                "--cve-details", "CVE-2021-44228"], env, False).returncode == 2
    assert run(["bash", "edamame-ng.sh", "--cve-details", "CVE-2025-32463",
                "--poc", "CVE-2021-4034"], env, False).returncode == 2
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
        windows_details = run([str(PWSH), "-NoProfile", "-File", "Edamame-NG.ps1",
                               "-CveDetails", "CVE-2025-32463"], env).stdout
        assert 'source-metadata-unreviewed' in windows_details and '"lessThan":"1.9.17p1"' in windows_details
        assert 'details-not-installed' in run([str(PWSH), "-NoProfile", "-File", "Edamame-NG.ps1",
                                               "-CveDetails", "CVE-2021-44228"], env).stdout
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
    detail_file = copied / 'local-eop-details.tsv'
    detail_file.write_bytes(detail_file.read_bytes() + b'\n')
    assert run(["bash", "edamame-ng.sh", "--cve-details", "CVE-2025-32463",
                "--catalog-dir", str(copied)], env, False).returncode == 2
    if PWSH.is_file():
        assert run([str(PWSH), "-NoProfile", "-File", "Edamame-NG.ps1",
                    "-CveDetails", "CVE-2025-32463", "-CatalogDir", str(copied)], env, False).returncode != 0
    member_catalog = work / 'removed-candidate'
    shutil.copytree(ROOT / 'catalog', member_catalog)
    base_rows = (member_catalog / 'local-eop.tsv').read_text().splitlines()
    (member_catalog / 'local-eop.tsv').write_text(
        '\n'.join(row for row in base_rows if not row.startswith('CVE-2025-32463\t')) + '\n')
    assert 'details-not-installed' in run(
        ["bash", "edamame-ng.sh", "--cve-details", "CVE-2025-32463",
         "--catalog-dir", str(member_catalog)], env).stdout
    if PWSH.is_file():
        assert 'details-not-installed' in run(
            [str(PWSH), "-NoProfile", "-File", "Edamame-NG.ps1",
             "-CveDetails", "CVE-2025-32463", "-CatalogDir", str(member_catalog)], env).stdout
    curated_only = work / 'curated-only'
    shutil.copytree(ROOT / 'catalog', curated_only)
    (curated_only / 'local-eop.tsv').unlink()
    assert 'indexed-review-only\tlinux\tglibc' in run(
        ["bash", "edamame-ng.sh", "--cve", "CVE-2023-4911",
         "--catalog-dir", str(curated_only)], env).stdout
    assert 'source-metadata-unreviewed' in run(
        ["bash", "edamame-ng.sh", "--cve-details", "CVE-2023-4911",
         "--catalog-dir", str(curated_only)], env).stdout
    if PWSH.is_file():
        assert 'source-metadata-unreviewed' in run(
            [str(PWSH), "-NoProfile", "-File", "Edamame-NG.ps1",
             "-CveDetails", "CVE-2023-4911", "-CatalogDir", str(curated_only)], env).stdout
        assert 'indexed-review-only\tlinux\tglibc' in run(
            [str(PWSH), "-NoProfile", "-File", "Edamame-NG.ps1",
             "-Cve", "CVE-2023-4911", "-CatalogDir", str(curated_only)], env).stdout
    (copied / "curated-eop.tsv").unlink()
    assert "published-general" in run(["bash", "edamame-ng.sh", "--cve", "CVE-2023-4911",
                               "--catalog-dir", str(copied)], env).stdout
    (copied / "pocs/CVE-2025-32463/sudo-chwoot.sh").write_text("tampered\n")
    assert run(["bash", "edamame-ng.sh", "--poc", "CVE-2025-32463",
                "--catalog-dir", str(copied)], env, False).returncode == 2
    if PWSH.is_file():
        assert run([str(PWSH), "-NoProfile", "-File", "Edamame-NG.ps1",
                    "-Poc", "CVE-2025-32463", "-CatalogDir", str(copied)], env, False).returncode != 0

    # Complete optional sidecar: deterministic source projection and immutable
    # publication, including every state and the longest supported ID suffix.
    import importlib.util
    import gzip
    spec = importlib.util.spec_from_file_location('cve_builder', ROOT / 'scripts/build_cve_ids.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    fixture = ROOT / 'tests/fixtures/cve-details'
    records = json.loads((fixture / 'records.json').read_text())

    def make_baseline(path, source_records):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, 'w', zipfile.ZIP_DEFLATED) as archive:
            for record in source_records:
                cve = record['cveMetadata']['cveId']
                info = zipfile.ZipInfo(f'cves/{cve[4:8]}/{cve}.json', (2020, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(',', ':')))
        with zipfile.ZipFile(path, 'w') as archive:
            archive.writestr(zipfile.ZipInfo('cves.zip', (2020, 1, 1, 0, 0, 0)), inner.getvalue())

    detail_baseline = work / 'synthetic-baseline.zip.zip'
    make_baseline(detail_baseline, records)
    complete = work / 'complete'
    builder.build(detail_baseline, complete, builder.sha256(detail_baseline), with_all_details=True)
    assert builder.verify_all_details(complete) == len(records)
    expected_files = {str(p.relative_to(fixture / 'catalog')): p.read_bytes()
                      for p in (fixture / 'catalog').rglob('*') if p.is_file()}
    generated = lambda: {str(p.relative_to(complete)): p.read_bytes() for p in complete.rglob('*') if p.is_file()}
    assert generated() == expected_files
    builder.build(detail_baseline, complete, builder.sha256(detail_baseline), with_all_details=True)
    assert generated() == expected_files
    assert not list(complete.glob('.cve-build-*'))

    def must_reject(operation):
        try:
            operation()
        except (ValueError, FileNotFoundError, OSError):
            return
        raise AssertionError('Invalid complete catalog accepted')

    # A Git source checkout contains tracked manifests but no ignored payload
    # or install marker. Its existing generation directory is not a full pack.
    manifest_only = work / 'manifest-only'
    shutil.copytree(fixture / 'catalog', manifest_only)
    (manifest_only / 'all-cve-details/installed').unlink()
    for path in (manifest_only / 'all-cve-details').rglob('*.tsv.gz'):
        path.unlink()
    builder.build(detail_baseline, manifest_only, builder.sha256(detail_baseline), with_all_details=True)
    assert builder.verify_all_details(manifest_only) == len(records)
    assert {str(p.relative_to(manifest_only)): p.read_bytes() for p in manifest_only.rglob('*') if p.is_file()} == expected_files

    # Refuse changed active provenance before any publication. Merely renaming
    # the same verified ZIP changes baseline_asset and the source-manifest hash.
    from unittest.mock import patch
    renamed_baseline = work / 'renamed-synthetic-baseline.zip.zip'
    shutil.copyfile(detail_baseline, renamed_baseline)
    real_replace = builder.os.replace
    publication_calls = []

    def fail_marker_replace(source, target):
        publication_calls.append(str(target))
        if Path(target).name == 'installed':
            raise OSError('synthetic install-marker replacement failure')
        return real_replace(source, target)

    active_before = generated()
    with patch.object(builder.os, 'replace', fail_marker_replace):
        must_reject(lambda: builder.build(renamed_baseline, complete, builder.sha256(renamed_baseline), with_all_details=True))
    assert publication_calls == []
    assert generated() == active_before
    assert builder.verify_all_details(complete) == len(records)

    # An actual marker replacement failure on an identical in-place rebuild
    # preserves every byte of the previously verified active catalog.
    with patch.object(builder.os, 'replace', fail_marker_replace):
        must_reject(lambda: builder.build(detail_baseline, complete, builder.sha256(detail_baseline), with_all_details=True))
    assert any(Path(path).name == 'installed' for path in publication_calls)
    assert generated() == active_before
    assert builder.verify_all_details(complete) == len(records)

    # Failure on the first activation leaves no marker. A retry accepts the
    # complete staged generation left on disk and activates it successfully.
    failed_install = work / 'failed-first-install'
    with patch.object(builder.os, 'replace', fail_marker_replace):
        must_reject(lambda: builder.build(detail_baseline, failed_install, builder.sha256(detail_baseline), with_all_details=True))
    assert not (failed_install / 'all-cve-details/installed').exists()
    assert not list(failed_install.glob('.cve-build-*'))
    builder.build(detail_baseline, failed_install, builder.sha256(detail_baseline), with_all_details=True)
    assert builder.verify_all_details(failed_install) == len(records)
    print('Manifest-only installation, changed active provenance refusal, and install-marker failure recovery passed')

    before = generated()
    must_reject(lambda: builder.build(detail_baseline, complete, with_all_details=True))
    must_reject(lambda: builder.build(detail_baseline, complete, '0' * 64, with_all_details=True))
    other = work / 'other-baseline.zip.zip'
    make_baseline(other, records[:2])
    must_reject(lambda: builder.build(other, complete, builder.sha256(other), with_all_details=True))
    assert generated() == before
    duplicate_source = work / 'duplicate-baseline.zip.zip'
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', UserWarning)
        make_baseline(duplicate_source, records + records[:1])
    must_reject(lambda: builder.build(duplicate_source, work / 'duplicate-output', builder.sha256(duplicate_source), with_all_details=True))
    assert not (work / 'duplicate-output/all-cve-details/installed').exists()
    # Exact ID/state equality is checked even when the provenance digest agrees.
    index_path = complete / 'cve-ids/2020.tsv'
    old_index = index_path.read_bytes()
    index_path.write_bytes(old_index.replace(b'published', b'rejected', 1))
    must_reject(lambda: builder.build(detail_baseline, complete, builder.sha256(detail_baseline), with_all_details=True))
    index_path.write_bytes(old_index)
    assert generated() == before

    def detail_query(catalog, cve, powershell=False, check=True):
        command = ([str(PWSH), '-NoProfile', '-File', 'Edamame-NG.ps1', '-CveDetails', cve, '-CatalogDir', str(catalog)]
                   if powershell else ['bash', 'edamame-ng.sh', '--cve-details', cve, '--catalog-dir', str(catalog)])
        return run(command, env, check)

    for powershell in ([False, True] if PWSH.is_file() else [False]):
        for record in records:
            cve = record['cveMetadata']['cveId']
            fields = detail_query(complete, cve, powershell).stdout.splitlines()[1].split('\t')
            assert len(fields) == 7 and fields[:2] == [cve, record['cveMetadata']['state'].lower()]
            assert json.loads(fields[6]) == record
            if cve == 'CVE-2020-0001':
                assert json.loads('"' + fields[2] + '"') == record['containers']['cna']['descriptions'][0]['value']
                assert json.loads(fields[6])['containers']['adp'][0]['affected'][0]['versions'][0]['status'] == 'unaffected'
            if fields[1] == 'reserved':
                assert fields[2:5] == ['', '[]', '[]']
            if fields[1] == 'rejected':
                assert 'Synthetic duplicate' in fields[2] and 'replacedBy' in fields[6]
        assert 'not-in-dated-baseline' in detail_query(complete, 'CVE-2020-0003', powershell).stdout
        assert 'not-in-dated-baseline' in detail_query(complete, 'CVE-2099-99999', powershell).stdout
        command = ([str(PWSH), '-NoProfile', '-File', 'Edamame-NG.ps1', '-Cve', 'CVE-2020-0001', '-CatalogDir', str(complete)]
                   if powershell else ['bash', 'edamame-ng.sh', '--cve', 'CVE-2020-0001', '--catalog-dir', str(complete)])
        assert 'published-general' in run(command, env).stdout

    source_metadata = json.loads((complete / 'all-cve-details-source.json').read_text())
    generation = source_metadata['shards_sha256']
    touched = complete / 'all-cve-details' / generation / builder.bucket('CVE-2020-0001')
    untouched = complete / 'all-cve-details' / generation / builder.bucket('CVE-2021-1000')
    untouched.unlink()
    # Ordinary ID lookup and unrelated detail lookup never open an unused shard.
    assert 'source-metadata-unreviewed' in detail_query(complete, 'CVE-2020-0001').stdout
    if PWSH.is_file():
        assert 'source-metadata-unreviewed' in detail_query(complete, 'CVE-2020-0001', True).stdout
    touched_bytes = touched.read_bytes()
    for damage in ('missing', 'corrupt', 'truncated'):
        if damage == 'missing':
            touched.unlink()
        else:
            touched.write_bytes(b'corrupt' if damage == 'corrupt' else touched_bytes[:-8])
        for powershell in ([False, True] if PWSH.is_file() else [False]):
            result = detail_query(complete, 'CVE-2020-0001', powershell, False)
            assert result.returncode != 0 and 'integrity-failed' in result.stdout
        touched.write_bytes(touched_bytes)
    marker = complete / 'all-cve-details/installed'
    marker_bytes = marker.read_bytes()
    marker.unlink()
    assert 'details-not-installed' in detail_query(complete, 'CVE-2020-0001').stdout
    if PWSH.is_file():
        assert 'details-not-installed' in detail_query(complete, 'CVE-2020-0001', True).stdout
    marker.write_bytes(marker_bytes)
    manifest = complete / 'all-cve-details' / generation / 'shards.tsv'
    old_manifest = manifest.read_bytes()
    manifest.write_bytes(old_manifest + b'changed\n')
    assert detail_query(complete, 'CVE-2020-0001', check=False).returncode != 0
    manifest.write_bytes(old_manifest)
    metadata_path = complete / 'all-cve-details-source.json'
    old_metadata = metadata_path.read_bytes()
    changed_metadata = dict(source_metadata, baseline_sha256='0' * 64)
    builder.write_json(metadata_path, changed_metadata)
    marker.write_text(builder.sha256(metadata_path) + '\n')
    for powershell in ([False, True] if PWSH.is_file() else [False]):
        assert detail_query(complete, 'CVE-2020-0001', powershell, False).returncode != 0
    metadata_path.write_bytes(old_metadata)
    marker.write_bytes(marker_bytes)

    # Exercise gzip/row validation after rebinding deliberately malformed test
    # bytes to internally consistent hashes. These are synthetic data only.
    def rebind_payload(catalog, relative, content, raw=None):
        metadata_path = catalog / 'all-cve-details-source.json'
        metadata = json.loads(metadata_path.read_text())
        old_root = catalog / 'all-cve-details' / metadata['shards_sha256']
        target = old_root / relative
        target.write_bytes(gzip.compress(content, mtime=0) if raw is None else raw)
        manifest = old_root / 'shards.tsv'
        entries = list(csv.DictReader(manifest.read_text().splitlines(), delimiter='\t'))
        for entry in entries:
            if entry['path'] == relative:
                entry.update(sha256=builder.sha256(target), bytes=str(target.stat().st_size), uncompressed_bytes=str(len(content)))
        manifest.write_text(builder.SHARD_HEADER + ''.join('\t'.join(entry[key] for key in builder.SHARD_HEADER.strip().split('\t')) + '\n' for entry in entries))
        new_digest = builder.sha256(manifest)
        old_root.rename(old_root.with_name(new_digest))
        metadata['shards_sha256'] = new_digest
        builder.write_json(metadata_path, metadata)
        (catalog / 'all-cve-details/installed').write_text(builder.sha256(metadata_path) + '\n')

    import csv
    original_content = gzip.decompress(touched_bytes)
    for label, content, raw in (
        ('gzip-truncated', original_content, touched_bytes[:30]),
        ('bad-row-count', original_content + original_content.splitlines(keepends=True)[1], None),
        ('overlong-row', builder.ALL_HEADER.encode() + b'x' * builder.MAX_ROW_BYTES + b'\n', None),
    ):
        damaged = work / label
        shutil.copytree(fixture / 'catalog', damaged)
        rebind_payload(damaged, builder.bucket('CVE-2020-0001'), content, raw)
        for powershell in ([False, True] if PWSH.is_file() else [False]):
            result = detail_query(damaged, 'CVE-2020-0001', powershell, False)
            assert result.returncode != 0 and 'integrity-failed' in result.stdout, (label, result)
    assert not (work / 'network-attempt').exists()


print("Offline CVE catalog, deterministic build, cross-platform lookup, and PoC digest checks passed")
