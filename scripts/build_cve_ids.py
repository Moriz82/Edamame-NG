#!/usr/bin/env python3
"""Build a small offline ID/state index from an official CVE List V5 baseline ZIP.

The CVE Project distributes a ZIP containing cves.zip. This script streams the
inner archive to a temporary file and retains only CVE IDs and record states.
The original JSON remains the authority for product/build applicability.
"""

import argparse
import hashlib
import json
import re
import shutil
import tempfile
import zipfile
from pathlib import Path


ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def build(source: Path, destination: Path, expected_sha256: str = "") -> int:
    digest = hashlib.sha256()
    with source.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if expected_sha256 and digest.hexdigest() != expected_sha256.lower():
        raise ValueError("CVE baseline SHA-256 differs from the published digest")
    with zipfile.ZipFile(source) as outer:
        if outer.namelist() != ["cves.zip"]:
            raise ValueError("Unexpected CVE baseline ZIP layout")
        with tempfile.TemporaryFile() as inner_file:
            with outer.open("cves.zip") as compressed:
                shutil.copyfileobj(compressed, inner_file, 1024 * 1024)
            inner_file.seek(0)
            with zipfile.ZipFile(inner_file) as inner:
                rows = {}
                for name in inner.namelist():
                    if not ID.fullmatch(Path(name).stem):
                        continue
                    with inner.open(name) as record_file:
                        record = json.load(record_file)
                    metadata = record.get("cveMetadata", {})
                    cve = metadata.get("cveId", "")
                    state = metadata.get("state", "")
                    if cve != Path(name).stem or state not in ("PUBLISHED", "REJECTED", "RESERVED"):
                        raise ValueError(f"Invalid record metadata: {name}")
                    if cve in rows:
                        raise ValueError(f"Duplicate CVE ID: {cve}")
                    rows[cve] = state.lower()
    destination.mkdir(parents=True, exist_ok=True)
    index_dir = destination / "cve-ids"
    index_dir.mkdir(exist_ok=True)
    for old in index_dir.glob("[0-9][0-9][0-9][0-9].tsv"):
        old.unlink()
    per_year = {}
    for cve, state in sorted(rows.items()):
        per_year.setdefault(cve[4:8], []).append(f"{cve}\t{state}\n")
    index_digest = hashlib.sha256()
    for year, lines in sorted(per_year.items()):
        content = ("cve\tstate\n" + "".join(lines)).encode("ascii")
        (index_dir / f"{year}.tsv").write_bytes(content)
        index_digest.update(content)
    metadata = {
        "source": "https://github.com/CVEProject/cvelistV5/releases",
        "baseline_asset": source.name,
        "baseline_sha256": digest.hexdigest(),
        "published_digest_verified": bool(expected_sha256),
        "record_count": len(rows),
        "index_sha256": index_digest.hexdigest(),
        "index_format": "cve-ids/YYYY.tsv, sorted CVE ID and state",
        "meaning": "Official CVE List IDs and states only; no host applicability claim",
    }
    (destination / "cve-ids-source.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return len(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expected-sha256", default="", help="digest published with the release asset")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "catalog")
    args = parser.parse_args()
    print(f"Indexed {build(args.input, args.output, args.expected_sha256)} CVE IDs")
