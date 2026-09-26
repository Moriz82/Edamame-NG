#!/usr/bin/env python3
"""Build an offline ID/state index from an official CVE List V5 baseline ZIP.

The CVE Project distributes a ZIP containing cves.zip. This script streams the
inner archive to a temporary file and retains CVE IDs and record states. With
--with-local-details, it also retains source metadata for the small existing
local-EoP review set. Neither output establishes host applicability.
"""

import argparse
import csv
import hashlib
import json
import re
import shutil
import tempfile
import zipfile
from pathlib import Path


ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def selected_local_ids(destination: Path) -> set[str]:
    selected = set()
    for name in ("local-eop.tsv", "curated-eop.tsv"):
        with (destination / name).open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream, delimiter="\t")
            if not reader.fieldnames or "cve" not in reader.fieldnames:
                raise ValueError(f"Missing CVE column: {name}")
            for row in reader:
                cve = row["cve"]
                if not ID.fullmatch(cve):
                    raise ValueError(f"Invalid local candidate ID: {cve}")
                selected.add(cve)
    if not selected:
        raise ValueError("No local-EoP candidates selected")
    return selected


def english_description(container: dict) -> str:
    descriptions = container.get("descriptions", [])
    if not isinstance(descriptions, list):
        return ""
    for item in descriptions:
        if isinstance(item, dict) and str(item.get("lang", "")).lower().startswith("en"):
            return " ".join(str(item.get("value", "")).split())
    return ""


def details_row(cve: str, record: dict) -> str:
    if record["cveMetadata"]["state"] != "PUBLISHED":
        raise ValueError(f"Local candidate is not published: {cve}")
    container = record.get("containers", {}).get("cna", {})
    if not isinstance(container, dict):
        raise ValueError(f"Invalid CNA container: {cve}")
    affected = container.get("affected", [])
    references = container.get("references", [])
    if not isinstance(affected, list) or not isinstance(references, list):
        raise ValueError(f"Invalid CVE source metadata: {cve}")
    fields = (
        cve,
        "published",
        english_description(container),
        json.dumps(affected, ensure_ascii=True, separators=(",", ":")),
        json.dumps(references, ensure_ascii=True, separators=(",", ":")),
        "source-metadata-unreviewed",
    )
    if any("\t" in field or "\n" in field or "\r" in field for field in fields):
        raise ValueError(f"Control character in detail row: {cve}")
    return "\t".join(fields) + "\n"


def build(source: Path, destination: Path, expected_sha256: str = "", with_local_details: bool = False) -> int:
    if with_local_details and not expected_sha256:
        raise ValueError("Local details require the published baseline SHA-256")
    if not with_local_details and (destination / "local-eop-details.tsv").exists():
        raise ValueError("Existing local details require --with-local-details to keep source dates aligned")
    selected = selected_local_ids(destination) if with_local_details else set()
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
                details = {}
                state_counts = {state: 0 for state in ("published", "rejected", "reserved")}
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
                    state_counts[state.lower()] += 1
                    if cve in selected:
                        details[cve] = details_row(cve, record)
    if selected and set(details) != selected:
        missing = sorted(selected - set(details))
        raise ValueError(f"Local candidates missing from CVE baseline: {', '.join(missing)}")
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
        "state_counts": state_counts,
        "index_sha256": index_digest.hexdigest(),
        "index_format": "cve-ids/YYYY.tsv, sorted CVE ID and state",
        "meaning": "Official CVE List IDs and states only; no host applicability claim",
    }
    (destination / "cve-ids-source.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if selected:
        content = ("cve\tstate\tdescription\taffected_json\treferences_json\treview_state\n" +
                   "".join(details[cve] for cve in sorted(details))).encode("utf-8")
        (destination / "local-eop-details.tsv").write_bytes(content)
        detail_metadata = {
            "source": metadata["source"],
            "baseline_asset": source.name,
            "baseline_sha256": digest.hexdigest(),
            "published_digest_verified": True,
            "selected_count": len(selected),
            "details_sha256": hashlib.sha256(content).hexdigest(),
            "meaning": "CNA metadata for local-EoP review leads only; not a host applicability or patch assessment",
        }
        (destination / "local-eop-details-source.json").write_text(
            json.dumps(detail_metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return len(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expected-sha256", default="", help="digest published with the release asset")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "catalog")
    parser.add_argument("--with-local-details", action="store_true", help="retain CNA metadata for selected local-EoP review leads")
    args = parser.parse_args()
    print(f"Indexed {build(args.input, args.output, args.expected_sha256, args.with_local_details)} CVE IDs")
