#!/usr/bin/env python3
"""Build offline CVE IDs and optional source details from a verified V5 baseline.

No fetching, applicability matching, recipe selection, or PoC execution occurs.
All-detail generations are immutable; the small active source manifest is
replaced only after the complete staged generation passes ID/state validation.
"""

import argparse
import csv
import gzip
import hashlib
import itertools
import json
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}")
DETAIL_HEADER = "cve\tstate\tdescription\taffected_json\treferences_json\treview_state"
ALL_HEADER = DETAIL_HEADER + "\tsource_json\n"
MAX_ROW_BYTES = 16 * 1024 * 1024
MAX_SHARD_BYTES = 256 * 1024 * 1024
MAX_SHARD_ROWS = 1000
SHARD_HEADER = "path\tsha256\trows\tbytes\tuncompressed_bytes\n"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.write_bytes((json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def bucket(cve: str) -> str:
    if not ID.fullmatch(cve):
        raise ValueError(f"Invalid CVE ID: {cve}")
    # String routing preserves 4-19 digit suffixes, including leading zeroes.
    return f"{cve[4:8]}/{cve[9:-3]}.tsv.gz"


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


def english_description(container: dict, key: str = "descriptions") -> str:
    descriptions = container.get(key, [])
    if not isinstance(descriptions, list):
        return ""
    for item in descriptions:
        if isinstance(item, dict) and str(item.get("lang", "")).lower().startswith("en"):
            return str(item.get("value", ""))
    return ""


def compact(value) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def details_row(cve: str, record: dict, all_details: bool = False) -> str:
    state = record["cveMetadata"]["state"]
    if not all_details and state != "PUBLISHED":
        raise ValueError(f"Local candidate is not published: {cve}")
    containers = record.get("containers", {})
    if not isinstance(containers, dict):
        raise ValueError(f"Invalid containers: {cve}")
    container = containers.get("cna", {})
    if not isinstance(container, dict):
        raise ValueError(f"Invalid CNA container: {cve}")
    affected = container.get("affected", [])
    references = container.get("references", [])
    if not isinstance(affected, list) or not isinstance(references, list):
        raise ValueError(f"Invalid CVE source metadata: {cve}")
    description = english_description(container, "rejectedReasons" if state == "REJECTED" else "descriptions")
    if all_details:
        # JSON escaping keeps Unicode and source control characters on one TSV
        # line. source_json retains CNA/ADP claims separately, without merging.
        description = compact(description)[1:-1]
        fields = [cve, state.lower(), description, compact(affected), compact(references),
                  "source-metadata-unreviewed", compact({key: record[key] for key in
                  ("dataType", "dataVersion", "cveMetadata", "containers") if key in record})]
    else:
        # Keep the existing sparse format and byte order stable.
        fields = [cve, "published", " ".join(description.split()),
                  json.dumps(affected, ensure_ascii=True, separators=(",", ":")),
                  json.dumps(references, ensure_ascii=True, separators=(",", ":")),
                  "source-metadata-unreviewed"]
    if any(any(ord(char) < 32 for char in field) for field in fields):
        raise ValueError(f"Control character in detail row: {cve}")
    row = "\t".join(fields) + "\n"
    if len(row.encode("utf-8")) > MAX_ROW_BYTES:
        raise ValueError(f"Detail row exceeds {MAX_ROW_BYTES} bytes: {cve}")
    return row


def read_ids(destination: Path) -> tuple[dict, str]:
    rows = {}
    digest = hashlib.sha256()
    for path in sorted((destination / "cve-ids").glob("[0-9][0-9][0-9][0-9].tsv")):
        content = path.read_bytes()
        digest.update(content)
        for row in csv.DictReader(content.decode("ascii").splitlines(), delimiter="\t"):
            cve, state = row["cve"], row["state"]
            if not ID.fullmatch(cve) or cve in rows or state not in ("published", "rejected", "reserved"):
                raise ValueError("Invalid ID/state index")
            rows[cve] = state
    return rows, digest.hexdigest()


def verify_all_details(destination: Path) -> int:
    source = json.loads((destination / "all-cve-details-source.json").read_text())
    base = json.loads((destination / "cve-ids-source.json").read_text())
    marker = destination / "all-cve-details" / "installed"
    if marker.read_bytes() != (sha256(destination / "all-cve-details-source.json") + "\n").encode("ascii"):
        raise ValueError("Source manifest digest mismatch")
    generation = source["shards_sha256"]
    if not re.fullmatch(r"[0-9a-f]{64}", generation):
        raise ValueError("Invalid generation digest")
    if source["format_version"] != 1 or source["baseline_sha256"] != base["baseline_sha256"]:
        raise ValueError("Detail baseline mismatch")
    rows, index_digest = read_ids(destination)
    if source["index_sha256"] != index_digest or base["index_sha256"] != index_digest:
        raise ValueError("ID index digest mismatch")
    root = destination / "all-cve-details" / generation
    manifest = root / "shards.tsv"
    if sha256(manifest) != generation:
        raise ValueError("Shard manifest digest mismatch")
    seen = set()
    paths = set()
    with manifest.open(newline="", encoding="ascii") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        if reader.fieldnames != SHARD_HEADER.rstrip("\n").split("\t"):
            raise ValueError("Invalid shard manifest header")
        for entry in reader:
            relative = entry["path"]
            if not re.fullmatch(r"[0-9]{4}/[0-9]{1,16}\.tsv\.gz", relative) or relative in paths:
                raise ValueError("Invalid or duplicate shard path")
            paths.add(relative)
            path = root / relative
            if path.is_symlink() or path.stat().st_size != int(entry["bytes"]) or sha256(path) != entry["sha256"]:
                raise ValueError("Shard digest/size mismatch")
            count, size = 0, len(ALL_HEADER)
            with gzip.open(path, "rb") as detail:
                if detail.readline(MAX_ROW_BYTES + 1) != ALL_HEADER.encode("ascii"):
                    raise ValueError("Invalid shard header")
                while True:
                    line = detail.readline(MAX_ROW_BYTES + 1)
                    if not line:
                        break
                    size += len(line)
                    if len(line) > MAX_ROW_BYTES or size > MAX_SHARD_BYTES or not line.endswith(b"\n"):
                        raise ValueError("Shard row/size limit exceeded")
                    fields = line.decode("ascii").rstrip("\n").split("\t")
                    if len(fields) != 7:
                        raise ValueError("Invalid detail row")
                    cve, state = fields[:2]
                    if cve in seen or rows.get(cve) != state or bucket(cve) != relative:
                        raise ValueError("Detail/ID state mismatch")
                    seen.add(cve)
                    count += 1
                    if count > MAX_SHARD_ROWS:
                        raise ValueError("Shard row limit exceeded")
            if count != int(entry["rows"]) or size != int(entry["uncompressed_bytes"]):
                raise ValueError("Shard count/size mismatch")
    if seen != set(rows) or len(seen) != source["record_count"] or len(paths) != source["shard_count"]:
        raise ValueError("Incomplete detail generation")
    return len(seen)


def build(source: Path, destination: Path, expected_sha256: str = "", with_local_details: bool = False,
          with_all_details: bool = False) -> int:
    if (with_local_details or with_all_details) and not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        raise ValueError("Details require the published baseline SHA-256")
    if not with_local_details and (destination / "local-eop-details.tsv").exists():
        raise ValueError("Existing local details require --with-local-details to keep source dates aligned")
    if not with_all_details and (destination / "all-cve-details-source.json").exists():
        raise ValueError("Existing all-CVE details require --with-all-details")
    digest = sha256(source)
    if expected_sha256 and digest != expected_sha256.lower():
        raise ValueError("CVE baseline SHA-256 differs from the published digest")
    old_source = destination / "cve-ids-source.json"
    if with_all_details and old_source.exists():
        if json.loads(old_source.read_text())["baseline_sha256"] != digest:
            raise ValueError("All-CVE sidecar must match the existing ID baseline; use a fresh output for a new baseline")
    selected = selected_local_ids(destination) if with_local_details else set()
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".cve-build-", dir=destination) as temporary:
        stage = Path(temporary)
        payload = stage / "payload"
        payload.mkdir()
        rows, details, shards = {}, {}, []
        state_counts = {state: 0 for state in ("published", "rejected", "reserved")}
        with zipfile.ZipFile(source) as outer:
            if outer.namelist() != ["cves.zip"]:
                raise ValueError("Unexpected CVE baseline ZIP layout")
            with tempfile.TemporaryFile(dir=stage) as inner_file:
                with outer.open("cves.zip") as compressed:
                    shutil.copyfileobj(compressed, inner_file, 1024 * 1024)
                inner_file.seek(0)
                with zipfile.ZipFile(inner_file) as inner:
                    records = []
                    for entry in inner.infolist():
                        name = PurePosixPath(entry.filename)
                        if not name.name.startswith("CVE-"):
                            continue
                        if (entry.is_dir() or name.suffix != ".json" or not ID.fullmatch(name.stem)
                                or name.is_absolute() or ".." in name.parts or "\\" in entry.filename):
                            raise ValueError(f"Invalid CVE record path: {entry.filename}")
                        records.append((bucket(name.stem), name.stem, entry))
                    for relative, entries in itertools.groupby(sorted(records, key=lambda item: item[:2]), key=lambda item: item[0]):
                        target = payload / relative
                        if with_all_details:
                            target.parent.mkdir(parents=True, exist_ok=True)
                            raw = target.open("wb")
                            compressed = gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9)
                            compressed.write(ALL_HEADER.encode("ascii"))
                        count, size = 0, len(ALL_HEADER)
                        try:
                            for _, cve, entry in entries:
                                if cve in rows:
                                    raise ValueError(f"Duplicate CVE ID: {cve}")
                                if entry.file_size > MAX_SHARD_BYTES:
                                    raise ValueError(f"Oversized CVE source record: {cve}")
                                with inner.open(entry) as record_file:
                                    record = json.load(record_file)
                                metadata = record.get("cveMetadata", {})
                                state = metadata.get("state", "")
                                if metadata.get("cveId") != cve or state not in ("PUBLISHED", "REJECTED", "RESERVED"):
                                    raise ValueError(f"Invalid record metadata: {entry.filename}")
                                rows[cve] = state.lower()
                                state_counts[state.lower()] += 1
                                if cve in selected:
                                    details[cve] = details_row(cve, record)
                                if with_all_details:
                                    line = details_row(cve, record, True).encode("ascii")
                                    count += 1
                                    size += len(line)
                                    if count > MAX_SHARD_ROWS or size > MAX_SHARD_BYTES:
                                        raise ValueError(f"Detail shard exceeds limits: {relative}")
                                    compressed.write(line)
                        finally:
                            if with_all_details:
                                compressed.close()
                                raw.close()
                        if with_all_details:
                            shards.append(f"{relative}\t{sha256(target)}\t{count}\t{target.stat().st_size}\t{size}\n")
        if not rows:
            raise ValueError("No CVE records in baseline")
        if selected and set(details) != selected:
            raise ValueError(f"Local candidates missing from CVE baseline: {', '.join(sorted(selected - set(details)))}")
        index_dir = stage / "cve-ids"
        index_dir.mkdir()
        index_digest = hashlib.sha256()
        for year, entries in itertools.groupby(sorted(rows), key=lambda cve: cve[4:8]):
            content = ("cve\tstate\n" + "".join(f"{cve}\t{rows[cve]}\n" for cve in entries)).encode("ascii")
            (index_dir / f"{year}.tsv").write_bytes(content)
            index_digest.update(content)
        metadata = {
            "source": "https://github.com/CVEProject/cvelistV5/releases", "baseline_asset": source.name,
            "baseline_sha256": digest, "published_digest_verified": bool(expected_sha256),
            "record_count": len(rows), "state_counts": state_counts, "index_sha256": index_digest.hexdigest(),
            "index_format": "cve-ids/YYYY.tsv, sorted CVE ID and state",
            "meaning": "Official CVE List IDs and states only; no host applicability claim",
        }
        write_json(stage / "cve-ids-source.json", metadata)
        if old_source.exists() and with_all_details:
            old_rows, old_digest = read_ids(destination)
            if rows != old_rows or old_digest != metadata["index_sha256"]:
                raise ValueError("All-detail records differ from the existing ID/state index")
        if selected:
            content = (DETAIL_HEADER + "\n" + "".join(details[cve] for cve in sorted(details))).encode("utf-8")
            (stage / "local-eop-details.tsv").write_bytes(content)
            write_json(stage / "local-eop-details-source.json", {
                "source": metadata["source"], "baseline_asset": source.name, "baseline_sha256": digest,
                "published_digest_verified": True, "selected_count": len(selected),
                "details_sha256": hashlib.sha256(content).hexdigest(),
                "meaning": "CNA metadata for local-EoP review leads only; not a host applicability or patch assessment",
            })
        if with_all_details:
            (payload / "shards.tsv").write_bytes((SHARD_HEADER + "".join(shards)).encode("ascii"))
            generation = sha256(payload / "shards.tsv")
            generations = stage / "all-cve-details"
            generations.mkdir()
            payload.rename(generations / generation)
            write_json(stage / "all-cve-details-source.json", {
                "format_version": 1, "source": metadata["source"], "baseline_asset": source.name,
                "baseline_sha256": digest, "published_digest_verified": True,
                "index_sha256": metadata["index_sha256"], "record_count": len(rows),
                "shard_count": len(shards), "shards_sha256": generation,
                "meaning": "Unreviewed CNA and ADP source claims; no host applicability, patch or recipe selection",
            })
            (generations / "installed").write_bytes((sha256(stage / "all-cve-details-source.json") + "\n").encode("ascii"))
            verify_all_details(stage)
            final_generations = destination / "all-cve-details"
            installed = final_generations / "installed"
            active = installed.exists() or installed.is_symlink()
            if active:
                # Replacing two files cannot atomically switch source + marker.
                # Only an identical active source may be rebuilt in place, so
                # any later marker-write failure leaves the old pack valid.
                if (installed.is_symlink() or not installed.is_file() or
                        installed.read_bytes() != (generations / "installed").read_bytes() or
                        (destination / "all-cve-details-source.json").read_bytes() !=
                        (stage / "all-cve-details-source.json").read_bytes()):
                    raise ValueError("Installed detail provenance differs; use a fresh output catalog")
            final_generations.mkdir(exist_ok=True)
            final_generation = final_generations / generation
            if final_generation.is_symlink():
                raise ValueError("Detail generation must not be a link")
            if final_generation.exists():
                matching = True
                for path in (generations / generation).rglob("*"):
                    if not path.is_file():
                        continue
                    existing = final_generation / path.relative_to(generations / generation)
                    if existing.is_symlink() or not existing.is_file() or sha256(path) != sha256(existing):
                        matching = False
                        break
                if not matching:
                    if active:
                        raise ValueError("Existing generation differs from the staged payload")
                    # A source checkout tracks only shards.tsv. With no install
                    # marker, replace its incomplete generation as one directory.
                    previous = stage / "previous-generation"
                    final_generation.rename(previous)
                    try:
                        (generations / generation).rename(final_generation)
                    except OSError:
                        previous.rename(final_generation)
                        raise
            else:
                (generations / generation).rename(final_generation)
        (destination / "cve-ids").mkdir(exist_ok=True)
        for path in index_dir.iterdir():
            os.replace(path, destination / "cve-ids" / path.name)
        for old in (destination / "cve-ids").glob("[0-9][0-9][0-9][0-9].tsv"):
            if old.stem not in {cve[4:8] for cve in rows}:
                old.unlink()
        for name in ("cve-ids-source.json", "local-eop-details.tsv", "local-eop-details-source.json",
                     "all-cve-details-source.json"):
            if (stage / name).exists():
                os.replace(stage / name, destination / name)
        if with_all_details:
            os.replace(generations / "installed", destination / "all-cve-details" / "installed")
    return len(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--expected-sha256", default="", help="digest published with the release asset")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "catalog")
    parser.add_argument("--with-local-details", action="store_true", help="retain CNA metadata for selected local-EoP review leads")
    parser.add_argument("--with-all-details", action="store_true", help="build the optional complete dated source-detail sidecar")
    parser.add_argument("--verify-all-details", action="store_true", help="verify every installed detail shard against the ID/state index")
    args = parser.parse_args()
    if args.verify_all_details:
        print(f"Verified {verify_all_details(args.output)} all-CVE detail rows")
    else:
        if args.input is None:
            parser.error("--input is required for a build")
        print(f"Indexed {build(args.input, args.output, args.expected_sha256, args.with_local_details, args.with_all_details)} CVE IDs")
