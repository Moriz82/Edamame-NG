#!/usr/bin/env python3
"""Build a compact, review-only local EoP index from an official CISA KEV JSON file.

This development-time command never downloads data. Runtime scripts only read its output.
"""

import argparse
import hashlib
import json
import re
from pathlib import Path

SOURCE_URL = "https://github.com/cisagov/kev-data/blob/develop/known_exploited_vulnerabilities.json"
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
EOP = re.compile(r"privilege escalation|elevation of privilege|escalat(?:e|ion) privileges|elevat(?:e|ion) privileges|elevated privileges|as (?:root|system)", re.I)
LINUX_VENDORS = {"linux", "linux kernel", "sudo", "gnu", "red hat", "canonical", "ubuntu", "polkit"}
LINUX_PRODUCTS = re.compile(r"kernel|sudo|glibc|polkit|policykit|libuser|abrt", re.I)


def clean(value):
    return " ".join(str(value).split())


def classify(item):
    vendor = clean(item["vendorProject"])
    product = clean(item["product"])
    name = clean(item["vulnerabilityName"])
    description = clean(item["shortDescription"])
    if not EOP.search(name + " " + description):
        return None
    if vendor.casefold() == "microsoft" and product.casefold().startswith("windows"):
        return "windows"
    if vendor.casefold() in LINUX_VENDORS and LINUX_PRODUCTS.search(product + " " + name):
        return "linux"
    return None


def build(source: Path, destination: Path):
    raw = source.read_bytes()
    data = json.loads(raw)
    if not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("Missing CISA vulnerabilities list")
    if data.get("count") != len(data["vulnerabilities"]):
        raise ValueError("CISA count does not match the vulnerability list")
    rows = []
    seen = set()
    for item in data["vulnerabilities"]:
        identifier = item["cveID"]
        if not CVE.fullmatch(identifier) or identifier in seen:
            raise ValueError("Invalid or duplicate CVE ID")
        seen.add(identifier)
        platform = classify(item)
        if not platform:
            continue
        date = item["dateAdded"]
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", date):
            raise ValueError("Invalid CISA dateAdded")
        product = clean(item["product"])
        if len(product) > 120:
            product = product[:117] + "..."
        rows.append((identifier, platform, product, date,
                     f"https://www.cve.org/CVERecord?id={identifier}"))
    rows.sort()
    destination.mkdir(parents=True, exist_ok=True)
    index = destination / "local-eop.tsv"
    index.write_text("cve\tplatform\tproduct\tkev_date\treference\n" +
                     "".join("\t".join(row) + "\n" for row in rows))
    metadata = {
        "source": SOURCE_URL,
        "catalog_version": data["catalogVersion"],
        "catalog_released": data["dateReleased"],
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "source_records": data["count"],
        "indexed_candidates": len(rows),
        "meaning": "CISA KEV local-EoP text candidates; not host vulnerability or exploit proof",
    }
    (destination / "source.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return len(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="verified CISA KEV JSON snapshot")
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "catalog")
    args = parser.parse_args()
    print(f"Indexed {build(args.input, args.output)} review-only candidates in {args.output}")
