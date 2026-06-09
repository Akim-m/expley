#!/usr/bin/env python3
"""Extract the full CVE corpus from VRS MongoDB into a flat parquet table.

Output columns:
    cve_id, published, last_modified, cisa_exploit_added, description,
    cwe_ids (list[str]), cvss_v3_base, cvss_v3_severity, cvss_v3_vector,
    cvss_v2_base, vendors (list[str]), products (list[str]), reference_count

This is the base table that every other dataset joins onto.

Run:
    python extract/01_cve_corpus.py --out out/cve_corpus.parquet
    python extract/01_cve_corpus.py --limit 1000   # quick dev sample
"""
import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any

import pandas as pd
import pymongo
from tqdm import tqdm

MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb://root:example@localhost:27017/?directConnection=true",
)
DB_NAME = os.getenv("VRS_DB_NAME", "threatAssessmentEngineData")
CVE_COLLECTION = "vulncheckCveItem"
BATCH_SIZE = 1000

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("cve_corpus")


def english_description(doc: dict) -> str:
    for d in doc.get("descriptions", []) or []:
        if d.get("lang") == "en":
            return d.get("value") or ""
    return ""


def extract_cwe_ids(doc: dict) -> list[str]:
    ids: list[str] = []
    for pt in doc.get("weaknesses", []) or doc.get("problemTypes", []) or []:
        for desc in pt.get("description", []) or pt.get("descriptions", []) or []:
            value = desc.get("value") or desc.get("cweId")
            if not value:
                continue
            value = str(value).strip()
            if value.upper().startswith("CWE-"):
                ids.append(value.upper())
            elif value.isdigit():
                ids.append(f"CWE-{value}")
    return sorted(set(ids))


def extract_cvss(doc: dict) -> dict[str, Any]:
    metrics = doc.get("metrics") or {}
    out = {
        "cvss_v3_base": None,
        "cvss_v3_severity": None,
        "cvss_v3_vector": None,
        "cvss_v2_base": None,
    }
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for entry in metrics.get(key, []) or []:
            data = entry.get("cvssData") or {}
            out["cvss_v3_base"] = data.get("baseScore")
            out["cvss_v3_severity"] = data.get("baseSeverity")
            out["cvss_v3_vector"] = data.get("vectorString")
            if out["cvss_v3_base"] is not None:
                break
        if out["cvss_v3_base"] is not None:
            break
    for entry in metrics.get("cvssMetricV2", []) or []:
        data = entry.get("cvssData") or {}
        out["cvss_v2_base"] = data.get("baseScore")
        if out["cvss_v2_base"] is not None:
            break
    return out


def extract_vendors_products(doc: dict) -> tuple[list[str], list[str]]:
    vendors: set[str] = set()
    products: set[str] = set()
    cpes = doc.get("vcVulnerableCPEs") or doc.get("configurations") or []
    if isinstance(cpes, list):
        for entry in cpes:
            if isinstance(entry, str):
                _parse_cpe(entry, vendors, products)
            elif isinstance(entry, dict):
                cpe_str = entry.get("cpe23Uri") or entry.get("criteria")
                if cpe_str:
                    _parse_cpe(cpe_str, vendors, products)
                for node in entry.get("nodes", []) or []:
                    for match in node.get("cpeMatch", []) or []:
                        s = match.get("criteria")
                        if s:
                            _parse_cpe(s, vendors, products)
    return sorted(vendors), sorted(products)


def _parse_cpe(cpe: str, vendors: set[str], products: set[str]) -> None:
    parts = cpe.split(":")
    if len(parts) >= 5 and parts[0] == "cpe":
        vendors.add(parts[3])
        products.add(parts[4])


def doc_to_row(doc: dict) -> dict[str, Any]:
    cvss = extract_cvss(doc)
    vendors, products = extract_vendors_products(doc)
    return {
        "cve_id": doc.get("id") or doc.get("_id"),
        "published": doc.get("published"),
        "last_modified": doc.get("lastModified"),
        "cisa_exploit_added": doc.get("cisaExploitAdd"),
        "description": english_description(doc),
        "cwe_ids": extract_cwe_ids(doc),
        **cvss,
        "vendors": vendors,
        "products": products,
        "reference_count": len(doc.get("references", []) or []),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="out/cve_corpus.parquet")
    parser.add_argument("--limit", type=int, default=None, help="Process only N documents (dev mode)")
    args = parser.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    log.info("Connecting to MongoDB at %s", MONGODB_URI)
    client = pymongo.MongoClient(MONGODB_URI, serverSelectionTimeoutMS=10_000)
    coll = client[DB_NAME][CVE_COLLECTION]
    total = coll.estimated_document_count() if args.limit is None else args.limit
    log.info("Streaming up to %s documents from %s.%s", total, DB_NAME, CVE_COLLECTION)

    cursor = coll.find({}, batch_size=BATCH_SIZE)
    if args.limit is not None:
        cursor = cursor.limit(args.limit)

    rows: list[dict[str, Any]] = []
    for doc in tqdm(cursor, total=total, unit="cve"):
        try:
            row = doc_to_row(doc)
        except Exception as exc:  # noqa: BLE001 — log and continue, don't abort on per-row issues
            log.warning("skipped %s: %s", doc.get("id"), exc)
            continue
        if row["cve_id"]:
            rows.append(row)

    client.close()
    log.info("Writing %d rows → %s", len(rows), out_path)
    df = pd.DataFrame(rows)
    df["published"] = pd.to_datetime(df["published"], errors="coerce", utc=True)
    df["last_modified"] = pd.to_datetime(df["last_modified"], errors="coerce", utc=True)
    df["cisa_exploit_added"] = pd.to_datetime(df["cisa_exploit_added"], errors="coerce", utc=True)
    df.to_parquet(out_path, index=False)
    log.info("Done. Columns: %s", list(df.columns))
    return 0


if __name__ == "__main__":
    sys.exit(main())
