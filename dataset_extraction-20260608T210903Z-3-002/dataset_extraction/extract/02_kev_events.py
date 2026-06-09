#!/usr/bin/env python3
"""Extract CISA KEV exploitation events from VRS MongoDB.

Output columns:
    cve_id, kev_date_added (timestamp), kev_vendor, kev_product,
    kev_vulnerability_name, kev_due_date, kev_known_ransomware,
    kev_short_description

CISA `dateAdded` is the canonical exploitation event timestamp. The downstream
survival analysis picks its own right-censoring snapshot date.

Run:
    python extract/02_kev_events.py --out out/kev_events.parquet
"""
import argparse
import logging
import os
import sys
from pathlib import Path

import pandas as pd
import pymongo

MONGODB_URI = os.getenv(
    "MONGODB_URI",
    "mongodb://root:example@localhost:27017/?directConnection=true",
)
DB_NAME = os.getenv("VRS_DB_NAME", "threatAssessmentEngineData")
KEV_COLLECTION = "knownExploitedVulnerabilities"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("kev_events")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="out/kev_events.parquet")
    args = parser.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    client = pymongo.MongoClient(MONGODB_URI, serverSelectionTimeoutMS=10_000)
    coll = client[DB_NAME][KEV_COLLECTION]
    log.info("Reading %s.%s", DB_NAME, KEV_COLLECTION)
    docs = list(coll.find({}))
    client.close()
    log.info("Fetched %d KEV entries", len(docs))

    rows = [
        {
            "cve_id": d.get("_id") or d.get("cveId") or d.get("cve"),
            "kev_date_added": d.get("dateAdded"),
            "kev_vendor": d.get("vendorProject"),
            "kev_product": d.get("product"),
            "kev_vulnerability_name": d.get("vulnerabilityName"),
            "kev_due_date": d.get("dueDate"),
            "kev_known_ransomware": (d.get("knownRansomwareCampaignUse") or "").lower() == "known",
            "kev_short_description": d.get("shortDescription"),
        }
        for d in docs
    ]
    df = pd.DataFrame(rows)
    df = df[df["cve_id"].notna()].copy()
    df["kev_date_added"] = pd.to_datetime(df["kev_date_added"], errors="coerce", utc=True)
    df["kev_due_date"] = pd.to_datetime(df["kev_due_date"], errors="coerce", utc=True)
    df.to_parquet(out_path, index=False)
    log.info("Wrote %d rows → %s", len(df), out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
