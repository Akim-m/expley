#!/usr/bin/env python3
"""Extract per-CVE presence flags from VRS reference collections.

The following VRS collections store only CVE IDs (no timestamps):

    metasploitReference     — Metasploit exploit module exists
    nucleiReference         — Nuclei template exists
    vulncheckKevReference   — VulnCheck KEV (extended)
    zerodaysReference       — Google Project Zero 0-day

VRS also supports Trickest (trickestReference) and Nomi-sec (nomisecReference)
PoC collections, but the dev Spring profile our dump was taken from disables
their schedulers (schedule.startup=false, schedule.cron.{trickest,nomisec}=-)
so those collections are empty in our archive. PoC data is captured separately
by enrich/06_poc_dates.py via git mining of the upstream repos — richer than
the presence flags VRS would produce.

Output: one row per CVE present in any source, with one boolean column per
source. Missing collections are skipped with a warning rather than failing,
so this script is robust to future dumps that add/remove sources.

Run:
    python extract/03_vrs_presence_flags.py --out out/vrs_presence.parquet
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
SOURCES: dict[str, str] = {
    "in_metasploit": "metasploitReference",
    "in_nuclei": "nucleiReference",
    "in_vulncheck_kev": "vulncheckKevReference",
    "in_google_zeroday": "zerodaysReference",
    # Trickest and Nomi-sec PoC presence collections are not in this VRS dump.
    # Their data is captured by enrich/06_poc_dates.py (git-mined dates from
    # the upstream PoC repos), which is richer than a presence flag anyway.
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("vrs_presence")


def fetch_ids(coll) -> set[str]:
    return {d["_id"] for d in coll.find({}, {"_id": 1}) if d.get("_id")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="out/vrs_presence.parquet")
    args = parser.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    client = pymongo.MongoClient(MONGODB_URI, serverSelectionTimeoutMS=10_000)
    db = client[DB_NAME]
    existing = set(db.list_collection_names())
    presence: dict[str, set[str]] = {}
    for column, collection in SOURCES.items():
        if collection not in existing:
            log.warning("  %s: collection missing from dump — skipping %s", collection, column)
            continue
        ids = fetch_ids(db[collection])
        log.info("  %s: %d CVE IDs", collection, len(ids))
        presence[column] = ids
    client.close()

    all_ids = sorted(set().union(*presence.values()))
    log.info("Building presence matrix for %d unique CVEs", len(all_ids))
    df = pd.DataFrame({"cve_id": all_ids})
    for column, ids in presence.items():
        df[column] = df["cve_id"].isin(ids)
    df.to_parquet(out_path, index=False)
    log.info("Wrote %d rows → %s", len(df), out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
