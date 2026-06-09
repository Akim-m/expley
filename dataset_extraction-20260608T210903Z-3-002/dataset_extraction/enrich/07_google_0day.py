#!/usr/bin/env python3
"""Extract Google Project Zero "0days in the Wild" timestamps.

VRS ships a copy of the canonical CSV at
    vulnerability-retrieval-service/src/main/resources/zerodays/0day _In the Wild_ - All.csv

so this script defaults to that local copy. Pass --url to fetch a fresher copy
from the upstream Project Zero Google Sheet export.

Schema (input CSV):
    CVE, Vendor, Product, Type, Description, Date Discovered, Date Patched,
    Advisory, Analysis URL, Root Cause Analysis, Reported By

Output columns:
    cve_id, zeroday_date_discovered (nullable), zeroday_date_patched (nullable),
    zeroday_vendor, zeroday_product, zeroday_type

Run:
    python enrich/07_google_0day.py --out out/google_0day.parquet
    python enrich/07_google_0day.py --url https://… --out out/google_0day.parquet
"""
import argparse
import logging
import sys
from io import StringIO
from pathlib import Path

import pandas as pd
import requests

DEFAULT_CSV = Path(__file__).resolve().parents[2] / (
    "vulnerability-retrieval-service/src/main/resources/zerodays/"
    "0day _In the Wild_ - All.csv"
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("zeroday")


def load(source: str | Path, url: str | None) -> pd.DataFrame:
    if url:
        log.info("Fetching upstream CSV: %s", url)
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return pd.read_csv(StringIO(resp.text))
    log.info("Reading local CSV: %s", source)
    return pd.read_csv(source)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=str(DEFAULT_CSV))
    parser.add_argument("--url", default=None,
                        help="Fetch from this URL instead of the local VRS copy")
    parser.add_argument("--out", default="out/google_0day.parquet")
    args = parser.parse_args()

    df = load(args.source, args.url)
    df = df.rename(columns={
        "CVE": "cve_id",
        "Vendor": "zeroday_vendor",
        "Product": "zeroday_product",
        "Type": "zeroday_type",
        "Date Discovered": "zeroday_date_discovered",
        "Date Patched": "zeroday_date_patched",
    })
    df = df[df["cve_id"].notna() & df["cve_id"].str.startswith("CVE-", na=False)].copy()
    df["zeroday_date_discovered"] = pd.to_datetime(
        df["zeroday_date_discovered"].replace("???", pd.NA), errors="coerce", utc=True,
    )
    df["zeroday_date_patched"] = pd.to_datetime(
        df["zeroday_date_patched"].replace("???", pd.NA), errors="coerce", utc=True,
    )
    keep = [
        "cve_id", "zeroday_date_discovered", "zeroday_date_patched",
        "zeroday_vendor", "zeroday_product", "zeroday_type",
    ]
    df = df[keep].drop_duplicates(subset=["cve_id"], keep="first")
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out_path, index=False)
    log.info("Wrote %d rows → %s", len(df), out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
