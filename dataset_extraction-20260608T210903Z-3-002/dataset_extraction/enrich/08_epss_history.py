#!/usr/bin/env python3
"""Download FIRST.org daily EPSS archive and stack into a long-form parquet.

EPSS archives are at:
    https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz

There is one CSV per day from 2021-04-14 onward. Each CSV has columns
`cve,epss,percentile` and a comment header naming the model version.

This script is incremental: it writes one daily parquet per date under
.cache/epss/ and then concatenates everything into the final output. Reruns
skip dates that are already cached, so it's safe to resume after interruption.

Run examples:
    python enrich/08_epss_history.py --start 2023-01-01 --end 2024-12-31 \\
        --out out/epss_history.parquet
    python enrich/08_epss_history.py --start 2023-01-01 --end 2023-01-31 \\
        --concat-only --out out/epss_history.parquet
"""
import argparse
import gzip
import io
import logging
import sys
from datetime import date, timedelta
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import requests
from tqdm import tqdm

# Canonical schema for the concatenated parquet. Early EPSS v1 days have
# all-null `percentile` (model didn't emit it) which pyarrow infers as a null
# column; later v2 days have it as double. Casting both to this canonical
# schema during concat lets them coexist in one file.
CANONICAL_SCHEMA = pa.schema([
    pa.field("cve_id", pa.string()),
    pa.field("date", pa.timestamp("ms", tz="UTC")),
    pa.field("epss", pa.float64()),
    pa.field("percentile", pa.float64()),
])

# Cyentia was acquired and rebranded; the archive lives at the new domain now.
# The old epss.cyentia.com URL still redirects but 403s intermittently — go
# direct to avoid the redirect.
URL_TEMPLATE = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("epss")


def daterange(start: date, end: date):
    cur = start
    while cur <= end:
        yield cur
        cur += timedelta(days=1)


def fetch_one(d: date, cache: Path, session: requests.Session) -> Path | None:
    out = cache / f"epss-{d.isoformat()}.parquet"
    if out.exists():
        return out
    url = URL_TEMPLATE.format(date=d.isoformat())
    try:
        resp = session.get(url, timeout=60)
    except requests.RequestException as exc:
        log.warning("network error %s: %s", d, exc)
        return None
    if resp.status_code in (403, 404):
        # 403 shows up for early-launch dates where the archive file isn't
        # available (model tuning days, etc.). Treat as "missing day, skip"
        # rather than aborting the run.
        log.warning("no EPSS file for %s (%d)", d, resp.status_code)
        return None
    resp.raise_for_status()
    text = gzip.decompress(resp.content).decode("utf-8")
    # First line is a comment beginning with '#' — pandas handles that.
    df = pd.read_csv(io.StringIO(text), comment="#")
    df = df.rename(columns={"cve": "cve_id"})
    # EPSS v1 (April 2021 — March 2022) did not emit a `percentile` column;
    # only `epss`. Backfill as NA so downstream schema is uniform.
    if "percentile" not in df.columns:
        df["percentile"] = pd.NA
    df["date"] = pd.Timestamp(d, tz="UTC")
    df = df[["cve_id", "date", "epss", "percentile"]]
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--start", type=date.fromisoformat, required=False,
                        default=date(2021, 4, 14))
    parser.add_argument("--end", type=date.fromisoformat, required=False,
                        default=date.today() - timedelta(days=1))
    parser.add_argument("--cache", default=".cache/epss")
    parser.add_argument("--out", default="out/epss_history.parquet")
    parser.add_argument("--concat-only", action="store_true",
                        help="Skip downloading; just concatenate what's already cached")
    args = parser.parse_args()

    cache = Path(args.cache)
    cache.mkdir(parents=True, exist_ok=True)

    if not args.concat_only:
        session = requests.Session()
        for d in tqdm(list(daterange(args.start, args.end)), unit="day"):
            fetch_one(d, cache, session)

    daily_files = sorted(cache.glob("epss-*.parquet"))
    if not daily_files:
        log.error("nothing to concatenate; check the date range and --cache directory")
        return 1
    log.info("Streaming-concat %d daily files → %s", len(daily_files), args.out)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Stream: read one daily parquet, write its rows to the output file, free
    # memory. Avoids loading all 1.7k daily frames into RAM simultaneously
    # (which OOMs at ~20 GB peak for the 247M-row dataset). Each table is
    # cast to CANONICAL_SCHEMA so v1 (null percentile) and v2 (double
    # percentile) days coexist.
    writer = pq.ParquetWriter(out_path, CANONICAL_SCHEMA)
    total_rows = 0
    try:
        for f in tqdm(daily_files, unit="file"):
            table = pq.read_table(f).cast(CANONICAL_SCHEMA, safe=False)
            writer.write_table(table)
            total_rows += table.num_rows
    finally:
        writer.close()
    log.info("Wrote %d rows → %s", total_rows, out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
