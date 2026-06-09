#!/usr/bin/env python3
"""Mine PoC first-publication dates from Trickest/cve and nomi-sec/PoC-in-GitHub.

Both repos use folder/file layouts where the CVE ID is in the path:
    trickest/cve         : YYYY/CVE-YYYY-NNNNN.md
    nomi-sec/PoC-in-GitHub: YYYY/CVE-YYYY-NNNNN.json

So filename → CVE resolution is straightforward. Output one row per (source, cve)
so the survival join can pick either or compute their minimum.

Run:
    python enrich/06_poc_dates.py --out out/poc_dates.parquet
"""
import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
from _git_helpers import first_add_dates, normalise_cve, shallow_clone

SOURCES: dict[str, tuple[str, tuple[str, ...]]] = {
    "trickest": ("https://github.com/trickest/cve.git", ("",)),
    "nomisec":  ("https://github.com/nomi-sec/PoC-in-GitHub.git", ("",)),
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("poc")


def mine_source(name: str, repo: Path, prefixes: tuple[str, ...]) -> list[dict]:
    add_dates = first_add_dates(repo, paths=list(prefixes) if prefixes != ("",) else None)
    earliest: dict[str, tuple[int, str]] = {}
    for path, ts in add_dates.items():
        cve_id = normalise_cve(Path(path).name)
        if not cve_id:
            continue
        prev = earliest.get(cve_id)
        if prev is None or ts < prev[0]:
            earliest[cve_id] = (ts, path)
    return [
        {
            "cve_id": cve_id,
            "poc_source": name,
            "poc_first_seen": datetime.fromtimestamp(ts, tz=timezone.utc),
            "poc_path": path,
        }
        for cve_id, (ts, path) in earliest.items()
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", default=".cache")
    parser.add_argument("--out", default="out/poc_dates.parquet")
    parser.add_argument("--skip-clone", action="store_true")
    parser.add_argument("--only", choices=list(SOURCES.keys()), default=None,
                        help="Restrict to a single source (useful for partial reruns)")
    args = parser.parse_args()

    cache = Path(args.cache)
    rows: list[dict] = []
    for name, (url, prefixes) in SOURCES.items():
        if args.only and args.only != name:
            continue
        repo = cache / f"poc-{name}"
        if not args.skip_clone:
            shallow_clone(url, repo)
        log.info("Mining %s …", name)
        rows.extend(mine_source(name, repo, prefixes))

    df = pd.DataFrame(rows).sort_values(["cve_id", "poc_first_seen"])
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out_path, index=False)
    log.info("Wrote %d rows (%d unique CVEs) → %s",
             len(df), df["cve_id"].nunique() if not df.empty else 0, out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
