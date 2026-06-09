#!/usr/bin/env python3
"""Mine first-seen dates per CVE from the projectdiscovery/nuclei-templates repo.

Nuclei templates are stored under http/cves/<year>/cve-YYYY-NNNNN.yaml so the
CVE ID is in the path itself — no file-content scan needed.

Output: parquet with (cve_id, nuclei_first_seen, nuclei_template_path).

Run:
    python enrich/05_nuclei_dates.py --repo .cache/nuclei-templates \\
                                      --out out/nuclei_dates.parquet
"""
import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
from _git_helpers import first_add_dates, normalise_cve, shallow_clone

REPO_URL = "https://github.com/projectdiscovery/nuclei-templates.git"
PATH_PREFIXES = ("http/cves/", "cves/")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("nuclei")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".cache/nuclei-templates")
    parser.add_argument("--out", default="out/nuclei_dates.parquet")
    parser.add_argument("--skip-clone", action="store_true")
    args = parser.parse_args()

    repo = Path(args.repo)
    if not args.skip_clone:
        shallow_clone(REPO_URL, repo)

    add_dates = first_add_dates(repo, paths=list(PATH_PREFIXES))
    log.info("Resolving CVE IDs from %d template paths", len(add_dates))

    earliest: dict[str, tuple[int, str]] = {}
    for path, ts in add_dates.items():
        cve_id = normalise_cve(Path(path).name)
        if not cve_id:
            continue
        prev = earliest.get(cve_id)
        if prev is None or ts < prev[0]:
            earliest[cve_id] = (ts, path)

    rows = [
        {
            "cve_id": cve_id,
            "nuclei_first_seen": datetime.fromtimestamp(ts, tz=timezone.utc),
            "nuclei_template_path": path,
        }
        for cve_id, (ts, path) in earliest.items()
    ]
    df = pd.DataFrame(rows).sort_values("nuclei_first_seen")
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out_path, index=False)
    log.info("Wrote %d CVE→date rows → %s", len(df), out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
