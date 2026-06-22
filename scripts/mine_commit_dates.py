"""Mine fix-commit dates for the OSS subset (Phase 2 patch clock).

20.9k CVEs carry a fix-commit URL in their NVD references; 98.9% are full-SHA
GitHub commits. GitHub GraphQL lets us batch ~50 commit lookups per request
(repository(owner,name).object(oid).committedDate), turning a ~4h REST crawl
into minutes. committedDate = when the fix landed = patch-available proxy.

Auth via the local `gh` token (5000 pts/hr). Checkpoints every BATCH to
data/merged/commit_date_parts/. Output: data/merged/commit_dates.parquet
  cve_id, repo, commit_sha, commit_date
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pandas as pd

OUT = Path("data/merged/commit_dates.parquet")
PARTS = Path("data/merged/commit_date_parts")
BATCH = 50
# github.com/<owner>/<repo>/commit/<40-hex>; owner/repo restricted to safe chars
URL_RE = re.compile(
    r"github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/commit/([0-9a-f]{40})", re.I
)


def parse_first(urls) -> tuple[str, str, str] | None:
    for u in urls:
        m = URL_RE.search(u)
        if m:
            return m.group(1), m.group(2), m.group(3).lower()
    return None


def gql(batch) -> dict:
    """One GraphQL request with up to BATCH aliased commit lookups."""
    parts = []
    for i, (_, owner, repo, sha) in enumerate(batch):
        parts.append(
            f'a{i}: repository(owner:"{owner}", name:"{repo}") '
            f'{{ object(oid:"{sha}") {{ ... on Commit {{ committedDate }} }} }}'
        )
    query = "query {\n" + "\n".join(parts) + "\n}"
    res = subprocess.run(
        ["gh", "api", "graphql", "-f", f"query={query}"],
        capture_output=True, text=True, timeout=120,
    )
    if res.returncode != 0:
        # whole-query failure (rare) -> empty; those CVEs just stay undated
        return {}
    return json.loads(res.stdout).get("data", {}) or {}


def main():
    PARTS.mkdir(parents=True, exist_ok=True)
    refs = pd.read_parquet("data/merged/nvd_references.parquet",
                           columns=["cve_id", "commit_urls"])
    refs = refs[refs.commit_urls.str.len() > 0]
    items = []
    for cve, urls in zip(refs.cve_id, refs.commit_urls):
        p = parse_first(urls)
        if p:
            items.append((cve, *p))   # (cve, owner, repo, sha)
    print(f"mineable github full-SHA commits: {len(items)}", flush=True)

    done_batches = {int(p.stem.split("_")[1]) for p in PARTS.glob("part_*.parquet")}
    for b in range(0, len(items), BATCH):
        bn = b // BATCH
        if bn in done_batches:
            continue
        batch = items[b:b + BATCH]
        data = gql(batch)
        rows = []
        for i, (cve, owner, repo, sha) in enumerate(batch):
            node = (data.get(f"a{i}") or {})
            obj = node.get("object") if isinstance(node, dict) else None
            cd = obj.get("committedDate") if isinstance(obj, dict) else None
            rows.append({"cve_id": cve, "repo": f"{owner}/{repo}",
                         "commit_sha": sha, "commit_date": cd})
        pd.DataFrame(rows).to_parquet(PARTS / f"part_{bn:05d}.parquet")
        if bn % 20 == 0:
            print(f"batch {bn} / {len(items)//BATCH}", flush=True)

    parts = [pd.read_parquet(p) for p in sorted(PARTS.glob("part_*.parquet"))]
    full = pd.concat(parts, ignore_index=True)
    full["commit_date"] = pd.to_datetime(full["commit_date"], utc=True, errors="coerce")
    full.to_parquet(OUT)
    ok = full.commit_date.notna().mean()
    print(f"DONE rows={len(full)} dated={ok:.3f} -> {OUT}", flush=True)


if __name__ == "__main__":
    main()
