"""Lightweight NVD 2.0 reference puller — the patch-clock foundation (Phase 2).

The corpus connector kept only reference_count; we need the reference TAGS
(Patch / Vendor Advisory / Exploit) and the fix-COMMIT URLs. This pages the full
NVD 2.0 catalog (no date filter -> all CVEs, ~180 pages of 2000), extracting only
the cheap per-CVE signals so memory + parse cost stay tiny:

  cve_id, has_patch_ref, has_vendor_advisory, has_exploit_ref, n_refs, commit_urls

Checkpoints every CHUNK pages to data/merged/nvd_refs_parts/ so a 503 death never
loses the crawl. Keyless => sleep SPACING s between requests (NVD: 5 req / 30s).
Combine parts at the end into data/merged/nvd_references.parquet.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pandas as pd

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PARTS = Path("data/merged/nvd_refs_parts")
OUT = Path("data/merged/nvd_references.parquet")
PAGE = 2000
SPACING = 6.5          # keyless safety (5 req / 30s)
CHUNK = 5              # checkpoint every CHUNK pages (limits re-fetch on crash)
COMMIT_RE = re.compile(r"(github\.com|gitlab\.com|bitbucket\.org)/[^\s]+/commit/[0-9a-f]{7,40}", re.I)
PATCH_TAGS = {"Patch"}
ADVISORY_TAGS = {"Vendor Advisory"}
EXPLOIT_TAGS = {"Exploit"}


def _get(url: str, retries: int = 8) -> dict:
    """Resilient GET: retries on HTTP 429/503 AND socket/read timeouts + URL errors
    (the keyless NVD endpoint drops slow reads), with exponential backoff."""
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 503) and attempt < retries:
                time.sleep(min(60, 6.0 * (2 ** attempt)))
                continue
            raise
        except (TimeoutError, urllib.error.URLError, ConnectionError, OSError) as exc:
            if attempt < retries:
                time.sleep(min(60, 6.0 * (2 ** attempt)))
                continue
            raise RuntimeError(f"give up after {retries} retries: {exc}") from exc


def parse(vulns):
    rows = []
    for entry in vulns:
        cve = entry["cve"]
        refs = cve.get("references", [])
        tags, commits = set(), []
        for r in refs:
            for t in r.get("tags", []) or []:
                tags.add(t)
            url = r.get("url", "")
            if COMMIT_RE.search(url):
                commits.append(url)
        rows.append({
            "cve_id": cve["id"],
            "has_patch_ref": bool(tags & PATCH_TAGS),
            "has_vendor_advisory": bool(tags & ADVISORY_TAGS),
            "has_exploit_ref": bool(tags & EXPLOIT_TAGS),
            "n_refs": len(refs),
            "commit_urls": commits,
        })
    return pd.DataFrame(rows)


def main():
    PARTS.mkdir(parents=True, exist_ok=True)
    done = {int(p.stem.split("_")[1]) for p in PARTS.glob("part_*.parquet")}
    start_index = 0
    buf, total = [], None
    page_no = 0
    while True:
        if page_no in done:  # resume: skip already-saved pages
            start_index += PAGE
            page_no += 1
            if total is not None and start_index >= total:
                break
            continue
        params = {"resultsPerPage": PAGE, "startIndex": start_index}
        url = f"{BASE}?{urllib.parse.urlencode(params)}"
        payload = _get(url)
        total = payload.get("totalResults", 0)
        vulns = payload.get("vulnerabilities", [])
        if vulns:
            buf.append((page_no, parse(vulns)))
        print(f"page {page_no} idx {start_index}/{total} got {len(vulns)}", flush=True)
        start_index += len(vulns)
        if len(buf) >= CHUNK:
            for pn, df in buf:
                df.to_parquet(PARTS / f"part_{pn:04d}.parquet")
            buf = []
        page_no += 1
        if not vulns or start_index >= total:
            break
        time.sleep(SPACING)
    for pn, df in buf:
        df.to_parquet(PARTS / f"part_{pn:04d}.parquet")

    parts = [pd.read_parquet(p) for p in sorted(PARTS.glob("part_*.parquet"))]
    full = pd.concat(parts, ignore_index=True).drop_duplicates("cve_id")
    full.to_parquet(OUT)
    print(f"DONE rows={len(full)} patch_ref={full.has_patch_ref.mean():.3f} "
          f"with_commit={ (full.commit_urls.str.len()>0).mean():.3f} -> {OUT}", flush=True)


if __name__ == "__main__":
    main()
