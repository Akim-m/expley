"""HackerOne Hacktivity as an EPSS-reconciliation lens — reproducible fetch + analysis.

Evaluates whether HackerOne *coordinated-disclosure* (bug-bounty) reports carry an
in-the-wild signal that COMPLEMENTS EPSS. Conclusion (see the companion doc
`docs/hackerone_epss_reconciliation_2026-07.md`): HackerOne report membership is a
real but SPARSE EPSS-blind-spot flag — it does NOT add new in-wild labels and is
too small (and likely redundant with existing structural features) to move a model
metric, but it makes a clean, quantified case study of *where EPSS is blind*.

Data source: hackerone.com/graphql (unauthenticated, introspection open).
  - Feed used: search(index: CompleteHacktivityReportIndex) -> HacktivityDocument
    (has cve_ids, cwe, severity_rating, submitted_at, disclosed_at — real history).
  - Offset paging (from/size) bypasses the 50-row cursor cap; ES max_result_window
    (10k) means date-slicing is the fallback for larger query sets.
  - Throttled 3s/request with 429/503 backoff. Full CVE-tagged set is only ~1.9k rows.

Run:
  .venv/bin/python scripts/hackerone_epss_reconciliation.py --fetch   # ~40 throttled requests
  .venv/bin/python scripts/hackerone_epss_reconciliation.py           # analysis only (uses cache)
"""
from __future__ import annotations
import argparse, json, sys, time, urllib.request, urllib.error
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out"
ART = REPO / "artifacts"
CACHE = REPO / "artifacts" / "hackerone_cve_reports.json"   # gitignored artifacts dir

GRAPHQL = "https://hackerone.com/graphql"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
QS = "disclosed:true AND _exists_:cve_ids"
QUERY = """query($qs:String!,$from:Int!,$size:Int!){
  search(index: CompleteHacktivityReportIndex, query_string:$qs, from:$from, size:$size){
    total_count
    edges{ node{ ... on HacktivityDocument {
      _id cve_ids cwe severity_rating submitted_at disclosed_at
    }}}
  }
}"""


def _gq(variables, throttle=3.0):
    time.sleep(throttle)
    req = urllib.request.Request(
        GRAPHQL, data=json.dumps({"query": QUERY, "variables": variables}).encode(),
        headers={"Content-Type": "application/json", "User-Agent": UA, "Accept": "application/json"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=40) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code in (429, 503):
                wait = 10 * (attempt + 1)
                print(f"  [{e.code}] backoff {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            raise
    raise RuntimeError("retries exhausted")


def fetch_all(size=50, cap=2100) -> list[dict]:
    rows, seen, off = [], set(), 0
    while off < cap:
        d = _gq({"qs": QS, "from": off, "size": size})
        if "errors" in d:
            print("GraphQL error:", json.dumps(d["errors"])[:300]); break
        s = d["data"]["search"]
        got = 0
        for e in s["edges"]:
            n = e["node"]
            if n.get("_id") in seen:
                continue
            seen.add(n.get("_id")); got += 1
            if n.get("cve_ids"):
                rows.append({k: n.get(k) for k in
                             ("_id", "cve_ids", "cwe", "severity_rating", "submitted_at", "disclosed_at")})
        print(f"from={off:4d} got={got:2d} cum={len(rows):4d}/{s['total_count']}")
        if got == 0:
            break
        off += size
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(rows))
    print(f"saved {len(rows)} rows -> {CACHE}")
    return rows


def _upper_set(series) -> set[str]:
    return set(series.astype(str).str.upper())


def analyse(rows: list[dict]) -> dict:
    # explode to per-CVE, keep earliest submitted/disclosed
    sub, dis = {}, {}
    for r in rows:
        for c in (r.get("cve_ids") or []):
            c = c.strip().upper()
            s = pd.to_datetime(r.get("submitted_at"), utc=True, errors="coerce")
            d = pd.to_datetime(r.get("disclosed_at"), utc=True, errors="coerce")
            if pd.notna(s):
                sub[c] = min(sub.get(c, s), s)
            if pd.notna(d):
                dis[c] = min(dis.get(c, d), d)
    h1 = set(sub) | set(dis)

    corpus = pq.read_table(OUT / "cve_corpus.parquet", columns=["cve_id", "published", "cwe_ids"]).to_pandas()
    corpus["cve_id"] = corpus["cve_id"].astype(str).str.upper()
    corpus["published"] = pd.to_datetime(corpus["published"], utc=True, errors="coerce")
    corpus_cves = set(corpus["cve_id"])
    pub = corpus.set_index("cve_id")["published"]
    cwe_map = corpus.set_index("cve_id")["cwe_ids"]

    kev = pq.read_table(OUT / "kev_events.parquet").to_pandas()
    kcid = next(c for c in kev.columns if "cve" in c.lower())
    kev_cves = _upper_set(kev[kcid]) & corpus_cves

    ep = pq.read_table(ART / "epss_at_publication.parquet").to_pandas()
    ep["cve_id"] = ep["cve_id"].astype(str).str.upper()
    pct = ep.set_index("cve_id")["epss_percentile_at_publication"]

    h1 = h1 & corpus_cves
    N = len(corpus_cves)
    base_rate = 100 * len(kev_cves) / N
    h1_rate = 100 * len(h1 & kev_cves) / len(h1)

    # EPSS blind-spot: within EPSS bottom-decile, KEV rate H1 vs non-H1
    vlow = set(pct[pct < 0.1].index) & corpus_cves
    h1_lo, non_lo = vlow & h1, vlow - h1
    kr_h1 = 100 * len(h1_lo & kev_cves) / max(1, len(h1_lo))
    kr_non = 100 * len(non_lo & kev_cves) / max(1, len(non_lo))

    # leakage boundary
    comm = [c for c in h1 if c in pub.index and pd.notna(pub[c])]
    dis_before = sum(1 for c in comm if c in dis and dis[c] <= pub[c])

    # CWE clusters of the blind-spot in-wild CVEs
    def cwes(cve):
        v = cwe_map.get(cve)
        if v is None:
            return []
        return [str(x) for x in v] if isinstance(v, (list, np.ndarray)) else [str(v)]
    blind = sorted(c for c in h1 if c in kev_cves and c in pct.index and pct[c] < 0.1)
    cwe_cnt = Counter(w for c in blind for w in cwes(c))

    return {
        "h1_unique_cves": len(h1),
        "corpus_inwild_rate_pct": round(base_rate, 3),
        "h1_inwild_rate_pct": round(h1_rate, 3),
        "h1_inwild_lift_x": round(h1_rate / base_rate, 1),
        "blindspot_kev_rate_h1_pct": round(kr_h1, 3),
        "blindspot_kev_rate_non_h1_pct": round(kr_non, 3),
        "blindspot_lift_x": round(kr_h1 / max(1e-9, kr_non), 1),
        "blindspot_inwild_cves_flagged": len(blind),
        "leakage_safe_fraction_pct": round(100 * dis_before / len(comm), 1),
        "blindspot_top_cwes": cwe_cnt.most_common(8),
        "blindspot_examples": blind[:8],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fetch", action="store_true", help="re-pull from HackerOne (throttled)")
    args = ap.parse_args()
    rows = fetch_all() if args.fetch or not CACHE.exists() else json.loads(CACHE.read_text())
    res = analyse(rows)
    print(json.dumps(res, indent=2))
    (ART / "hackerone_epss_reconciliation.json").write_text(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
