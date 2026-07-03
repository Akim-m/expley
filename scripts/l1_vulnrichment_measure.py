"""L1 measurement: label value of mined Vulnrichment SSVC `active` dates.

Quantifies what the git-mined CISA Vulnrichment `Exploitation: active` dates add
*on top of* the in-wild sources already wired into the pipeline (kev, google_0day,
vulncheck_kev, shadowserver, msrc — labels.IN_WILD_SOURCES). This is a
VERIFICATION step only: the source is NOT added to EVENT_SOURCES/IN_WILD_SOURCES
here (see CLAUDE.md leakage discipline — SSVC Exploitation is a label, never a
feature, and label wiring happens after this measurement).

Loads existing in-wild sources exactly the way scripts/inwild_remetric.py does
(data/live first, handover OUT_DIR fallback). All dates normalized tz-aware UTC.

Outputs artifacts/l1_vulnrichment_measure.json + a compact stdout summary.
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd

from temporal_exploit.cli import EVENT_SOURCES, IN_WILD_SOURCES, load_optional_event
from temporal_exploit.loaders import load_parquet

OUT_DIR = Path("dataset_extraction-20260608T210903Z-3-002/dataset_extraction/out")
LIVE_DIR = Path("data/live")
MINED_PATH = LIVE_DIR / "vulnrichment_ssvc.parquet"
OUT_JSON = Path("artifacts/l1_vulnrichment_measure.json")


def _utc(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, errors="coerce", utc=True)


def main() -> None:
    # ---- mined SSVC active dates ------------------------------------------
    mined = pd.read_parquet(MINED_PATH)
    for col in ("ssvc_active_date", "ssvc_poc_date"):
        mined[col] = _utc(mined[col])
    active = mined.loc[mined["ssvc_active_date"].notna(), ["cve_id", "ssvc_active_date"]]
    active = active.dropna(subset=["cve_id"]).drop_duplicates("cve_id")
    active_cves = set(active["cve_id"])

    # ---- existing in-wild sources (inwild_remetric.py loading contract) ----
    existing_frames: dict[str, pd.DataFrame] = {}
    for source, (parquet_name, date_col) in EVENT_SOURCES.items():
        if source not in IN_WILD_SOURCES:
            continue
        frame = load_optional_event(LIVE_DIR, parquet_name, date_col)
        if frame is None:
            frame = load_optional_event(OUT_DIR, parquet_name, date_col)
        if frame is not None:
            f = frame[["cve_id", date_col]].copy()
            f[date_col] = _utc(f[date_col])
            f = f.dropna(subset=["cve_id", date_col])
            existing_frames[source] = f.rename(columns={date_col: "date"})
    loaded_sources = sorted(existing_frames)

    # union of CVEs seen in-wild + per-CVE earliest in-wild date
    if existing_frames:
        existing_all = pd.concat(existing_frames.values(), ignore_index=True)
    else:
        existing_all = pd.DataFrame(columns=["cve_id", "date"])
    existing_earliest = existing_all.groupby("cve_id")["date"].min()
    existing_cves = set(existing_earliest.index)

    # ---- (a) net-new vs existing in-wild union ----------------------------
    net_new_cves = active_cves - existing_cves
    overlap_cves = active_cves & existing_cves

    # ---- (b) per-CVE date delta on the overlap ----------------------------
    ov = active[active["cve_id"].isin(overlap_cves)].copy()
    ov["existing_earliest"] = ov["cve_id"].map(existing_earliest)
    ov["delta_days"] = (
        ov["ssvc_active_date"] - ov["existing_earliest"]
    ).dt.total_seconds() / 86400.0
    d = ov["delta_days"].to_numpy()
    delta_stats = {
        "n_overlap": int(len(ov)),
        "median_days": float(np.median(d)) if len(d) else None,
        "q25_days": float(np.percentile(d, 25)) if len(d) else None,
        "q75_days": float(np.percentile(d, 75)) if len(d) else None,
        "mean_days": float(np.mean(d)) if len(d) else None,
        "pct_mined_earlier": float(np.mean(d < 0) * 100) if len(d) else None,
        "pct_mined_same_day": float(np.mean(d == 0) * 100) if len(d) else None,
        "pct_mined_later": float(np.mean(d > 0) * 100) if len(d) else None,
    }

    # ---- (c) net-new usable-as-events check against the corpus ------------
    corpus = load_parquet(OUT_DIR, "cve_corpus", columns=["cve_id", "published"])
    corpus["published"] = _utc(corpus["published"])
    pub = corpus.dropna(subset=["published"]).set_index("cve_id")["published"]

    nn = active[active["cve_id"].isin(net_new_cves)].copy()
    nn["published"] = nn["cve_id"].map(pub)
    in_corpus = nn["published"].notna()
    nn_in_corpus = nn[in_corpus].copy()
    nn_not_in_corpus = int((~in_corpus).sum())

    dur = (
        nn_in_corpus["ssvc_active_date"] - nn_in_corpus["published"]
    ).dt.total_seconds() / 86400.0
    usable_after = dur > 0        # active strictly after publication -> usable event
    same_day = dur == 0
    negative = dur < 0            # active before publication -> negative-duration

    usable = nn_in_corpus[usable_after].copy()

    net_new_stats = {
        "net_new_cve_count": int(len(net_new_cves)),
        "overlap_cve_count": int(len(overlap_cves)),
        "net_new_in_corpus": int(in_corpus.sum()),
        "net_new_not_in_corpus": nn_not_in_corpus,
        "usable_events_after_publication": int(usable_after.sum()),
        "same_day_as_publication": int(same_day.sum()),
        "negative_duration": int(negative.sum()),
    }

    # ---- (d) usable net-new events per publication year -------------------
    usable_by_year = (
        usable["published"].dt.year.value_counts().sort_index().astype(int).to_dict()
    )
    usable_by_year = {str(int(y)): int(c) for y, c in usable_by_year.items()}

    out = {
        "inputs": {
            "mined_path": str(MINED_PATH),
            "existing_in_wild_sources_loaded": loaded_sources,
            "existing_in_wild_sources_configured": list(IN_WILD_SOURCES),
        },
        "totals": {
            "mined_active_cves": int(len(active_cves)),
            "existing_in_wild_union_cves": int(len(existing_cves)),
        },
        "a_net_new": {
            "net_new_cves": int(len(net_new_cves)),
            "overlap_cves": int(len(overlap_cves)),
        },
        "b_overlap_date_delta_mined_minus_existing": delta_stats,
        "c_net_new_usable": net_new_stats,
        "d_usable_net_new_events_by_publication_year": usable_by_year,
    }
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(out, indent=1))

    # ---- compact summary --------------------------------------------------
    print(f"loaded in-wild sources: {loaded_sources}")
    print(f"mined active CVEs={len(active_cves)}  existing in-wild union={len(existing_cves)}")
    print(f"(a) net-new={len(net_new_cves)}  overlap={len(overlap_cves)}")
    print(
        f"(b) overlap delta (mined-existing) days: median={delta_stats['median_days']} "
        f"q25={delta_stats['q25_days']} q75={delta_stats['q75_days']} "
        f"earlier={delta_stats['pct_mined_earlier']}%"
    )
    print(
        f"(c) net-new in corpus={net_new_stats['net_new_in_corpus']} "
        f"(not-in-corpus={net_new_stats['net_new_not_in_corpus']}) | "
        f"usable(after pub)={net_new_stats['usable_events_after_publication']} "
        f"same-day={net_new_stats['same_day_as_publication']} "
        f"neg-duration={net_new_stats['negative_duration']}"
    )
    print(f"(d) usable net-new events by pub year: {usable_by_year}")
    print(f"wrote {OUT_JSON}")


if __name__ == "__main__":
    main()
