import json

import pandas as pd

from temporal_exploit.merge import merge_live, merge_source


def _kev(cve, date):
    return pd.DataFrame({"cve_id": cve, "kev_date_added": pd.to_datetime(date, utc=True)})


def test_merge_source_kev_keeps_earliest():
    handover = _kev(["CVE-1"], ["2024-02-01"])
    live = _kev(["CVE-1", "CVE-2"], ["2024-01-01", "2024-03-01"])
    merged = merge_source(handover, live, key="cve_id", order_col="kev_date_added", keep="first")
    got = dict(zip(merged["cve_id"], merged["kev_date_added"]))
    assert got["CVE-1"] == pd.Timestamp("2024-01-01", tz="UTC")
    assert got["CVE-2"] == pd.Timestamp("2024-03-01", tz="UTC")


def test_merge_source_corpus_keeps_newest():
    handover = pd.DataFrame(
        {"cve_id": ["CVE-1"], "last_modified": pd.to_datetime(["2024-01-01"], utc=True), "description": ["old"]}
    )
    live = pd.DataFrame(
        {"cve_id": ["CVE-1"], "last_modified": pd.to_datetime(["2024-02-01"], utc=True), "description": ["new"]}
    )
    merged = merge_source(handover, live, key="cve_id", order_col="last_modified", keep="last")
    assert len(merged) == 1
    assert merged.iloc[0]["description"] == "new"


def test_merge_source_epss_dedupes_by_cve_date_live_wins():
    handover = pd.DataFrame(
        {"cve_id": ["CVE-1"], "date": pd.to_datetime(["2024-01-01"], utc=True), "epss": [0.1]}
    )
    live = pd.DataFrame(
        {
            "cve_id": ["CVE-1", "CVE-1"],
            "date": pd.to_datetime(["2024-01-01", "2024-01-02"], utc=True),
            "epss": [0.2, 0.3],
        }
    )
    merged = merge_source(handover, live, key=["cve_id", "date"], keep="last")
    day1 = merged[merged["date"] == pd.Timestamp("2024-01-01", tz="UTC")]
    assert len(merged) == 2
    assert day1.iloc[0]["epss"] == 0.2


def test_merge_source_empty_live_returns_handover():
    handover = _kev(["CVE-1"], ["2024-02-01"])
    empty = handover.iloc[0:0]
    merged = merge_source(handover, empty, key="cve_id", order_col="kev_date_added", keep="first")
    assert len(merged) == 1


def test_merge_dedups_vulncheck_and_exploitdb(tmp_path):
    # vulncheck_kev / exploitdb have no handover counterpart (live-only), but a
    # re-fetch must still dedup within the live frame on the merge key rather
    # than pass through verbatim with duplicate rows.
    handover = tmp_path / "h"
    live = tmp_path / "l"
    out = tmp_path / "o"
    handover.mkdir()
    live.mkdir()
    _kev(["CVE-1"], ["2022-01-01"]).to_parquet(handover / "kev_events.parquet", index=False)
    pd.DataFrame(
        {
            "cve_id": ["CVE-1", "CVE-1"],
            "vulncheck_kev_date_added": pd.to_datetime(["2022-03-01", "2022-01-15"], utc=True),
        }
    ).to_parquet(live / "vulncheck_kev.parquet", index=False)
    pd.DataFrame(
        {
            "cve_id": ["CVE-1", "CVE-1", "CVE-1"],
            "exploitdb_id": [10, 10, 20],
            "exploitdb_date_published": pd.to_datetime(
                ["2022-03-01", "2022-01-15", "2022-02-01"], utc=True
            ),
        }
    ).to_parquet(live / "exploitdb.parquet", index=False)

    summary = merge_live(handover, live, out)

    vc = pd.read_parquet(out / "vulncheck_kev.parquet")
    assert len(vc) == 1  # one CVE, earliest date_added wins
    assert vc.loc[0, "vulncheck_kev_date_added"] == pd.Timestamp("2022-01-15", tz="UTC")

    edb = pd.read_parquet(out / "exploitdb.parquet")
    assert len(edb) == 2  # (CVE-1,10) deduped to earliest, (CVE-1,20) kept
    id10 = edb[edb["exploitdb_id"] == 10].iloc[0]
    assert id10["exploitdb_date_published"] == pd.Timestamp("2022-01-15", tz="UTC")

    # manifest records the dedup as a merge, not a verbatim copy
    strategies = {e["source"]: e["strategy"] for e in summary["entries"]}
    assert strategies["vulncheck_kev"] == "merge_live_only"
    assert strategies["exploitdb"] == "merge_live_only"


def test_merge_live_merges_known_sources_and_copies_passthrough(tmp_path):
    handover = tmp_path / "handover"
    live = tmp_path / "live"
    out = tmp_path / "unified"
    handover.mkdir()
    live.mkdir()

    _kev(["CVE-1"], ["2024-02-01"]).to_parquet(handover / "kev_events.parquet", index=False)
    pd.DataFrame({"cve_id": ["CVE-9"], "poc_first_seen": pd.to_datetime(["2023-01-01"], utc=True)}).to_parquet(
        handover / "poc_dates.parquet", index=False
    )
    _kev(["CVE-1", "CVE-2"], ["2024-01-01", "2024-03-01"]).to_parquet(
        live / "kev_events.parquet", index=False
    )

    summary = merge_live(handover, live, out)

    merged_kev = pd.read_parquet(out / "kev_events.parquet")
    assert set(merged_kev["cve_id"]) == {"CVE-1", "CVE-2"}
    assert merged_kev.set_index("cve_id").loc["CVE-1", "kev_date_added"] == pd.Timestamp(
        "2024-01-01", tz="UTC"
    )
    # passthrough copied unchanged
    assert (out / "poc_dates.parquet").exists()
    assert set(pd.read_parquet(out / "poc_dates.parquet")["cve_id"]) == {"CVE-9"}

    manifest = json.loads((out / "merge_manifest.json").read_text())
    assert summary["entries"] == manifest["entries"]  # return value mirrors the written manifest
    kev_entry = next(e for e in manifest["entries"] if e["source"] == "kev_events")
    assert kev_entry["merged_rows"] == 2
    assert kev_entry["live_rows"] == 2
    assert any(e["source"] == "poc_dates" and e["strategy"] == "copy" for e in manifest["entries"])
