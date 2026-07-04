"""Task 3 of the speed bundle: cached landmark-EPSS loader (RE-hardened).

load_epss_at_landmark(s) must read the persisted build artifact only when EVERY
guard passes — snapshot match, trajectory+published columns, corpus coverage,
and per-CVE published equality (landmark windows are [pub, pub+L], so published
drift silently changes values) — and fall back to the streamed build otherwise.
Fallback tests use a nonexistent epss_path: if the cache is (wrongly) skipped
or (wrongly) trusted, streaming raises / wrong values return — the assertions.
"""
import json

import pandas as pd
import pytest

from temporal_exploit.landmark import (
    _LANDMARK_EPSS_COLUMNS,
    load_epss_at_landmark,
    load_epss_at_landmarks,
)


def _corpus():
    return pd.DataFrame({
        "cve_id": ["CVE-1", "CVE-2"],
        "published": pd.to_datetime(["2024-01-01", "2024-02-01"], utc=True),
    })


def _fake_bundle(corpus):
    out = corpus[["cve_id", "published"]].copy()
    for c in _LANDMARK_EPSS_COLUMNS:
        out[c] = 0.5
    return out[["cve_id", *(c for c in _LANDMARK_EPSS_COLUMNS), "published"]]


def _write_artifacts(tmp_path, corpus, snapshot, columns=None, landmark_days=30):
    bundle = _fake_bundle(corpus)
    if columns is not None:
        bundle = bundle[columns]
    bundle.to_parquet(tmp_path / f"landmark_features_{landmark_days}d.parquet", index=False)
    (tmp_path / "manifest.json").write_text(json.dumps({"snapshot_date": snapshot}))


def test_cache_hit_reads_parquet_not_stream(tmp_path):
    corpus = _corpus()
    _write_artifacts(tmp_path, corpus, "2026-03-14")
    got = load_epss_at_landmark(
        corpus, epss_path="/nonexistent.parquet", landmark_days=30,
        snapshot_date="2026-03-14", artifact_dir=tmp_path,
    )  # streaming would raise on the nonexistent path -> cache must have been used
    assert list(got.columns) == ["cve_id", *_LANDMARK_EPSS_COLUMNS]
    assert got["cve_id"].tolist() == corpus["cve_id"].tolist()


def test_cache_hit_aligns_to_corpus_order(tmp_path):
    corpus = _corpus().iloc[::-1].reset_index(drop=True)  # CVE-2 first
    _write_artifacts(tmp_path, _corpus(), "2026-03-14")   # artifact in CVE-1-first order
    got = load_epss_at_landmark(
        corpus, epss_path="/nonexistent.parquet", landmark_days=30,
        snapshot_date="2026-03-14", artifact_dir=tmp_path,
    )
    assert got["cve_id"].tolist() == ["CVE-2", "CVE-1"]


@pytest.mark.parametrize(
    "break_it",
    ["snapshot", "columns", "coverage", "missing", "published_drift",
     "no_published_col", "none_snapshot"],
)
def test_cache_falls_back_when_invalid(tmp_path, break_it):
    corpus = _corpus()
    snapshot_arg = "2026-03-14"
    if break_it == "snapshot":
        _write_artifacts(tmp_path, corpus, "2020-01-01")
    elif break_it == "columns":  # stale pre-trajectory artifact (2026-06-12 shape)
        _write_artifacts(tmp_path, corpus, "2026-03-14",
                         columns=["cve_id", "epss_at_landmark"])
    elif break_it == "coverage":
        _write_artifacts(tmp_path, corpus.iloc[:1], "2026-03-14")
    elif break_it == "published_drift":  # RE audit: same ids, shifted published
        drifted = corpus.copy()
        drifted["published"] = drifted["published"] + pd.Timedelta(days=4)
        _write_artifacts(tmp_path, drifted, "2026-03-14")
    elif break_it == "no_published_col":  # pre-hardening artifact shape
        _write_artifacts(tmp_path, corpus, "2026-03-14",
                         columns=["cve_id", *_LANDMARK_EPSS_COLUMNS])
    elif break_it == "none_snapshot":  # None==None must NOT hit the cache
        _write_artifacts(tmp_path, corpus, None)
        snapshot_arg = None
    # "missing": no files at all
    with pytest.raises(Exception):  # falls back to streaming -> bad path raises
        load_epss_at_landmark(
            corpus, epss_path="/nonexistent.parquet", landmark_days=30,
            snapshot_date=snapshot_arg, artifact_dir=tmp_path,
        )


def test_plural_loader_full_hit_and_fused_miss(tmp_path):
    corpus = _corpus()
    _write_artifacts(tmp_path, corpus, "2026-03-14", landmark_days=30)
    _write_artifacts(tmp_path, corpus, "2026-03-14", landmark_days=7)
    got = load_epss_at_landmarks(
        corpus, epss_path="/nonexistent.parquet", landmarks=(7, 30),
        snapshot_date="2026-03-14", artifact_dir=tmp_path,
    )  # both cached -> nonexistent path never touched
    assert set(got) == {7, 30}
    assert got[30]["cve_id"].tolist() == corpus["cve_id"].tolist()
    # one landmark missing -> the fused fallback runs (and raises on the bad path)
    with pytest.raises(Exception):
        load_epss_at_landmarks(
            corpus, epss_path="/nonexistent.parquet", landmarks=(7, 14),
            snapshot_date="2026-03-14", artifact_dir=tmp_path,
        )
