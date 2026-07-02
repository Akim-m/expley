"""Task 3 of the speed bundle: cached landmark-EPSS loader.

load_epss_at_landmark must read the persisted build artifact when it is valid
(snapshot matches, trajectory columns present, corpus covered) and fall back to
the streamed build otherwise. The fallback tests use a nonexistent epss_path:
if the cache is (wrongly) skipped, streaming raises — which is the assertion.
"""
import json

import numpy as np
import pandas as pd
import pytest

from temporal_exploit.landmark import _LANDMARK_EPSS_COLUMNS, load_epss_at_landmark


def _corpus():
    return pd.DataFrame({
        "cve_id": ["CVE-1", "CVE-2"],
        "published": pd.to_datetime(["2024-01-01", "2024-02-01"], utc=True),
    })


def _fake_bundle(corpus):
    out = corpus[["cve_id"]].copy()
    for c in _LANDMARK_EPSS_COLUMNS:
        out[c] = 0.5
    return out


def _write_artifacts(tmp_path, corpus, snapshot, columns=None):
    bundle = _fake_bundle(corpus)
    if columns is not None:
        bundle = bundle[columns]
    bundle.to_parquet(tmp_path / "landmark_features_30d.parquet", index=False)
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


@pytest.mark.parametrize("break_it", ["snapshot", "columns", "coverage", "missing"])
def test_cache_falls_back_when_invalid(tmp_path, break_it):
    corpus = _corpus()
    if break_it == "snapshot":
        _write_artifacts(tmp_path, corpus, "2020-01-01")
    elif break_it == "columns":  # stale pre-trajectory artifact (2026-06-12 shape)
        _write_artifacts(tmp_path, corpus, "2026-03-14",
                         columns=["cve_id", "epss_at_landmark"])
    elif break_it == "coverage":
        _write_artifacts(tmp_path, corpus.iloc[:1], "2026-03-14")
    # "missing": no files at all
    with pytest.raises(Exception):  # falls back to streaming -> bad path raises
        load_epss_at_landmark(
            corpus, epss_path="/nonexistent.parquet", landmark_days=30,
            snapshot_date="2026-03-14", artifact_dir=tmp_path,
        )
