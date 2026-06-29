"""GreyNoise CVE in-the-wild observation connector (prospective accumulator).

The connector turns GreyNoise's rolling-window `exploitation_activity` (threat-IP
counts) into a per-CVE "observed exploited in the wild as of <snapshot>" stamp.
It does NOT use `first_known_published_date` (that is exploit-code publication =
tooling, the project's existing first-weaponization signal, not in-the-wild).
These tests pin the parse contract; the network call is exercised only via the
token / empty-list short-circuits (no live API in CI).
"""
import pandas as pd
import pytest

from temporal_exploit.fetch.greynoise import GreyNoiseCVEConnector

SNAPSHOT = "2026-06-30"
COLS = ["cve_id", "greynoise_inwild_first_seen"]


def _payload():
    return {
        "data": [
            # observed exploited in the wild -> kept
            {"id": "CVE-2024-0001", "exploitation_activity": {"threat_ip_count_30d": 12, "benign_ip_count_30d": 3}},
            # benign-only scanning (no threat IPs) -> NOT in-wild
            {"id": "CVE-2024-0002", "exploitation_activity": {"threat_ip_count_30d": 0, "benign_ip_count_30d": 50}},
            # no observed activity at all -> dropped
            {"id": "CVE-2024-0003", "exploitation_activity": {}},
            # alternate key name, threshold exactly met -> kept
            {"cve": "CVE-2024-0004", "exploitation_activity": {"threat_ip_count_30d": 1}},
        ]
    }


def test_parse_stamps_only_observed_inwild_with_snapshot_date():
    df = GreyNoiseCVEConnector._parse(_payload(), SNAPSHOT)
    assert list(df.columns) == COLS
    assert set(df["cve_id"]) == {"CVE-2024-0001", "CVE-2024-0004"}
    # every kept CVE is stamped with the observation snapshot date, tz-aware UTC
    assert (df["greynoise_inwild_first_seen"] == pd.Timestamp(SNAPSHOT, tz="UTC")).all()
    assert str(df["greynoise_inwild_first_seen"].dt.tz) == "UTC"


def test_parse_window_and_threshold():
    payload = {"data": [{"id": "CVE-A", "exploitation_activity": {"threat_ip_count_1d": 0, "threat_ip_count_30d": 5}}]}
    assert GreyNoiseCVEConnector._parse(payload, SNAPSHOT, window="1d").empty       # 0 in 1d window
    assert len(GreyNoiseCVEConnector._parse(payload, SNAPSHOT, window="30d")) == 1  # 5 in 30d window
    assert GreyNoiseCVEConnector._parse(payload, SNAPSHOT, window="30d", threat_threshold=10).empty


def test_parse_dedups_keeps_one_row_per_cve():
    payload = {"data": [
        {"id": "CVE-X", "exploitation_activity": {"threat_ip_count_30d": 2}},
        {"id": "CVE-X", "exploitation_activity": {"threat_ip_count_30d": 9}},
    ]}
    df = GreyNoiseCVEConnector._parse(payload, SNAPSHOT)
    assert df["cve_id"].tolist() == ["CVE-X"]


def test_parse_accepts_bare_list_and_empty_data():
    assert GreyNoiseCVEConnector._parse([{"id": "CVE-1", "exploitation_activity": {"threat_ip_count_30d": 3}}], SNAPSHOT)["cve_id"].tolist() == ["CVE-1"]
    # an empty data array must yield an empty frame, not try to parse the envelope
    empty = GreyNoiseCVEConnector._parse({"data": []}, SNAPSHOT)
    assert empty.empty and list(empty.columns) == COLS


def test_fetch_requires_token():
    with pytest.raises(ValueError):
        GreyNoiseCVEConnector().fetch("", ["CVE-2024-0001"], SNAPSHOT)


def test_fetch_empty_cve_list_short_circuits_without_network():
    df = GreyNoiseCVEConnector().fetch("tok", [], SNAPSHOT)
    assert df.empty and list(df.columns) == COLS
