
from temporal_exploit.features import build_publication_features
from temporal_exploit.labels import build_first_weaponization_labels
from temporal_exploit.loaders import load_parquet
from temporal_exploit.schema import REQUIRED_COLUMNS, validate_columns
from tests.fixtures.tiny_parquets import write_tiny_handover


def test_labels_and_features_from_fixture_parquets(tmp_path):
    write_tiny_handover(tmp_path)
    corpus = load_parquet(tmp_path, "cve_corpus")
    poc = load_parquet(tmp_path, "poc_dates")
    kev = load_parquet(tmp_path, "kev_events")
    for name, frame in [("cve_corpus", corpus), ("poc_dates", poc), ("kev_events", kev)]:
        validate_columns(frame, name, REQUIRED_COLUMNS[name])

    labels = build_first_weaponization_labels(
        corpus,
        {"poc": (poc, "poc_first_seen"), "kev": (kev, "kev_date_added")},
        snapshot_date="2024-03-01",
    )
    observed = labels.loc[labels["cve_id"] == "CVE-2024-0001"].iloc[0]
    assert observed["event_source"] == "poc"
    assert observed["duration_days"] == 9
    censored = labels.loc[labels["cve_id"] == "CVE-2024-0002"].iloc[0]
    assert censored["event_source"] == "censored"

    features = build_publication_features(corpus)
    assert features["weakness_count"].tolist() == [1, 1]
    assert features["vendor_count"].tolist() == [1, 1]
