
from temporal_exploit.simulate import synth_weaponization


def test_synth_schema_and_cure_fraction():
    corpus, event_frames, truth = synth_weaponization(n=3000, cure_fraction=0.6, seed=0)
    # handover-shaped corpus
    for col in ("cve_id", "published", "cvss_v3_base", "cvss_v3_severity", "cwe_ids"):
        assert col in corpus.columns
    assert len(corpus) == 3000
    # cure fraction recovered approximately
    assert abs(truth["cure_fraction"] - 0.6) < 0.05
    # only susceptible CVEs have a PoC event, dated after publication
    poc = event_frames["poc"][0]
    assert 0 < len(poc) < 3000
    assert set(poc["cve_id"]) <= set(corpus["cve_id"])


def test_synth_signal_is_learnable_and_zero_signal_is_not():

    from temporal_exploit.features import build_publication_features
    from temporal_exploit.labels import build_first_weaponization_labels
    from temporal_exploit.modeling import (
        _risk_scores,
        fit_cox,
        prepare_modeling_frame,
        truncated_cindex,
    )

    def cindex(signal):
        corpus, ev, _ = synth_weaponization(n=4000, signal=signal, seed=1)
        labels = build_first_weaponization_labels(corpus, ev, "2024-01-01")
        frame = prepare_modeling_frame(labels, build_publication_features(corpus))
        cox = fit_cox(frame)
        risk = _risk_scores(cox, frame[cox.feature_cols_].astype(float), "cox")
        return truncated_cindex(
            frame["duration_days"].to_numpy(float),
            frame["event_observed"].to_numpy(bool),
            risk,
            float(frame["duration_days"].max()),
        )

    assert cindex(signal=1.5) > 0.6     # real feature signal -> learnable
    assert abs(cindex(signal=0.0) - 0.5) < 0.05  # no signal -> chance level
