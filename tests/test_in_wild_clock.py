"""in_wild_clock_start — the in-wild risk-set floor.

A first-evidence source (VulnCheck / Shadowserver / Google 0-day) carries genuine
discovery/exploitation dates with no catalog-launch backfill spike, so it lifts the
CISA catalog-launch floor — which otherwise globally drops every CVE published before
2021-11-03 from training (a measured loss: +0.0147 AUC@90 recovered by removing it,
CI excludes 0; see scripts/inwild_floor_ablation.py). Catalog-add-only sources (CISA
KEV: all 287 launch-day entries stamped 2021-11-03) keep the floor.
"""
from temporal_exploit.cli import in_wild_clock_start


def test_cisa_only_keeps_the_catalog_floor():
    assert in_wild_clock_start(("kev",)) == "2021-11-03"


def test_first_evidence_source_lifts_the_floor():
    # VulnCheck's first-evidence dates make the global published-floor unnecessary;
    # its earliest-wins merge already supplies real dates for the CISA backfill CVEs.
    assert in_wild_clock_start(("kev", "vulncheck_kev")) is None


def test_evidence_only_sources_have_no_floor():
    assert in_wild_clock_start(("google_0day",)) is None
    assert in_wild_clock_start(("shadowserver",)) is None


def test_no_sources_no_floor():
    assert in_wild_clock_start(()) is None
