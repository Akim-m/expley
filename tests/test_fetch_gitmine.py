
from temporal_exploit.fetch import gitmine
from temporal_exploit.fetch.nuclei import NucleiConnector
from temporal_exploit.fetch.poc import PocConnector


def test_normalise_cve():
    assert gitmine.normalise_cve("cve-2021-44228.yaml") == "CVE-2021-44228"
    assert gitmine.normalise_cve("CVE-2024-0001.md") == "CVE-2024-0001"
    assert gitmine.normalise_cve("readme.md") is None


def test_parse_added_keeps_earliest_per_path():
    stdout = "\n".join(
        [
            "COMMIT 200",
            "http/cves/2021/cve-2021-1.yaml",
            "",
            "COMMIT 100",
            "http/cves/2021/cve-2021-1.yaml",
            "http/cves/2021/cve-2021-2.yaml",
        ]
    )
    added = gitmine._parse_added(stdout)
    assert added["http/cves/2021/cve-2021-1.yaml"] == 100
    assert added["http/cves/2021/cve-2021-2.yaml"] == 100


def test_earliest_by_cve_resolves_and_dedupes():
    added = {
        "http/cves/2021/cve-2021-0001.yaml": 300,
        "archived/cve-2021-0001.yaml": 100,
        "notes/readme.md": 50,
    }
    earliest = gitmine.earliest_by_cve(added)
    assert set(earliest) == {"CVE-2021-0001"}
    ts, path = earliest["CVE-2021-0001"]
    assert ts == 100
    assert path == "archived/cve-2021-0001.yaml"


def test_nuclei_connector_builds_schema(monkeypatch):
    monkeypatch.setattr(
        gitmine,
        "first_add_dates",
        lambda repo, paths=None: {
            "http/cves/2021/cve-2021-44228.yaml": 1_600_000_000,
            "http/cves/2020/cve-2020-0001.yaml": 1_500_000_000,
        },
    )
    frame = NucleiConnector().fetch(repo="anything", skip_clone=True)

    assert list(frame.columns) == ["cve_id", "nuclei_first_seen", "nuclei_template_path"]
    assert str(frame["nuclei_first_seen"].dt.tz) == "UTC"
    # sorted ascending: the 2020 template (earlier ts) comes first
    assert list(frame["cve_id"]) == ["CVE-2020-0001", "CVE-2021-44228"]


def test_poc_connector_emits_row_per_source(monkeypatch):
    monkeypatch.setattr(
        gitmine,
        "first_add_dates",
        lambda repo, paths=None: {f"2021/{repo.name}-CVE-2021-0001.json": 1_600_000_000},
    )
    frame = PocConnector().fetch(cache="anything", skip_clone=True)

    assert list(frame.columns) == ["cve_id", "poc_source", "poc_first_seen", "poc_path"]
    assert set(frame["poc_source"]) == set(PocConnector.SOURCES)
    assert set(frame["cve_id"]) == {"CVE-2021-0001"}


def test_earliest_introduction_skips_on_pickaxe_timeout(monkeypatch, tmp_path):
    import subprocess

    from temporal_exploit.fetch import gitmine

    def fake_run(cmd, **kwargs):
        assert kwargs.get("timeout") is not None  # the call is bounded
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    monkeypatch.setattr(gitmine.subprocess, "run", fake_run)
    # a stalled pair is skipped (None), not propagated as a crash
    assert gitmine.earliest_introduction(tmp_path, "CVE-2021-44228", "some/path") is None
