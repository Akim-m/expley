import json

from temporal_exploit.fetch import gitmine
from temporal_exploit.fetch.metasploit import MetasploitConnector, cves_from_module


def test_cves_from_module_string_and_dict_refs():
    module = {
        "references": [
            "CVE-2021-44228",
            {"type": "CVE", "ref": "2017-0144"},
            {"type": "URL", "ref": "https://example.com"},
            "URL-not-a-cve",
        ]
    }
    assert cves_from_module(module) == {"CVE-2021-44228", "CVE-2017-0144"}


def test_cves_from_module_handles_missing_refs():
    assert cves_from_module({}) == set()
    assert cves_from_module({"references": None}) == set()


def test_metasploit_connector_builds_schema(monkeypatch):
    manifest = {
        "exploit/multi/log4shell": {
            "path": "/modules/exploits/multi/http/log4shell.rb",
            "references": ["CVE-2021-44228"],
        },
        "exploit/windows/eternalblue": {
            "path": "/modules/exploits/windows/smb/eternalblue.rb",
            "references": [{"type": "CVE", "ref": "2017-0144"}],
        },
        # same CVE referenced from a second module file — earliest ts must win
        "auxiliary/scanner/log4shell_scan": {
            "path": "modules/auxiliary/scanner/http/log4shell_scanner.rb",
            "references": ["CVE-2021-44228"],
        },
    }
    monkeypatch.setattr(gitmine, "file_at_head", lambda repo, path: json.dumps(manifest))

    hits = {
        ("CVE-2021-44228", "modules/exploits/multi/http/log4shell.rb"): (1_700_000_000, "sha_late"),
        ("CVE-2021-44228", "modules/auxiliary/scanner/http/log4shell_scanner.rb"): (1_600_000_000, "sha_early"),
        ("CVE-2017-0144", "modules/exploits/windows/smb/eternalblue.rb"): (1_500_000_000, "sha_eb"),
    }
    monkeypatch.setattr(
        gitmine,
        "earliest_introduction",
        lambda repo, cve_id, path: hits.get((cve_id, path)),
    )

    frame = MetasploitConnector().fetch(repo="anything", skip_clone=True)

    assert list(frame.columns) == [
        "cve_id",
        "metasploit_first_seen",
        "metasploit_commit_sha",
        "metasploit_commit_path",
    ]
    assert str(frame["metasploit_first_seen"].dt.tz) == "UTC"
    # sorted ascending by first_seen: eternalblue (1.5e9) before log4shell (1.6e9)
    assert list(frame["cve_id"]) == ["CVE-2017-0144", "CVE-2021-44228"]

    log4j = frame[frame["cve_id"] == "CVE-2021-44228"].iloc[0]
    assert log4j["metasploit_commit_sha"] == "sha_early"
    assert log4j["metasploit_commit_path"] == "modules/auxiliary/scanner/http/log4shell_scanner.rb"
    assert log4j["metasploit_first_seen"] == gitmine.to_utc(1_600_000_000)


def test_metasploit_connector_empty_manifest_keeps_columns(monkeypatch):
    monkeypatch.setattr(gitmine, "file_at_head", lambda repo, path: json.dumps({}))
    frame = MetasploitConnector().fetch(repo="anything", skip_clone=True)
    assert list(frame.columns) == [
        "cve_id",
        "metasploit_first_seen",
        "metasploit_commit_sha",
        "metasploit_commit_path",
    ]
    assert frame.empty


def test_metasploit_connector_missing_manifest_raises(monkeypatch):
    monkeypatch.setattr(gitmine, "file_at_head", lambda repo, path: None)
    try:
        MetasploitConnector().fetch(repo="anything", skip_clone=True)
    except RuntimeError:
        return
    raise AssertionError("expected RuntimeError when manifest is missing")
