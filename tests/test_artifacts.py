import json

from temporal_exploit.artifacts import write_manifest


def test_write_manifest_writes_sorted_json(tmp_path):
    path = tmp_path / "manifest.json"
    write_manifest(path, {"snapshot_date": "2026-03-14", "labels_rows": 2})
    loaded = json.loads(path.read_text())
    assert loaded["snapshot_date"] == "2026-03-14"
    assert loaded["labels_rows"] == 2
    assert "created_utc" in loaded
