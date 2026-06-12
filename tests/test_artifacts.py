import hashlib
import json

from temporal_exploit.artifacts import artifact_hashes, write_manifest


def test_write_manifest_writes_sorted_json(tmp_path):
    path = tmp_path / "manifest.json"
    write_manifest(path, {"snapshot_date": "2026-03-14", "labels_rows": 2})
    loaded = json.loads(path.read_text())
    assert loaded["snapshot_date"] == "2026-03-14"
    assert loaded["labels_rows"] == 2
    assert "created_utc" in loaded


def test_artifact_hashes_covers_data_files_only(tmp_path):
    (tmp_path / "a.parquet").write_bytes(b"hello")
    (tmp_path / "b.csv").write_text("x,y\n1,2\n")
    (tmp_path / "manifest.json").write_text("{}")
    hashes = artifact_hashes(tmp_path)
    assert set(hashes) == {"a.parquet", "b.csv"}
    assert hashes["a.parquet"] == hashlib.sha256(b"hello").hexdigest()
