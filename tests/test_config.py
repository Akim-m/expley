from pathlib import Path

from temporal_exploit.config import ProjectPaths


def test_project_paths_resolve_dataset_root(tmp_path: Path) -> None:
    paths = ProjectPaths(project_root=tmp_path)

    assert paths.dataset_root == tmp_path / "dataset_extraction-20260608T210903Z-3-002" / "dataset_extraction"
    assert paths.handover_out == paths.dataset_root / "out"
    assert paths.artifacts == tmp_path / "artifacts"
