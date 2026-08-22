from pathlib import Path

from hatchling.builders.sdist import SdistBuilder

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def sdist_paths() -> set[str]:
    builder = SdistBuilder(str(PROJECT_ROOT))
    return {
        included.distribution_path.replace("\\", "/")
        for included in builder.recurse_included_files()
    }


def test_sdist_ships_the_importable_package():
    paths = sdist_paths()

    assert "src/ttlock_ble/__init__.py" in paths
    assert "src/ttlock_ble/py.typed" in paths
    assert "README.md" in paths
    assert "LICENSE" in paths


def test_sdist_omits_development_assets():
    paths = sdist_paths()

    assert not [path for path in paths if path.startswith("tests/")]
    assert not [path for path in paths if path.startswith(".github/")]
