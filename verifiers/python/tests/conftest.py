from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
VECTORS = REPO_ROOT / "docs" / "test-vectors"

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def load_vector_file(name: str) -> Any:
    with open(VECTORS / name, "r", encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture(scope="session")
def vectors_dir() -> Path:
    return VECTORS
