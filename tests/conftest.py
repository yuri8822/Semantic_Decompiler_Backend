import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FIXTURE = ROOT / "tests" / "fixtures" / "chess_subset.json"


@pytest.fixture(scope="session")
def chess_ir():
    from ghidra_io.ir import load_ir
    return load_ir(FIXTURE)


@pytest.fixture
def kb(tmp_path):
    from knowledge.store import KnowledgeBase
    return KnowledgeBase.open(tmp_path / "kb")
