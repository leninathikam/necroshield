import importlib.util
import sys
from pathlib import Path

import pytest

from necroshield.runner import run_pair
from necroshield.scenarios import DOCUMENT_INJECTION

VERIFIER_PATH = Path(__file__).resolve().parents[2] / "scripts" / "verify_evidence.py"


@pytest.fixture
def pair():
    return run_pair(DOCUMENT_INJECTION)


@pytest.fixture(scope="session")
def verifier():
    spec = importlib.util.spec_from_file_location("verify_evidence", VERIFIER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["verify_evidence"] = module
    spec.loader.exec_module(module)
    return module
