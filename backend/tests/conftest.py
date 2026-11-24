import pytest

from necroshield.catalog import DOCUMENT_INJECTION
from necroshield.runner import run_pair
from necroshield.verification import DEFAULT_PATH as VERIFIER_PATH, verifier as load_verifier


@pytest.fixture
def pair():
    return run_pair(DOCUMENT_INJECTION)


@pytest.fixture(scope="session")
def verifier():
    return load_verifier()


__all__ = ["VERIFIER_PATH"]
