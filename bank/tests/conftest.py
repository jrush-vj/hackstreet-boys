import os
import tempfile

import pytest

# must be set before bank.app.db is imported: it reads BANK_DB_PATH at import time
os.environ["BANK_DB_PATH"] = os.path.join(tempfile.mkdtemp(), "bank-test.db")

from fastapi.testclient import TestClient  # noqa: E402

from bank.app.main import app  # noqa: E402


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:  # runs startup → seeds the throwaway DB
        yield c
