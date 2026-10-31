import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Simulated TPM keys for the tests live in a throw-away folder.
os.environ["PIM_SIMULATED_TPM_DIR"] = tempfile.mkdtemp(prefix="pim_tpm_")
os.environ["PIM_ADMIN_TOKEN"] = "test-admin-token"
sys.path.insert(0, str(ROOT / "SERVER"))
sys.path.insert(0, str(ROOT / "CLIENT"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import settings  # noqa: E402
from app import create_app  # noqa: E402
from database import Database  # noqa: E402
from simulated_pc import PcWorld  # noqa: E402


@pytest.fixture()
def world():
    """A fresh server with an in-memory database and helpers to create simulated PCs."""
    settings.ALLOW_SIMULATED_TPM = True
    database = Database(":memory:")
    application = create_app(database, show_otp=True)
    with TestClient(application) as client:
        yield PcWorld(client, database, application)
    database.close()
