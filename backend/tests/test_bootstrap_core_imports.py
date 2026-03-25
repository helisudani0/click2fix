from __future__ import annotations

import os
import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ.setdefault(
    "JWT_SECRET",
    "bootstrap-import-test-secret-0123456789abcdef0123456789abcdef",
)
os.environ.setdefault("SECURITY_ENFORCE_STRONG_JWT", "false")


def test_bootstrap_support_modules_import():
    import core.alert_stream  # noqa: F401
    import core.distributed_leases  # noqa: F401
    import core.ingest_gateway_client  # noqa: F401
    import core.secrets  # noqa: F401
    import core.security_monitoring  # noqa: F401
