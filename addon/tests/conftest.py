import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # the addon folder, so tests can import orch_apps_addon

from orch.testing.pytest_plugin import orch_user_dir, orch_workspace  # noqa: E402,F401

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _isolated_user_dir(orch_user_dir):
    """Every test gets a temp orch config dir, so nothing reads or writes the real ~/.config/orch."""
    return orch_user_dir
