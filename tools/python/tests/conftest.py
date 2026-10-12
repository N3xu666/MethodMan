"""pytest configuration for tools/python/tests.

Adds the parent directory (tools/python/) to sys.path so tests can import
Session_Report directly without installing the package.
"""

import sys
from pathlib import Path

TOOLS_PYTHON = Path(__file__).resolve().parent.parent
if str(TOOLS_PYTHON) not in sys.path:
    sys.path.insert(0, str(TOOLS_PYTHON))