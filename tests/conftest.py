import os
import sys
import tempfile
from pathlib import Path

# Point the app at a throwaway database before any app module is imported.
_tmp = tempfile.mkdtemp(prefix="pager-test-")
os.environ["PAGER_DB"] = str(Path(_tmp) / "test.db")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
