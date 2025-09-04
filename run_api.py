"""Helper launcher to run the FastAPI app without worrying about PYTHONPATH.

Usage (from project root):
  python run_api.py
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from spcp.api.main import app  # noqa: E402

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)
