from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

__path__ = [str(ROOT)]
__version__ = "0.1.0"
__all__ = []
