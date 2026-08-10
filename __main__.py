import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("PYTHONPATH", str(ROOT))

from main import main

if __name__ == "__main__":
    asyncio.run(main())
