"""Plugin loader — auto-discovers exploit modules from the filesystem.

Any file matching ``exploit_*.py`` under ``modules/exploits/`` is
imported at startup.  The ``Exploit.__init_subclass__`` hook registers
each class automatically — no manual bookkeeping needed.
"""

import importlib
import pkgutil
from pathlib import Path

from alma.utils.logger import AlmaLogger


def discover_modules() -> None:
    log = AlmaLogger("plugin-loader").get()
    exploits_dir = Path(__file__).parent / "exploits"

    if not exploits_dir.is_dir():
        log.warning("Exploit modules directory not found: %s", exploits_dir)
        return

    loaded = 0
    for f in sorted(exploits_dir.iterdir()):
        if not f.name.startswith("exploit_") or not f.name.endswith(".py"):
            continue
        module_name = f"alma.modules.exploits.{f.stem}"
        try:
            importlib.import_module(module_name)
            log.debug("Loaded module: %s", module_name)
            loaded += 1
        except Exception as e:
            log.error("Failed to load %s: %s", module_name, e)

    log.info("Plugin discovery complete — %d exploit modules loaded", loaded)
