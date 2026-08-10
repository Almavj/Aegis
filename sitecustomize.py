import importlib
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _register_alias_package(module_name: str, package_dir: str | None = None) -> None:
    real_module = importlib.import_module(module_name)
    alias_module = types.ModuleType(f"aegis.{module_name}")
    alias_module.__file__ = getattr(real_module, "__file__", str(ROOT / module_name / "__init__.py"))
    alias_module.__package__ = f"aegis.{module_name}"
    alias_module.__path__ = [str(ROOT / module_name)] if package_dir is None else [package_dir]
    alias_module.__dict__.update(real_module.__dict__)
    sys.modules[f"aegis.{module_name}"] = alias_module


# Expose the project root as an aegis package so imports like `from aegis.core...` work.
aegis_pkg = types.ModuleType("aegis")
aegis_pkg.__path__ = [str(ROOT)]
aegis_pkg.__package__ = "aegis"
sys.modules["aegis"] = aegis_pkg

for module_name in ("core", "modules", "ui", "utils"):
    try:
        importlib.import_module(module_name)
    except Exception:
        continue
    package_dir = str(ROOT / module_name)
    _register_alias_package(module_name, package_dir)
