import importlib
import unittest


class ImportTests(unittest.TestCase):
    def test_aegis_package_imports(self) -> None:
        module = importlib.import_module("aegis")
        self.assertTrue(module)

    def test_core_scanner_imports(self) -> None:
        module = importlib.import_module("aegis.core.scanner")
        self.assertTrue(module)


if __name__ == "__main__":
    unittest.main()
