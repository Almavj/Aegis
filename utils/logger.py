import logging
import sys
from pathlib import Path


class AegisLogger:
    """Centralised logging with structured output and per-module levels."""

    def __init__(self, name: str, level: int = logging.DEBUG, log_dir: str | None = None) -> None:
        self._logger = logging.getLogger(f"aegis.{name}")
        self._logger.setLevel(level)

        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                    datefmt="%Y-%m-%dT%H:%M:%S",
                )
            )
            self._logger.addHandler(handler)

        if log_dir:
            path = Path(log_dir)
            path.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(path / f"{name}.log")
            fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
            self._logger.addHandler(fh)

    def get(self) -> logging.Logger:
        return self._logger
