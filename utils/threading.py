import asyncio
import contextlib
from collections.abc import Coroutine
from typing import Any


class CancellableTask:
    """Wraps an async task so it can be cancelled cleanly."""

    def __init__(self, coro: Coroutine[Any, Any, Any]) -> None:
        self._task = asyncio.ensure_future(coro)

    def cancel(self) -> None:
        self._task.cancel()

    @property
    def done(self) -> bool:
        return self._task.done()


class TaskPool:
    """Manages a bounded set of concurrent tasks (thread-based for blocking I/O)."""

    def __init__(self, max_workers: int = 10) -> None:
        self._max = max_workers
        self._tasks: list[CancellableTask] = []

    def spawn(self, coro: Coroutine[Any, Any, Any]) -> CancellableTask:
        if len(self._tasks) >= self._max:
            raise RuntimeError(f"TaskPool saturated ({self._max} workers)")
        t = CancellableTask(coro)
        self._tasks.append(t)
        return t

    async def drain(self) -> None:
        results = []
        for t in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                results.append(await t._task)
        self._tasks.clear()
        return results

    @property
    def pending(self) -> int:
        return sum(1 for t in self._tasks if not t.done)

    def cancel_all(self) -> None:
        for t in self._tasks:
            t.cancel()
        self._tasks.clear()
