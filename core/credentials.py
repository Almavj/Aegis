from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from alma.core.scanner import ServiceDiscovery


@dataclass
class Credential:
    username: str
    secret: str
    secret_type: str          # password | hash | key | ticket
    source_host: str
    source_session: str
    confidence: float         # 0.0 - 1.0
    extra: dict[str, Any] = field(default_factory=dict)


class CredentialCache:
    _SERVICE_PORT_MAP: dict[str, int] = {
        "ssh": 22, "smb": 445, "winrm": 5985, "rdp": 3389,
        "mssql": 1433, "mysql": 3306, "postgresql": 5432,
        "ftp": 21, "telnet": 23,
    }

    def __init__(self) -> None:
        self._by_host: dict[str, list[Credential]] = {}
        self._all: list[Credential] = []

    def store(self, cred: Credential) -> None:
        self._by_host.setdefault(cred.source_host, []).append(cred)
        self._all.append(cred)

    def for_host(self, host: str) -> list[Credential]:
        return list(self._by_host.get(host, []))

    def has_credential_for(self, host: str, service: str | None = None) -> bool:
        creds = self._by_host.get(host, [])
        if not creds:
            return False
        if service is None:
            return True
        for c in creds:
            if c.secret_type in ("password", "hash", "key"):
                return True
        return False

    def matches_service(self, host: str, service: str, port: int) -> list[Credential]:
        creds = self._by_host.get(host, [])
        if not creds:
            return []
        expected_port = self._SERVICE_PORT_MAP.get(service)
        if expected_port and port != expected_port:
            return []
        return creds

    def all(self) -> list[Credential]:
        return list(self._all)

    def merge(self, other: CredentialCache) -> None:
        for cred in other._all:
            self.store(cred)

    def lateral_move(self, source_host: str, discoveries: list[ServiceDiscovery]) -> list[tuple[Credential, str, int, str]]:
        """Try harvested credentials against other hosts with matching services.

        Returns list of (credential, target_host, target_port, service) tuples
        where a credential from source_host might work on another host.
        """
        source_creds = self._by_host.get(source_host, [])
        if not source_creds:
            return []

        attempts: list[tuple[Credential, str, int, str]] = []
        for cred in source_creds:
            for discovery in discoveries:
                if discovery.host == source_host:
                    continue
                for port in discovery.ports:
                    if not port.service:
                        continue
                    expected_port = self._SERVICE_PORT_MAP.get(port.service)
                    if expected_port and port.port == expected_port:
                        attempts.append((cred, discovery.host, port.port, port.service))
        return attempts
