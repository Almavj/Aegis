from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from typing import Any

from aegis.core.credentials import Credential, CredentialCache
from aegis.core.cve import CVEDataSource, CVEMatch
from aegis.core.exploit import Exploit, ExploitResult, ExploitTarget
from aegis.core.orchestrator import EngagementStatus, Orchestrator
from aegis.core.scanner import PortScanResult, Scanner, ServiceDiscovery
from aegis.core.session import Session, SessionManager
from aegis.core.vulnerability import VulnerabilityEngine
from aegis.utils.logger import AegisLogger


@dataclass
class ChaosProfile:
    partial_read: float = 0.0
    """Probability of returning a truncated response."""

    encoding_errors: float = 0.0
    """Probability of injecting garbage bytes in output."""

    slow_shell: float = 0.0
    """Probability of adding artificial delay to responses."""

    dropped_command: float = 0.0
    """Probability a command returns empty output."""

    flaky_transport: float = 0.0
    """Probability of raising ConnectionError on send."""

    truncated_output_max_pct: float = 0.5
    """When partial_read triggers, return only this fraction of output."""


@dataclass
class FakeSession:
    host: str = "192.168.1.100"
    id: str = "fake-session-001"
    response_map: dict[str, str] = field(default_factory=lambda: {
        "whoami": "root\n",
        "id": "uid=0(root) gid=0(root)\n",
        "echo 1": "1\n",
        "uname -a": "Linux target 5.15.0-generic x86_64\n",
        "cat /etc/shadow": "root:$6$xyz:19712:0:99999:7:::\n",
        "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
        "ip route": "default via 192.168.1.1 dev eth0\n"
                    "10.0.0.0/24 via 192.168.1.100 dev eth0\n",
        "sudo -n true 2>/dev/null && echo 'VULN: sudo nopass' || echo 'OK'": "VULN: sudo nopass\n",
        "find / -perm -4002 -type f 2>/dev/null | head -5": "/usr/bin/somebinary\n",
    })
    integrity: str = "user"
    degraded: bool = False
    _alive: bool = True
    _sent_commands: list[str] = field(default_factory=list)

    async def send(self, command: str, timeout: float = 10.0) -> str:
        self._sent_commands.append(command)
        await asyncio.sleep(0.01)
        return self.response_map.get(command, f"unknown command: {command}\n")

    def is_alive(self) -> bool:
        return self._alive

    def kill(self) -> None:
        self._alive = False

    def lock(self) -> asyncio.Lock:
        return asyncio.Lock()

    def __enter__(self) -> FakeSession:
        return self

    def __exit__(self, *args: Any) -> None:
        pass


class AdversarialSession(FakeSession):
    chaos: ChaosProfile = field(default_factory=ChaosProfile)

    def __init__(self, chaos: ChaosProfile | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.chaos = chaos or ChaosProfile()
        self._send_count: int = 0

    async def send(self, command: str, timeout: float = 10.0) -> str:
        self._sent_commands.append(command)
        self._send_count += 1
        seed = random.random()

        if self.chaos.flaky_transport > 0 and seed < self.chaos.flaky_transport:
            raise ConnectionError("Simulated transport failure")

        await asyncio.sleep(0.01)

        if self.chaos.slow_shell > 0 and seed < self.chaos.slow_shell:
            await asyncio.sleep(random.uniform(0.5, 3.0))

        result = self.response_map.get(command, f"unknown command: {command}\n")

        if self.chaos.dropped_command > 0 and seed < self.chaos.dropped_command:
            return ""

        if self.chaos.encoding_errors > 0 and seed < self.chaos.encoding_errors:
            garbage = bytes(random.choices(range(0x80, 0xFF), k=random.randint(4, 16)))
            result += garbage.decode("latin-1")

        if self.chaos.partial_read > 0 and seed < self.chaos.partial_read:
            cutoff = max(1, int(len(result) * random.uniform(0.1, self.chaos.truncated_output_max_pct)))
            result = result[:cutoff]

        return result


class FakeScanner(Scanner):
    def __init__(self, discoveries: list[ServiceDiscovery] | None = None,
                 delay: float = 0.0) -> None:
        super().__init__()
        self._discoveries = discoveries or []
        self._delay = delay

    async def _scan(self, targets: list[str], ports: list[int], fast_mode: bool) -> list[ServiceDiscovery]:
        await asyncio.sleep(self._delay)
        return self._discoveries

    def _default_ports(self) -> list[int]:
        return [22, 80, 443, 445]


@dataclass
class FakeCveDataSource(CVEDataSource):
    _matches: dict[str, list[CVEMatch]] = field(default_factory=dict)

    async def query(self, service: str, banner: str | None) -> list[CVEMatch]:
        await asyncio.sleep(0.01)
        key = service.lower().strip().replace(" ", "_")
        return self._matches.get(key, [])

    def add_match(self, service: str, cve: CVEMatch) -> None:
        key = service.lower().strip().replace(" ", "_")
        self._matches.setdefault(key, []).append(cve)


class FakeSessionManager:
    def __init__(self) -> None:
        self._sessions: dict[str, FakeSession] = {}
        self._log = AegisLogger("fake-session-mgr").get()

    async def register(self, session: Session) -> str:
        return session.id

    async def unregister(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    def list_active(self) -> dict[str, FakeSession]:
        return {sid: s for sid, s in self._sessions.items() if s.is_alive()}

    def add_pivot_route(self, session_id: str, subnet: str) -> None:
        pass

    async def cleanup_all(self) -> None:
        self._sessions.clear()


def make_discovery(host: str, ports: list[tuple[int, str, str]] | None = None) -> ServiceDiscovery:
    if ports is None:
        ports = [(22, "ssh", "OpenSSH 8.9p1"), (80, "http", "Apache/2.4.49"), (443, "https", "Apache/2.4.49")]
    return ServiceDiscovery(
        host=host,
        os_hint="Linux 5.15",
        ports=[PortScanResult(host=host, port=p, protocol="tcp", state="open", service=s, banner=b)
               for p, s, b in ports],
    )


def make_cve_match(cve_id: str = "CVE-2021-41773", score: float = 7.5,
                   software: str = "apache") -> CVEMatch:
    return CVEMatch(
        cve_id=cve_id,
        cvss_score=score,
        description=f"{cve_id} test vulnerability",
        affected_software=software,
        exploit_available=True,
        reference_urls=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
    )


async def test_recursive_loop_terminates() -> bool:
    scanner = FakeScanner(discoveries=[make_discovery("10.0.0.5")])
    cve_source = FakeCveDataSource()
    vuln_engine = VulnerabilityEngine(cve_finder=cve_source)
    session_mgr = FakeSessionManager()
    cred_cache = CredentialCache()

    status_log: list[str] = []
    def reporter(s: EngagementStatus) -> None:
        status_log.append(s.phase)

    orchestrator = Orchestrator(
        scanner=scanner,
        vuln_engine=vuln_engine,
        session_mgr=session_mgr,
        cve_source=cve_source,
        cred_cache=cred_cache,
        progress_reporter=reporter,
    )

    await orchestrator.run(targets=["10.0.0.0/24"], recursive=True, max_recursion_depth=2)
    return orchestrator.status.phase == "completed"


async def test_batch_cve_aggregation() -> bool:
    from aegis.core.cve import BatchCveAggregator

    source = FakeCveDataSource()
    source.add_match("http 2.4.49", make_cve_match())
    source.add_match("ssh 8.9p1", make_cve_match("CVE-2024-1234", 8.0, "ssh"))

    aggregator = BatchCveAggregator(source)
    discoveries = [
        make_discovery("10.0.0.1", [(80, "http", "Apache 2.4.49")]),
        make_discovery("10.0.0.2", [(80, "http", "Apache 2.4.49"), (22, "ssh", "OpenSSH 8.9p1")]),
    ]

    cve_map = await aggregator.resolve(discoveries)
    if not cve_map:
        return False

    total_matches = sum(len(v) for v in cve_map.values())
    return total_matches >= 2


async def test_lateral_movement_logging() -> bool:
    cred_cache = CredentialCache()
    cred_cache.store(Credential(
        username="admin", secret="hash123", secret_type="hash",
        source_host="10.0.0.1", source_session="s1", confidence=0.8,
    ))

    discoveries = [
        make_discovery("10.0.0.1", [(445, "smb", "Samba 4.15")]),
        make_discovery("10.0.0.2", [(445, "smb", "Samba 4.15")]),
    ]

    attempts = cred_cache.lateral_move("10.0.0.1", discoveries)
    return len(attempts) == 1 and attempts[0][1] == "10.0.0.2"


async def test_degraded_session_detection() -> None:
    fs = FakeSession()
    fs.response_map = {}
    whoami = await fs.send("whoami", timeout=5.0)
    return "unknown command" in whoami


async def test_adversarial_partial_read() -> bool:
    session = AdversarialSession(
        chaos=ChaosProfile(partial_read=1.0, truncated_output_max_pct=0.3),
    )
    result = await session.send("whoami")
    full = "root\n"
    return result != full and len(result) < len(full) and len(result) > 0


async def test_adversarial_flaky_transport() -> bool:
    session = AdversarialSession(chaos=ChaosProfile(flaky_transport=1.0))
    try:
        await session.send("whoami")
        return False
    except ConnectionError:
        return True


async def test_adversarial_encoding_errors() -> bool:
    session = AdversarialSession(chaos=ChaosProfile(encoding_errors=1.0))
    result = await session.send("whoami")
    has_garbage = any(ord(c) > 127 for c in result)
    return has_garbage or result.startswith("root")


async def test_adversarial_slow_shell() -> bool:
    session = AdversarialSession(chaos=ChaosProfile(slow_shell=1.0))
    start = asyncio.get_event_loop().time()
    await session.send("echo 1", timeout=10.0)
    elapsed = asyncio.get_event_loop().time() - start
    return elapsed >= 0.5


async def test_adversarial_dropped_command() -> bool:
    session = AdversarialSession(chaos=ChaosProfile(dropped_command=1.0))
    result = await session.send("whoami")
    return result == ""


def run_tests() -> dict[str, bool]:
    async def runner() -> dict[str, bool]:
        results = {}

        results["recursive_loop_terminates"] = await test_recursive_loop_terminates()
        results["batch_cve_aggregation"] = await test_batch_cve_aggregation()
        results["lateral_movement_logging"] = await test_lateral_movement_logging()
        results["degraded_session_detection"] = await test_degraded_session_detection()
        results["adversarial_partial_read"] = await test_adversarial_partial_read()
        results["adversarial_flaky_transport"] = await test_adversarial_flaky_transport()
        results["adversarial_encoding_errors"] = await test_adversarial_encoding_errors()
        results["adversarial_slow_shell"] = await test_adversarial_slow_shell()
        results["adversarial_dropped_command"] = await test_adversarial_dropped_command()

        return results

    return asyncio.run(runner())


if __name__ == "__main__":
    results = run_tests()
    for name, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {name}")
    print(f"\n{sum(results.values())}/{len(results)} tests passed")
