from __future__ import annotations

import asyncio
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Protocol

from alma.core.session import Session
from alma.utils.errors import ScanError
from alma.utils.logger import AlmaLogger


@dataclass(frozen=True)
class PortScanResult:
    host: str
    port: int
    protocol: str
    state: str
    service: str | None = None
    banner: str | None = None
    extra: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ServiceDiscovery:
    host: str
    hostname: str | None = None
    os_hint: str | None = None
    ports: list[PortScanResult] = field(default_factory=list)
    tags: set[str] = field(default_factory=set)


@dataclass
class ScanProfile:
    max_parallel: int = 10
    inter_batch_delay: float = 1.0
    randomize_port_order: bool = False
    inter_host_delay: float = 0.0


SCAN_PROFILE_STEALTH = ScanProfile(3, 5.0, True, 2.0)
SCAN_PROFILE_BALANCED = ScanProfile(10, 1.0, False, 0.0)
SCAN_PROFILE_AGGRESSIVE = ScanProfile(30, 0.0, True, 0.0)


class ScanProgressCallback(Protocol):
    def __call__(self, completed: int, total: int, current: PortScanResult | None = None) -> None:
        ...


class Scanner(ABC):
    def __init__(self, rate_limit: float = 100.0, timeout: float = 5.0) -> None:
        self._rate_limit = rate_limit
        self._timeout = timeout
        self._progress: ScanProgressCallback | None = None
        self._log = AlmaLogger(self.__class__.__name__).get()

    def set_progress_callback(self, cb: ScanProgressCallback | None) -> None:
        self._progress = cb

    async def discover(
        self,
        targets: list[str],
        ports: list[int] | None = None,
        fast_mode: bool = False,
    ) -> list[ServiceDiscovery]:
        self._on_scan_start(targets)
        try:
            results = await self._scan(targets, ports or self._default_ports(), fast_mode)
        except Exception as exc:
            self._on_scan_failure(exc)
            raise ScanError(f"Scan failed for targets={targets}") from exc
        else:
            self._on_scan_complete(results)
        return results

    @abstractmethod
    async def _scan(
        self, targets: list[str], ports: list[int], fast_mode: bool
    ) -> list[ServiceDiscovery]:
        ...

    @abstractmethod
    def _default_ports(self) -> list[int]:
        ...

    def _on_scan_start(self, targets: list[str]) -> None:
        self._log.info("Starting scan — targets=%s", targets)

    def _on_scan_failure(self, exc: Exception) -> None:
        self._log.error("Scan failed: %s", exc)

    def _on_scan_complete(self, results: list[ServiceDiscovery]) -> None:
        self._log.info("Scan complete — %d hosts found", len(results))

    async def _report(self, done: int, total: int, result: PortScanResult | None = None) -> None:
        if self._progress:
            self._progress(done, total, result)


class NmapScanner(Scanner):
    async def _scan(
        self, targets: list[str], ports: list[int], fast_mode: bool
    ) -> list[ServiceDiscovery]:
        cmd = ["nmap", "-oX", "-", "-A", "--open"]
        if fast_mode:
            cmd.append("-T4")
        else:
            cmd.append("-T3")
        if ports:
            cmd.extend(["-p", ",".join(str(p) for p in ports)])
        cmd.extend(targets)
        self._log.debug("Running: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=1800.0)
        except asyncio.TimeoutError:
            proc.kill()
            err = b""
            if proc.stderr:
                try:
                    err = await asyncio.wait_for(proc.stderr.read(), timeout=5.0)
                except (asyncio.TimeoutError, OSError):
                    pass
            raise ScanError(f"nmap timed out: {err.decode(errors='replace')[:200]}") from None
        if proc.returncode not in (0, 1):
            err = stderr.decode(errors="replace").strip()[:200]
            raise ScanError(f"nmap exited code {proc.returncode}: {err}")
        return self._parse_nmap_xml(stdout.decode(errors="replace"))

    def _default_ports(self) -> list[int]:
        return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
                8080, 8443, 27017]

    def _parse_nmap_xml(self, xml: str) -> list[ServiceDiscovery]:
        discoveries: list[ServiceDiscovery] = []
        try:
            root = ET.fromstring(xml)
        except ET.ParseError as e:
            self._log.error("Failed to parse nmap XML: %s", e)
            return discoveries

        for host_elem in root.findall("host"):
            status = host_elem.find("status")
            if status is None or status.get("state") != "up":
                continue
            addr = host_elem.find("address")
            host_ip = addr.get("addr") if addr is not None else "unknown"
            hostnames_elem = host_elem.find("hostnames")
            hostname = None
            if hostnames_elem is not None:
                hn = hostnames_elem.find("hostname")
                if hn is not None:
                    hostname = hn.get("name")
            os_elem = host_elem.find("os")
            os_hint = None
            if os_elem is not None:
                osm = os_elem.find("osmatch")
                if osm is not None:
                    os_hint = osm.get("name")
            ports_result: list[PortScanResult] = []
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    proto = port_elem.get("protocol", "tcp")
                    port_num = int(port_elem.get("portid", "0"))
                    state_elem = port_elem.find("state")
                    state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
                    service = None
                    banner = None
                    service_elem = port_elem.find("service")
                    if service_elem is not None:
                        service = service_elem.get("name")
                        banner = service_elem.get("product", "")
                        version = service_elem.get("version", "")
                        if version:
                            banner = f"{banner} {version}".strip()
                    ports_result.append(PortScanResult(
                        host=host_ip, port=port_num, protocol=proto, state=state,
                        service=service, banner=banner or None,
                    ))
            discoveries.append(ServiceDiscovery(host=host_ip, hostname=hostname, os_hint=os_hint, ports=ports_result))
        return discoveries


class MasscanScanner(Scanner):
    async def _scan(
        self, targets: list[str], ports: list[int], fast_mode: bool
    ) -> list[ServiceDiscovery]:
        port_str = ",".join(str(p) for p in ports)
        cmd = ["masscan", *targets, "-p", port_str, "--rate", str(int(self._rate_limit)), "-oJ", "-", "--open-only"]
        if fast_mode:
            cmd.extend(["--wait", "10"])
        self._log.debug("Running: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self._timeout * 2)
        if proc.returncode not in (0, 1):
            err = stderr.decode(errors="replace").strip()
            raise ScanError(f"masscan exited code {proc.returncode}: {err}")
        return self._parse_masscan_json(stdout.decode(errors="replace"))

    def _default_ports(self) -> list[int]:
        return list(range(1, 65536))

    def _parse_masscan_json(self, data: str) -> list[ServiceDiscovery]:
        import json
        discoveries: dict[str, ServiceDiscovery] = {}
        try:
            for line in data.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                record = json.loads(line)
                ip = record.get("ip", "unknown")
                port = int(record.get("port", 0))
                proto = record.get("protocol", "tcp")
                state = record.get("status", "unknown")
                svc = record.get("service", {})
                service = svc.get("name") if isinstance(svc, dict) else None
                result = PortScanResult(host=ip, port=port, protocol=proto, state=state, service=service)
                if ip not in discoveries:
                    discoveries[ip] = ServiceDiscovery(host=ip)
                discoveries[ip].ports.append(result)
        except (json.JSONDecodeError, ValueError, TypeError) as e:
            self._log.error("Failed to parse masscan JSON: %s", e)
        return list(discoveries.values())


class ConnectScanner(Scanner):
    _SERVICE_GUESS: dict[int, str] = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
        143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
        1433: "ms-sql-s", 1521: "oracle-db", 2049: "nfs", 3306: "mysql",
        3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc", 6379: "redis",
        8080: "http-proxy", 8443: "https-alt", 27017: "mongod",
    }

    def __init__(self, rate_limit: float = 100.0, timeout: float = 5.0,
                 profile: ScanProfile = SCAN_PROFILE_BALANCED) -> None:
        super().__init__(rate_limit=rate_limit, timeout=timeout)
        self._profile = profile

    async def _scan(
        self, targets: list[str], ports: list[int], fast_mode: bool
    ) -> list[ServiceDiscovery]:
        discoveries: dict[str, ServiceDiscovery] = {}

        import random
        work_ports = list(ports)
        if self._profile.randomize_port_order:
            random.shuffle(work_ports)

        total = len(targets) * len(work_ports)
        done = 0
        sem = asyncio.Semaphore(int(self._rate_limit) if self._rate_limit > 0 else 100)

        async def probe(host: str, port: int) -> PortScanResult | None:
            nonlocal done
            async with sem:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=self._timeout,
                    )
                    state = "open"
                    banner = None
                    try:
                        banner_bytes = await asyncio.wait_for(reader.read(256), timeout=2.0)
                        if banner_bytes:
                            banner = banner_bytes.decode(errors="replace").strip()[:128]
                    except (asyncio.TimeoutError, ConnectionError):
                        pass
                    writer.close()
                except (OSError, asyncio.TimeoutError):
                    return None
                finally:
                    done += 1
                    if done % 10 == 0 or done == total:
                        await self._report(done, total)
                service = self._SERVICE_GUESS.get(port)
                return PortScanResult(host=host, port=port, protocol="tcp", state=state, service=service, banner=banner)

        for idx, target in enumerate(targets):
            tasks = [probe(target, port) for port in work_ports]
            results = await asyncio.gather(*tasks)
            host_results = [r for r in results if r is not None]
            if host_results:
                discoveries[target] = ServiceDiscovery(host=target, ports=host_results)
            if self._profile.inter_host_delay and idx < len(targets) - 1:
                await asyncio.sleep(self._profile.inter_host_delay)
        return list(discoveries.values())

    def _default_ports(self) -> list[int]:
        return list(self._SERVICE_GUESS.keys())


class SessionScanner(Scanner):
    def __init__(self, session: Session, profile: ScanProfile = SCAN_PROFILE_BALANCED, timeout: float = 5.0) -> None:
        super().__init__(rate_limit=profile.max_parallel, timeout=timeout)
        self._session = session
        self._profile = profile
        self._service_map = ConnectScanner._SERVICE_GUESS

    async def _scan(self, targets: list[str], ports: list[int], fast_mode: bool) -> list[ServiceDiscovery]:
        discoveries: list[ServiceDiscovery] = []
        host_idx = 0

        for target in targets:
            base = ".".join(target.split(".")[:3])

            import random
            work_ports = list(ports)
            if self._profile.randomize_port_order:
                random.shuffle(work_ports)

            for port in work_ports:
                script = (
                    f'bash -c \'f=/tmp/.s.$$; '
                    f'for ip in {base}.{{1..254}}; do '
                    f'(timeout 1 bash -c "echo >/dev/tcp/$ip/{port}" 2>/dev/null && echo "$ip:{port}" >> $f) & '
                    f'if (( $(jobs -r | wc -l) >= {self._profile.max_parallel} )); then wait -n; fi; '
                    f'done; wait; cat $f; rm -f $f\''
                )
                result = await self._session.send(script, timeout=60.0)
                for line in result.strip().splitlines():
                    line = line.strip()
                    if ":" not in line:
                        continue
                    host, _ = line.split(":", 1)
                    service = self._service_map.get(port)
                    if host not in {d.host for d in discoveries}:
                        discoveries.append(ServiceDiscovery(host=host, tags={"via-pivot"}))
                    for d in discoveries:
                        if d.host == host:
                            d.ports.append(PortScanResult(
                                host=host, port=port, protocol="tcp", state="open", service=service,
                            ))
                            break
                host_idx += 1
                await self._report(host_idx, len(targets))

                if self._profile.inter_batch_delay:
                    await asyncio.sleep(self._profile.inter_batch_delay)

        return discoveries

    def _default_ports(self) -> list[int]:
        return list(self._service_map.keys())
