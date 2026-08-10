from __future__ import annotations

import asyncio
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from aegis.core.vulnerability import VulnerabilityFinding


class ReportFormat(Enum):
    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    MARKDOWN = "markdown"


@dataclass
class Finding:
    title: str
    severity: str
    target: str
    port: int | None
    service: str | None
    description: str
    remediation: str | None = None
    cvss_score: float | None = None
    cve_id: str | None = None
    evidence: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def from_vuln_finding(cls, vf: VulnerabilityFinding) -> Finding:
        if vf.cve:
            return cls(
                title=vf.cve.cve_id,
                severity=_cvss_to_label(vf.cve.cvss_score),
                target=vf.target,
                port=vf.port,
                service=vf.service,
                description=vf.cve.description,
                remediation=f"See {vf.cve.reference_urls[0]}" if vf.cve.reference_urls else None,
                cvss_score=vf.cve.cvss_score,
                cve_id=vf.cve.cve_id,
            )
        if vf.misconfiguration:
            return cls(
                title=vf.misconfiguration.title,
                severity=vf.misconfiguration.severity,
                target=vf.target,
                port=vf.port,
                service=vf.service,
                description=f"Misconfiguration: {vf.misconfiguration.category}",
                evidence=vf.evidence,
            )
        return cls(
            title="Unknown finding",
            severity="info",
            target=vf.target,
            port=vf.port,
            service=vf.service,
            description="No CVE or misconfiguration data.",
        )


def _cvss_to_label(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _write_file(path: str, content: str) -> None:
    try:
        with open(path, "w") as f:
            f.write(content)
    except PermissionError:
        import tempfile
        fd, fallback = tempfile.mkstemp(suffix=".md", prefix="aegis_report_", text=True)
        with os.fdopen(fd, "w") as f:
            f.write(content)
        print(f"Warning: could not write to {path}, wrote to {fallback} instead")


class ReportBuilder(ABC):
    """
    Aggregates findings from all phases and produces a final report.

    Multiple output formats are supported.  The orchestrator injects
    session metadata, scan summaries, and exploited-host details.
    """

    def __init__(self, title: str = "Aegis Pentest Report") -> None:
        self._title = title
        self._findings: list[Finding] = []
        self._scan_summary: dict[str, Any] = {}
        self._exploit_log: list[dict[str, Any]] = []

    def add_finding(self, finding: Finding) -> None:
        self._findings.append(finding)

    def add_findings(self, findings: list[Finding]) -> None:
        self._findings.extend(findings)

    def set_scan_summary(self, summary: dict[str, Any]) -> None:
        self._scan_summary = summary

    def log_exploit_attempt(self, entry: dict[str, Any]) -> None:
        self._exploit_log.append(entry)

    @abstractmethod
    async def render(self, fmt: ReportFormat = ReportFormat.MARKDOWN) -> str:
        """Render the full report and return it as a string."""

    @abstractmethod
    async def export(self, fmt: ReportFormat, path: str) -> None:
        """Render and write to *path*."""


class JsonReportBuilder(ReportBuilder):
    async def render(self, fmt: ReportFormat = ReportFormat.JSON) -> str:
        import json
        return json.dumps(self._serialize(), indent=2)

    async def export(self, fmt: ReportFormat, path: str) -> None:
        content = await self.render(fmt)
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _write_file, path, content)

    def _serialize(self) -> dict[str, Any]:
        return {
            "title": self._title,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_summary": self._scan_summary,
            "findings": [f.__dict__ for f in self._findings],
            "exploit_log": self._exploit_log,
        }


class MarkdownReportBuilder(ReportBuilder):
    async def render(self, fmt: ReportFormat = ReportFormat.MARKDOWN) -> str:
        lines = [f"# {self._title}\n", f"_Generated: {datetime.now(timezone.utc).isoformat()}_\n"]

        if self._scan_summary:
            lines.append("## Scan Summary\n")
            for k, v in self._scan_summary.items():
                lines.append(f"- **{k}:** {v}")
            lines.append("")

        lines.append(f"## Findings ({len(self._findings)})\n")
        for f in self._findings:
            lines.append(f"### {f.severity.upper()}: {f.title}")
            lines.append(f"- **Target:** {f.target}:{f.port}" if f.port else "")
            lines.append(f"- **CVSS:** {f.cvss_score}" if f.cvss_score else "")
            lines.append(f"- **CVE:** {f.cve_id}" if f.cve_id else "")
            lines.append(f"- **Description:** {f.description}")
            lines.append("")

        return "\n".join(lines)

    async def export(self, fmt: ReportFormat, path: str) -> None:
        content = await self.render()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _write_file, path, content)
