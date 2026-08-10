from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aegis.core.scanner import ServiceDiscovery
from aegis.utils.errors import AegisError
from aegis.utils.logger import AegisLogger


@dataclass(frozen=True)
class CVEMatch:
    cve_id: str
    cvss_score: float
    description: str
    affected_software: str
    exploit_available: bool
    reference_urls: list[str] = field(default_factory=list)


class CVEDataSource:
    async def query(self, service: str, banner: str | None) -> list[CVEMatch]:
        raise NotImplementedError


class NullCVEDataSource(CVEDataSource):
    async def query(self, service: str, banner: str | None) -> list[CVEMatch]:
        return []


class NistNvdApi(CVEDataSource):
    BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MIN_INTERVAL = 6.0

    def __init__(self, cache_path: str | None = None, api_key: str | None = None) -> None:
        self._api_key = api_key
        self._cache_path = Path(cache_path) if cache_path else Path("/tmp/aegis_nvd_cache.json")
        self._cache: dict[str, list[dict[str, Any]]] = {}
        self._last_call = 0.0
        self._lock = asyncio.Lock()
        self._log = AegisLogger("nvd-api").get()
        self._load_cache()

    def _load_cache(self) -> None:
        if self._cache_path.exists():
            try:
                raw = self._cache_path.read_text()
                self._cache = json.loads(raw)
                self._log.info("Loaded %d cached CVE queries from %s", len(self._cache), self._cache_path)
            except (json.JSONDecodeError, OSError) as e:
                self._log.warning("Failed to load NVD cache: %s", e)

    def _save_cache(self) -> None:
        try:
            self._cache_path.write_text(json.dumps(self._cache, indent=2))
        except OSError as e:
            self._log.warning("Failed to save NVD cache: %s", e)

    async def query(self, service: str, banner: str | None) -> list[CVEMatch]:
        import aiohttp

        keywords = service.lower().strip()
        if banner:
            version = banner.split()[-1] if banner.split() else ""
            if version and any(c.isdigit() for c in version):
                keywords = f"{keywords} {version}"

        cache_key = keywords.replace(" ", "_")
        async with self._lock:
            if cache_key in self._cache:
                self._log.debug("Cache hit for %s", keywords)
                return [CVEMatch(**e) for e in self._cache[cache_key]]

        elapsed = time.time() - self._last_call
        if elapsed < self.MIN_INTERVAL:
            await asyncio.sleep(self.MIN_INTERVAL - elapsed)

        params: dict[str, str] = {
            "keywordSearch": keywords,
            "keywordExactMatch": "false",
            "resultsPerPage": "20",
        }
        headers = {"User-Agent": "Aegis/1.0"}
        if self._api_key:
            params["apiKey"] = self._api_key

        self._log.debug("Querying NVD: %s", keywords)
        async with aiohttp.ClientSession(headers=headers) as session:
            try:
                async with session.get(self.BASE, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    self._last_call = time.time()
                    if resp.status != 200:
                        self._log.warning("NVD returned %d for %s", resp.status, keywords)
                        return []
                    data = await resp.json()
            except (aiohttp.ClientError, TimeoutError, asyncio.TimeoutError) as e:
                self._log.warning("NVD request failed: %s", e)
                return []

        matches: list[CVEMatch] = []
        raw_entries: list[dict[str, Any]] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

            metrics = cve.get("metrics", {})
            cvss = 0.0
            for metric_group in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                group = metrics.get(metric_group, [])
                if group:
                    cvss = group[0].get("cvssData", {}).get("baseScore", 0.0)
                    break

            refs = [r["url"] for r in cve.get("references", []) if r.get("url")]

            service_lower = service.lower()
            desc_lower = desc.lower()
            match = service_lower in desc_lower
            if banner:
                for word in banner.lower().split():
                    if word in desc_lower:
                        match = True
                        break

            if match:
                m = CVEMatch(
                    cve_id=cve_id,
                    cvss_score=float(cvss),
                    description=desc[:300],
                    affected_software=keywords,
                    exploit_available=False,
                    reference_urls=refs[:5],
                )
                matches.append(m)
                raw_entries.append({
                    "cve_id": cve_id,
                    "cvss_score": float(cvss),
                    "description": desc[:300],
                    "affected_software": keywords,
                    "exploit_available": False,
                    "reference_urls": refs[:5],
                })

        async with self._lock:
            self._cache[cache_key] = raw_entries
        self._save_cache()
        return matches


class BatchCveAggregator:
    """Deduplicates service+banner tuples across all discoveries before querying NVD.

    Turns an O(n) per-host NVD problem into O(1) relative to host count.
    Unique service keys are cached so repeated subnets cost zero NVD calls.
    """

    def __init__(self, source: CVEDataSource) -> None:
        self._source = source
        self._cache: dict[str, list[CVEMatch]] = {}
        self._log = AegisLogger("batch-cve").get()

    def _service_key(self, service: str, banner: str | None) -> str:
        key = service.lower().strip()
        if banner:
            version = banner.split()[-1] if banner.split() else ""
            if version and any(c.isdigit() for c in version):
                key = f"{key} {version}"
        return key.replace(" ", "_")

    async def resolve(self, discoveries: list[ServiceDiscovery]) -> dict[str, list[CVEMatch]]:
        unique: dict[str, str] = {}
        for d in discoveries:
            for p in d.ports:
                if not p.service:
                    continue
                key = self._service_key(p.service, p.banner)
                if key not in unique:
                    unique[key] = p.banner or ""

        result: dict[str, list[CVEMatch]] = {}
        for key, banner in unique.items():
            if key in self._cache:
                result[key] = self._cache[key]
                continue
            self._log.debug("Batch NVD query: %s", key)
            matches = await self._source.query(key.replace("_", " "), banner)
            self._cache[key] = matches
            result[key] = matches

        self._log.info("Batch CVE resolve — %d unique service keys, %d total matches",
                       len(unique), sum(len(v) for v in result.values()))
        return result
