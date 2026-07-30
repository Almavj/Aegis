"""Entry point — CLI runner for Alma."""

import argparse
import asyncio

from alma.core.cve import NistNvdApi
from alma.core.credentials import CredentialCache
from alma.core.exploit import Exploit
from alma.core.orchestrator import EngagementStatus, Orchestrator
from alma.core.payload import ScriptPayload
from alma.core.reporting import JsonReportBuilder, MarkdownReportBuilder
from alma.core.scanner import ConnectScanner, NmapScanner
from alma.core.session import TcpSessionManager
from alma.core.vulnerability import VulnerabilityEngine
from alma.modules import discover_modules
from alma.utils.logger import AlmaLogger


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="alma", description="Modular offensive security framework")
    p.add_argument("targets", nargs="*", help="Target CIDR ranges or hostnames")
    p.add_argument("-p", "--ports", nargs="*", type=int, help="Port list (default: top-1000)")
    p.add_argument("--fast", action="store_true", help="Fast mode (fewer probes)")
    p.add_argument("--no-exploit", action="store_true", help="Skip exploitation phase")
    p.add_argument("--report-format", choices=["json", "markdown"], default="markdown")
    p.add_argument("--lhost", default="127.0.0.1", help="Local IP for payload callbacks")
    p.add_argument("--lport", type=int, default=4444, help="Local port for payload callbacks")
    p.add_argument("--listen", action="store_true", help="Start C2 listener for reverse shells")
    p.add_argument("--log-dir", help="Directory for per-run logs")
    p.add_argument("--list-modules", action="store_true", help="List available exploit modules and exit")
    p.add_argument("--recursive", action="store_true", help="Recursive scan-exploit-pivot loop")
    p.add_argument("--max-depth", type=int, default=2, help="Max recursion depth for pivoting")
    p.add_argument("--no-nvd", action="store_true", help="Skip NVD API queries (use built-in rules only)")
    p.add_argument("--nvd-api-key", help="NIST NVD API key for higher rate limits")
    p.add_argument("--tui", action="store_true", help="Launch interactive TUI dashboard")
    p.add_argument("--headless", action="store_true", help="Force headless mode (no TUI)")
    return p


async def main() -> None:
    args = build_arg_parser().parse_args()

    discover_modules()

    if args.list_modules:
        print("Alma exploit modules:")
        for name, cls in Exploit.list_available().items():
            rank_name = cls.rank.name if hasattr(cls, "rank") else "AVERAGE"
            print(f"  {name:30s}  [{rank_name:10s}]  {cls.description}")
        return

    if args.tui and not args.headless:
        from alma.ui.app import run_tui
        run_tui()
        return

    if not args.targets:
        print("No targets specified. Use --help for usage.")
        return

    log = AlmaLogger("alma", log_dir=args.log_dir).get()
    log.info("Alma v0.1.0 starting — %d exploit modules loaded", len(Exploit._registry))

    import shutil
    if shutil.which("nmap"):
        scanner = NmapScanner(rate_limit=500, timeout=10)
        log.info("Using NmapScanner")
    else:
        scanner = ConnectScanner(rate_limit=100, timeout=3)
        log.info("nmap not found — using ConnectScanner (TCP connect only)")

    default_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                     993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
                     8080, 8443, 27017]

    cve_api = None if args.no_nvd else NistNvdApi(api_key=args.nvd_api_key)
    vuln_engine = VulnerabilityEngine(cve_finder=cve_api)
    session_mgr = TcpSessionManager()
    cred_cache = CredentialCache()
    payload_gen = ScriptPayload(lhost=args.lhost, lport=args.lport)
    report_builder = (
        JsonReportBuilder() if args.report_format == "json" else MarkdownReportBuilder()
    )

    if args.listen:
        await session_mgr.listen(port=args.lport)

    def progress_callback(status: EngagementStatus) -> None:
        d = status.to_dict()
        log.info(
            "[%s] hosts=%d ports=%d vulns=%d sessions=%d creds=%d elapsed=%.1fs",
            d["phase"], d["targets_identified"], d["ports_scanned"],
            d["vulnerabilities_found"], d["sessions_active"],
            d["credentials_harvested"], d["elapsed_seconds"],
        )

    orchestrator = Orchestrator(
        scanner=scanner,
        vuln_engine=vuln_engine,
        session_mgr=session_mgr,
        cve_source=cve_api,
        payload_gen=payload_gen,
        report_builder=report_builder,
        cred_cache=cred_cache,
        progress_reporter=progress_callback,
        log_dir=args.log_dir,
    )

    await orchestrator.run(
        targets=args.targets,
        ports=args.ports or default_ports,
        fast_scan=args.fast,
        auto_exploit=not args.no_exploit,
        recursive=args.recursive,
        max_recursion_depth=args.max_depth,
    )


if __name__ == "__main__":
    asyncio.run(main())
