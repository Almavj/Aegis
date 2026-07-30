from __future__ import annotations

import asyncio
from pathlib import Path

from textual import on
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import var
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    ProgressBar,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)

from alma.core.orchestrator import EngagementStatus


status_queue: asyncio.Queue[EngagementStatus] = asyncio.Queue(maxsize=50)


class AlmaTui(App):
    CSS = """
    Screen {
        background: $surface;
    }

    #title {
        text-style: bold;
        content-align: center middle;
        height: 3;
    }

    #control-row {
        height: 5;
        align: center middle;
    }

    #target-input {
        width: 40;
        margin-right: 1;
    }

    #run-btn {
        width: 16;
    }

    #status-grid {
        height: 8;
    }

    .stat-card {
        border: solid $primary;
        height: 3;
        width: 1fr;
        margin: 0 1;
        padding: 0 1;
    }

    .stat-label {
        text-style: bold;
        color: $text;
    }

    .stat-value {
        text-style: bold;
        color: $accent;
    }

    #log-widget {
        border: solid $secondary;
        height: 1fr;
        margin: 1;
    }

    #cred-widget {
        border: solid $warning;
        height: 1fr;
        margin: 1;
    }

    #findings-widget {
        border: solid $success;
        height: 1fr;
        margin: 1;
    }

    ProgressBar {
        width: 100%;
        margin: 0 1;
    }

    TabbedContent {
        height: 1fr;
        margin: 1;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        with Container():
            yield Static("Alma — Modular Offensive Security Framework", id="title")
            with Horizontal(id="control-row"):
                yield Input(placeholder="Target CIDR (e.g. 192.168.1.0/24)", id="target-input")
                yield Button("Run", id="run-btn", variant="primary")
                yield Button("Quit", id="quit-btn", variant="error")

            with Horizontal(id="status-grid"):
                with Vertical(classes="stat-card"):
                    yield Static("Phase", classes="stat-label")
                    yield Static("idle", id="phase-val", classes="stat-value")
                with Vertical(classes="stat-card"):
                    yield Static("Hosts", classes="stat-label")
                    yield Static("0", id="hosts-val", classes="stat-value")
                with Vertical(classes="stat-card"):
                    yield Static("Ports", classes="stat-label")
                    yield Static("0", id="ports-val", classes="stat-value")
                with Vertical(classes="stat-card"):
                    yield Static("Vulns", classes="stat-label")
                    yield Static("0", id="vulns-val", classes="stat-value")
                with Vertical(classes="stat-card"):
                    yield Static("Sessions", classes="stat-label")
                    yield Static("0", id="sessions-val", classes="stat-value")
                with Vertical(classes="stat-card"):
                    yield Static("Creds", classes="stat-label")
                    yield Static("0", id="creds-val", classes="stat-value")

            yield ProgressBar(total=100, show_eta=False, id="progress")

            with TabbedContent():
                with TabPane("Log", id="log-tab"):
                    yield RichLog(id="log-widget", highlight=True, max_lines=1000)
                with TabPane("Credentials", id="cred-tab"):
                    yield RichLog(id="cred-widget", highlight=True, max_lines=500)
                with TabPane("Findings", id="findings-tab"):
                    yield RichLog(id="findings-widget", highlight=True, max_lines=500)

        yield Footer()

    def on_mount(self) -> None:
        asyncio.create_task(self._watch_status())
        log = self.query_one("#log-widget", RichLog)
        log.write("Alma TUI ready. Enter a target and press Run.")

    async def _watch_status(self) -> None:
        while True:
            status = await status_queue.get()
            self._update_ui(status)

    def _update_ui(self, status: EngagementStatus) -> None:
        d = status.to_dict()

        self.query_one("#phase-val", Static).update(d.get("phase", "idle").upper())
        self.query_one("#hosts-val", Static).update(str(d.get("targets_identified", 0)))
        self.query_one("#ports-val", Static).update(str(d.get("ports_scanned", 0)))
        self.query_one("#vulns-val", Static).update(str(d.get("vulnerabilities_found", 0)))
        self.query_one("#sessions-val", Static).update(str(d.get("sessions_active", 0)))
        self.query_one("#creds-val", Static).update(str(d.get("credentials_harvested", 0)))

        bar = self.query_one("#progress", ProgressBar)
        elapsed = d.get("elapsed_seconds", 0)
        bar.progress = min(int(elapsed), 100)

        log = self.query_one("#log-widget", RichLog)
        log.write(
            f"[{d.get('phase')}] hosts={d.get('targets_identified')} "
            f"ports={d.get('ports_scanned')} vulns={d.get('vulnerabilities_found')} "
            f"sessions={d.get('sessions_active')} creds={d.get('credentials_harvested')} "
            f"elapsed={elapsed:.1f}s"
        )

    @on(Button.Pressed, "#run-btn")
    def handle_run(self) -> None:
        inp = self.query_one("#target-input", Input)
        target = inp.value.strip()
        if not target:
            return
        log = self.query_one("#log-widget", RichLog)
        log.write(f"Starting engagement against {target}")
        asyncio.create_task(self._launch_engagement(target))

    @on(Button.Pressed, "#quit-btn")
    def handle_quit(self) -> None:
        self.exit()

    async def _launch_engagement(self, target: str) -> None:
        from alma.core.orchestrator import Orchestrator
        from alma.core.scanner import ConnectScanner, NmapScanner
        from alma.core.session import TcpSessionManager
        from alma.core.vulnerability import VulnerabilityEngine
        from alma.core.credentials import CredentialCache
        from alma.core.cve import NistNvdApi
        from alma.core.payload import ScriptPayload
        from alma.core.reporting import MarkdownReportBuilder
        from alma.modules import discover_modules

        import shutil
        discover_modules()

        if shutil.which("nmap"):
            scanner = NmapScanner(rate_limit=500, timeout=10)
        else:
            scanner = ConnectScanner(rate_limit=100, timeout=3)

        cve_api = NistNvdApi()
        vuln_engine = VulnerabilityEngine(cve_finder=cve_api)
        session_mgr = TcpSessionManager()
        cred_cache = CredentialCache()

        orchestrator = Orchestrator(
            scanner=scanner,
            vuln_engine=vuln_engine,
            session_mgr=session_mgr,
            cve_source=cve_api,
            payload_gen=ScriptPayload(),
            report_builder=MarkdownReportBuilder(),
            cred_cache=cred_cache,
            status_queue=status_queue,
        )

        await session_mgr.listen(port=4444)
        await orchestrator.run(targets=[target], recursive=True, max_recursion_depth=2)

        log = self.query_one("#log-widget", RichLog)
        log.write("Engagement complete.")


def run_tui() -> None:
    app = AlmaTui()
    app.run()
