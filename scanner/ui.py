"""LANlord – Textual-based terminal UI for network scanning."""

from __future__ import annotations

import asyncio
from ipaddress import IPv4Address

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Log,
    ProgressBar,
    Static,
    TabbedContent,
    TabPane,
)

from scanner.export import export_csv, export_json
from scanner.network import (
    NetworkInfo,
    detect_network,
    ip_range_from_cidr,
    ip_range_from_start_end,
    validate_cidr,
    validate_ip,
)
from scanner.ping import PingResult, discover_hosts
from scanner.portscan import (
    COMMON_PORTS,
    DEFAULT_PORTS,
    HostScanResult,
    parse_ports,
    scan_hosts,
)

ASCII_BANNER = r"""
  ██╗      █████╗ ███╗   ██╗██╗      ██████╗ ██████╗ ██████╗
  ██║     ██╔══██╗████╗  ██║██║     ██╔═══██╗██╔══██╗██╔══██╗
  ██║     ███████║██╔██╗ ██║██║     ██║   ██║██████╔╝██║  ██║
  ██║     ██╔══██║██║╚██╗██║██║     ██║   ██║██╔══██╗██║  ██║
  ███████╗██║  ██║██║ ╚████║███████╗╚██████╔╝██║  ██║██████╔╝
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝
"""


class LANlordApp(App):
    """Main Textual application for LANlord network scanner."""

    TITLE = "LANlord"
    SUB_TITLE = "Network IP & Port Scanner"
    CSS_PATH = "styles.tcss"

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("d", "detect", "Detect Network", show=True),
        Binding("s", "start_scan", "Start Scan", show=True),
        Binding("e", "export_json", "Export JSON", show=True),
        Binding("c", "export_csv", "Export CSV", show=True),
        Binding("r", "reset", "Reset", show=True),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.net_info: NetworkInfo | None = None
        self.ping_results: list[PingResult] = []
        self.scan_results: list[HostScanResult] = []
        self._scanning = False

    # ── Compose ────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="main-container"):
            # Banner
            yield Static(ASCII_BANNER, id="banner")

            with TabbedContent(id="tabs"):
                # ── Tab 1: Network Config ──────────────────────────────
                with TabPane("Network", id="tab-network"):
                    with Vertical(id="network-panel"):
                        yield Label("🔎 Network Detection", id="net-detect-label", classes="section-title")
                        yield Static("Press [bold green]D[/] or click Detect to auto-detect your network.", id="net-hint")
                        with Horizontal(classes="btn-row"):
                            yield Button("Detect Network", id="btn-detect", variant="success")
                        yield Static("", id="net-info-display")

                        yield Label("✏️  Manual Override", id="manual-label", classes="section-title")
                        with Horizontal(classes="input-row"):
                            yield Input(placeholder="Start IP  (e.g. 192.168.1.1)", id="input-start-ip")
                            yield Input(placeholder="End IP  (e.g. 192.168.1.254)", id="input-end-ip")
                        with Horizontal(classes="input-row"):
                            yield Input(placeholder="CIDR  (e.g. 192.168.1.0/24)", id="input-cidr")
                        with Horizontal(classes="input-row"):
                            yield Input(placeholder="Ports  (e.g. 22,80,443 or 1-1024)", id="input-ports", value="22,80,443,3306,8080")
                        with Horizontal(classes="btn-row"):
                            yield Button("Start Scan", id="btn-scan", variant="primary")
                            yield Button("Reset", id="btn-reset", variant="error")

                # ── Tab 2: Live Results ────────────────────────────────
                with TabPane("Results", id="tab-results"):
                    with Vertical(id="results-panel"):
                        yield Label("📡 Scan Progress", classes="section-title")
                        yield Static("Idle", id="progress-label")
                        yield ProgressBar(id="scan-progress", total=100, show_eta=True)

                        yield Label("🖥️  Discovered Hosts", classes="section-title")
                        yield DataTable(id="hosts-table", zebra_stripes=True)

                        yield Label("🔓 Open Ports", classes="section-title")
                        yield DataTable(id="ports-table", zebra_stripes=True)

                # ── Tab 3: Log ─────────────────────────────────────────
                with TabPane("Log", id="tab-log"):
                    with Vertical(id="log-panel"):
                        yield Label("📋 Activity Log", classes="section-title")
                        yield Log(id="activity-log", highlight=True, auto_scroll=True, max_lines=5000)

                # ── Tab 4: Export ──────────────────────────────────────
                with TabPane("Export", id="tab-export"):
                    with Vertical(id="export-panel"):
                        yield Label("💾 Export Results", classes="section-title")
                        yield Static("Export scan results to a file for later analysis.", id="export-hint")
                        with Horizontal(classes="btn-row"):
                            yield Button("Export JSON", id="btn-export-json", variant="success")
                            yield Button("Export CSV", id="btn-export-csv", variant="primary")
                        yield Static("", id="export-status")

        yield Footer()

    # ── Mount ──────────────────────────────────────────────────────────

    def on_mount(self) -> None:
        # Set up host table columns
        hosts_table: DataTable = self.query_one("#hosts-table", DataTable)
        hosts_table.add_columns("IP Address", "Status", "Response Time", "Method")

        # Set up ports table columns
        ports_table: DataTable = self.query_one("#ports-table", DataTable)
        ports_table.add_columns("Host", "Port", "State", "Service")

        self._log("LANlord started.  Press [bold green]D[/] to detect your network.")

    # ── Helpers ────────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        log_widget: Log = self.query_one("#activity-log", Log)
        log_widget.write_line(msg)

    def _set_progress(self, label: str, pct: float) -> None:
        self.query_one("#progress-label", Static).update(label)
        bar: ProgressBar = self.query_one("#scan-progress", ProgressBar)
        bar.update(progress=pct)

    # ── Actions / Buttons ──────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-detect":
            self.action_detect()
        elif btn_id == "btn-scan":
            self.action_start_scan()
        elif btn_id == "btn-reset":
            self.action_reset()
        elif btn_id == "btn-export-json":
            self.action_export_json()
        elif btn_id == "btn-export-csv":
            self.action_export_csv()

    # ── Detect ─────────────────────────────────────────────────────────

    def action_detect(self) -> None:
        self._log("Detecting network…")
        self.net_info = detect_network()
        info = self.net_info
        if not info.local_ip:
            self.query_one("#net-info-display", Static).update(
                "[bold red]Could not detect network. Enter range manually.[/]"
            )
            self._log("[red]Network detection failed.[/red]")
            return

        lines = (
            f"[bold cyan]Interface:[/]  {info.interface}\n"
            f"[bold cyan]Local IP:[/]   {info.local_ip}\n"
            f"[bold cyan]Subnet:[/]     {info.subnet_mask}\n"
            f"[bold cyan]CIDR:[/]       {info.cidr}\n"
            f"[bold cyan]Range:[/]      {info.first_host} → {info.last_host}\n"
            f"[bold cyan]Hosts:[/]      {info.total_hosts}"
        )
        self.query_one("#net-info-display", Static).update(lines)

        # Pre-fill inputs
        self.query_one("#input-start-ip", Input).value = info.first_host
        self.query_one("#input-end-ip", Input).value = info.last_host
        self.query_one("#input-cidr", Input).value = info.cidr

        self._log(f"Detected {info.cidr}  ({info.total_hosts} hosts)")

    # ── Start Scan ─────────────────────────────────────────────────────

    def action_start_scan(self) -> None:
        if self._scanning:
            self.notify("A scan is already running!", severity="warning")
            return
        self._run_scan()

    @work(exclusive=True)
    async def _run_scan(self) -> None:
        self._scanning = True
        self.ping_results.clear()
        self.scan_results.clear()

        # Clear tables
        hosts_table: DataTable = self.query_one("#hosts-table", DataTable)
        ports_table: DataTable = self.query_one("#ports-table", DataTable)
        hosts_table.clear()
        ports_table.clear()

        # Switch to results tab
        tabs = self.query_one("#tabs", TabbedContent)
        tabs.active = "tab-results"

        # ── Resolve IP list ────────────────────────────────────────────
        cidr_val = self.query_one("#input-cidr", Input).value.strip()
        start_val = self.query_one("#input-start-ip", Input).value.strip()
        end_val = self.query_one("#input-end-ip", Input).value.strip()

        ips: list[str] = []
        if cidr_val and validate_cidr(cidr_val):
            ips = ip_range_from_cidr(cidr_val)
            self._log(f"Using CIDR {cidr_val}  →  {len(ips)} hosts")
        elif start_val and end_val and validate_ip(start_val) and validate_ip(end_val):
            ips = ip_range_from_start_end(start_val, end_val)
            self._log(f"Using range {start_val} → {end_val}  →  {len(ips)} hosts")
        else:
            self.notify("Please detect or enter a valid IP range first.", severity="error")
            self._log("[red]Invalid IP range.[/red]")
            self._scanning = False
            return

        if not ips:
            self.notify("No hosts in range.", severity="error")
            self._scanning = False
            return

        # ── Resolve Ports ──────────────────────────────────────────────
        port_str = self.query_one("#input-ports", Input).value.strip()
        ports = parse_ports(port_str) if port_str else COMMON_PORTS
        self._log(f"Ports to scan: {ports}")

        # ── Phase 1: Host Discovery ───────────────────────────────────
        self._log(f"[bold]Phase 1:[/bold] Host discovery  ({len(ips)} targets)…")
        self._set_progress("Phase 1: Host discovery…", 0)

        async def ping_progress(done: int, total: int, result: PingResult):
            pct = (done / total) * 50  # first half of bar
            self.call_from_thread(self._set_progress, f"Ping {done}/{total}", pct) if False else None
            self._set_progress(f"Ping {done}/{total}", pct)
            if result.alive:
                rtt = f"{result.response_time_ms:.1f} ms" if result.response_time_ms else "—"
                hosts_table.add_row(result.ip, "[green]Online[/]", rtt, result.method)
                self._log(f"  [green]●[/] {result.ip}  ({rtt})")

        ping_results = await discover_hosts(
            ips, concurrency=60, progress_callback=ping_progress,
        )
        self.ping_results = ping_results
        alive_hosts = [r for r in ping_results if r.alive]
        offline_count = len(ping_results) - len(alive_hosts)
        self._log(f"Discovery complete: [green]{len(alive_hosts)}[/] online, [dim]{offline_count}[/] offline")

        if not alive_hosts:
            self._set_progress("Done – no live hosts found.", 100)
            self._log("[yellow]No live hosts found.[/yellow]")
            self._scanning = False
            return

        # ── Phase 2: Port Scanning ────────────────────────────────────
        alive_ips = [r.ip for r in alive_hosts]
        total_probes = len(alive_ips) * len(ports)
        probes_done = 0
        self._log(f"[bold]Phase 2:[/bold] Port scan  ({len(alive_ips)} hosts × {len(ports)} ports = {total_probes} probes)…")

        async def port_progress(ip: str, done: int, total: int, result):
            nonlocal probes_done
            probes_done += 1
            pct = 50 + (probes_done / total_probes) * 50
            self._set_progress(f"Scanning {ip} ({done}/{total} ports)", pct)
            if result.state == "open":
                ports_table.add_row(ip, str(result.port), "[green]open[/]", result.service or "—")
                self._log(f"  [green]✓[/] {ip}:{result.port}  {result.service or ''}")

        scan_results = await scan_hosts(
            alive_ips,
            ports=ports,
            concurrency=80,
            port_progress_callback=port_progress,
        )
        self.scan_results = scan_results

        total_open = sum(len(r.open_ports) for r in scan_results)
        self._set_progress(f"Done – {len(alive_hosts)} hosts, {total_open} open ports", 100)
        self._log(f"[bold green]Scan complete.[/bold green]  {total_open} open port(s) across {len(alive_hosts)} host(s).")
        self.notify(f"Scan complete: {len(alive_hosts)} hosts, {total_open} open ports")
        self._scanning = False

    # ── Reset ──────────────────────────────────────────────────────────

    def action_reset(self) -> None:
        self.ping_results.clear()
        self.scan_results.clear()
        self.query_one("#hosts-table", DataTable).clear()
        self.query_one("#ports-table", DataTable).clear()
        self._set_progress("Idle", 0)
        self.query_one("#net-info-display", Static).update("")
        self.query_one("#input-start-ip", Input).value = ""
        self.query_one("#input-end-ip", Input).value = ""
        self.query_one("#input-cidr", Input).value = ""
        self.query_one("#input-ports", Input).value = "22,80,443,3306,8080"
        self.query_one("#export-status", Static).update("")
        self._log("Reset complete.")

    # ── Exports ────────────────────────────────────────────────────────

    def action_export_json(self) -> None:
        if not self.ping_results and not self.scan_results:
            self.notify("Nothing to export – run a scan first.", severity="warning")
            return
        try:
            path = export_json(self.ping_results, self.scan_results)
            self.query_one("#export-status", Static).update(f"[green]Saved → {path}[/]")
            self._log(f"Exported JSON → {path}")
            self.notify(f"JSON exported: {path}")
        except Exception as exc:
            self.notify(f"Export failed: {exc}", severity="error")

    def action_export_csv(self) -> None:
        if not self.ping_results and not self.scan_results:
            self.notify("Nothing to export – run a scan first.", severity="warning")
            return
        try:
            path = export_csv(self.ping_results, self.scan_results)
            self.query_one("#export-status", Static).update(f"[green]Saved → {path}[/]")
            self._log(f"Exported CSV → {path}")
            self.notify(f"CSV exported: {path}")
        except Exception as exc:
            self.notify(f"Export failed: {exc}", severity="error")
