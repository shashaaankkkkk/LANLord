from textual.app import App, ComposeResult
from textual.containers import Grid, Vertical
from textual.widgets import Header, Footer, Input, DataTable, Static
from textual.binding import Binding

from lanlord.core.engine import ScanEngine
from lanlord.core.profiles import QUICK
from lanlord.utils.network import range_from_start_end


class LANLordApp(App):

    CSS_PATH = "theme.css"

    BINDINGS = [
        Binding("s", "start_scan", "Start Scan"),
        Binding("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Grid(id="layout"):

            # LEFT PANEL
            with Vertical(classes="panel"):

                yield Static("Scan Configuration", classes="highlight")

                yield Static("Start IP")
                yield Input(id="start_ip", placeholder="192.168.1.1")

                yield Static("End IP")
                yield Input(id="end_ip", placeholder="192.168.1.254")

                yield Static("Scan Status")
                yield Static("Idle", id="scan_status")

                yield Static("Progress")
                yield Static("0%", id="progress")

            # CENTER PANEL
            with Vertical(classes="panel"):

                table = DataTable(id="host_table")
                table.add_columns(
                    "IP",
                    "Status",
                    "Latency",
                    "OS",
                    "Open Ports",
                    "MAC",
                    "Vendor"
                )
                yield table

            # RIGHT PANEL
            with Vertical(classes="panel"):
                yield Static("Host Intelligence", classes="highlight")
                yield Static(
                    "Select a host to view details",
                    id="detail_panel"
                )

        yield Footer()

    async def on_mount(self):
        self.engine = ScanEngine(profile=QUICK)

        self.table = self.query_one("#host_table", DataTable)
        self.status_label = self.query_one("#scan_status", Static)
        self.progress_label = self.query_one("#progress", Static)
        self.detail_panel = self.query_one("#detail_panel", Static)

    async def action_start_scan(self):

        start_ip = self.query_one("#start_ip", Input).value
        end_ip = self.query_one("#end_ip", Input).value

        if not start_ip or not end_ip:
            return

        self.table.clear()
        self.status_label.update("Scanning...")

        ips = range_from_start_end(start_ip, end_ip)

        total = len(ips)
        scanned = 0

        for ip in ips:

            host = await self.engine._scan_host(ip)

            if not host:
                continue

            scanned += 1
            percent = int((scanned / total) * 100)
            self.progress_label.update(f"{percent}%")

            open_ports = len([
                p for p in host.ports
                if p.state.value == "open"
            ])

            self.table.add_row(
                host.ip,
                host.status.value,
                f"{host.latency:.2f}s" if host.latency else "-",
                host.os or "-",
                str(open_ports),
                host.mac or "-",
                host.vendor or "-",
                key=host.ip
            )

        self.status_label.update("Completed")

    async def on_data_table_row_selected(self, event):

        ip = event.row_key

        if not hasattr(self.engine, "last_result"):
            return

        for host in self.engine.last_result.hosts:
            if host.ip == ip:

                details = f"""
IP: {host.ip}
Status: {host.status.value}
Latency: {host.latency}
OS: {host.os}
MAC: {host.mac}
Vendor: {host.vendor}
HTTP Title: {host.http_title}
SSL Info: {host.ssl_info}

Open Ports:
"""

                for port in host.ports:
                    if port.state.value == "open":
                        details += (
                            f"{port.port}/{port.protocol} "
                            f"- {port.service}\n"
                        )

                self.detail_panel.update(details)
                break
