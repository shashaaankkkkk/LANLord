from textual.app import App, ComposeResult
from textual.containers import Grid, Vertical
from textual.widgets import Header, Footer, Input, DataTable, Static
from textual.binding import Binding
from textual.reactive import reactive

from lanlord.core.engine import ScanEngine
from lanlord.core.profiles import QUICK


class LANLordApp(App):

    CSS_PATH = "theme.css"

    BINDINGS = [
        Binding("s", "start_scan", "Start Scan"),
        Binding("c", "cancel_scan", "Cancel"),
        Binding("q", "quit", "Quit"),
    ]

    selected_host = reactive(None)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Grid(id="layout"):

            with Vertical(classes="panel"):
                yield Static("Target Network", classes="highlight")
                yield Input(
                    placeholder="192.168.1.0/24",
                    id="target_input"
                )

                yield Static("Scan Stats", classes="highlight")
                yield Static("Status: Idle", id="scan_status")

            with Vertical(classes="panel"):
                table = DataTable(id="host_table")
                table.add_columns("IP", "Status", "Latency", "OS")
                yield table

            with Vertical(classes="panel"):
                yield Static("Host Details", classes="highlight")
                yield Static("Select a host...", id="detail_panel")

        yield Footer()

    async def on_mount(self):
        self.engine = ScanEngine(profile=QUICK)
        self.table = self.query_one("#host_table", DataTable)
        self.status_label = self.query_one("#scan_status", Static)
        self.detail_panel = self.query_one("#detail_panel", Static)

    async def action_start_scan(self):
        target = self.query_one("#target_input", Input).value
        self.status_label.update("Status: Scanning...")

        async for host in self.engine.scan_stream(target):
            row_style = "alive" if host.status.value == "alive" else "dead"

            self.table.add_row(
                host.ip,
                host.status.value,
                f"{host.latency:.2f}s" if host.latency else "-",
                host.os or "-",
                key=host.ip
            )

        self.status_label.update("Status: Completed")

    async def action_cancel_scan(self):
        self.engine.cancel()
        self.status_label.update("Status: Cancelled")

    async def on_data_table_row_highlighted(self, event):
        row_key = event.row_key
        host = row_key

        self.detail_panel.update(f"Selected Host: {host}")
