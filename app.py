from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Input, Button, DataTable, Static
from scanner import scan_range
from utils import generate_ips, get_local_range

class AngrIP(App):
    CSS = """
    Screen {
        layout: vertical;
    }
    DataTable {
        height: 60%;
    }
    #details {
        height: 40%;
        padding: 1;
        border: solid green;
    }
    """

    BINDINGS = [
        ("s", "scan", "Scan"),
        ("r", "reset", "Clear"),
        ("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        self.start = Input(placeholder="Start IP", id="start")
        self.end = Input(placeholder="End IP", id="end")
        yield self.start
        yield self.end
        yield Button("Scan", id="scan")

        self.table = DataTable()
        self.table.add_columns("IP", "Status", "Hostname")
        yield self.table

        self.details = Static("Select an IP to view details", id="details")
        yield self.details
        yield Footer()

    async def on_mount(self):
        s, e = get_local_range()
        self.start.value = s
        self.end.value = e
        self.scan_results = {}

    async def action_scan(self):
        self.table.clear()
        self.scan_results.clear()

        ips = generate_ips(self.start.value, self.end.value)
        results = await scan_range(ips)

        for r in results:
            self.scan_results[r.ip] = r
            self.table.add_row(
                r.ip,
                "Alive" if r.alive else "Dead",
                r.hostname or "-"
            )

    def action_reset(self):
        self.table.clear()
        self.details.update("Select an IP to view details")
        self.scan_results.clear()

    async def on_button_pressed(self, event):
        if event.button.id == "scan":
            await self.action_scan()

    async def on_data_table_row_selected(self, event):
        ip = event.row_key.value
        r = self.scan_results[ip]

        self.details.update(
            f"""
IP        : {r.ip}
Status    : {'Alive' if r.alive else 'Dead'}
Hostname  : {r.hostname or 'N/A'}
OpenPorts : {', '.join(map(str, r.ports)) or 'None'}
"""
        )

if __name__ == "__main__":
    AngrIP().run()
