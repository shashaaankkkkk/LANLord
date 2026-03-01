# LANlord 🏰

A fast, clean, **hacker-style** terminal-based network IP & port scanner built entirely in Python + [Textual](https://textual.textualize.io/).

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)

---

## Features

| Feature | Description |
|---|---|
| **Auto-Detect Network** | Detects active interface, local IP, subnet mask & CIDR range |
| **Manual IP Range** | Enter start/end IPs or a CIDR block to override detection |
| **Host Discovery** | ICMP ping scan with TCP fallback for restricted environments |
| **Port Scanning** | Async TCP connect scan with configurable port list |
| **Live TUI** | Textual-powered interactive UI with tables, progress bar & log |
| **Export** | Save results to JSON or CSV |
| **Cross-Platform** | Works on macOS, Linux & Windows — no root required |

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run LANlord
python -m scanner.main
```

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `D` | Detect network |
| `S` | Start scan |
| `E` | Export JSON |
| `C` | Export CSV |
| `R` | Reset |
| `Q` | Quit |

---

## Project Structure

```
scanner/
├── __init__.py      # Package metadata
├── main.py          # Entry point
├── network.py       # Network detection & IP utilities
├── ping.py          # Host discovery (ICMP + TCP fallback)
├── portscan.py      # Async TCP port scanner
├── export.py        # JSON / CSV export
├── ui.py            # Textual terminal UI
└── styles.tcss      # Textual CSS theme
```

---

## Usage

1. **Launch** the app → `python -m scanner.main`
2. Press **D** to auto-detect your network
3. Optionally edit the IP range and ports in the **Network** tab
4. Press **S** to start scanning
5. Watch live results in the **Results** tab and logs in the **Log** tab
6. Export results from the **Export** tab (JSON / CSV)

---

## Configuration

### Default Ports

The default scan targets these common ports:

```
22, 80, 443, 3306, 8080
```

Enter a custom list in the **Ports** input field using:

- Single ports: `80`
- Comma-separated: `22,80,443`
- Ranges: `1-1024`
- Mixed: `22,80,100-200,443,8080-8090`

---

## Dependencies

- **[textual](https://pypi.org/project/textual/)** — Terminal UI framework
- **[rich](https://pypi.org/project/rich/)** — Rich text rendering
- **[psutil](https://pypi.org/project/psutil/)** — Network interface detection

---

## License

MIT
