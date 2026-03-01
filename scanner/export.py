"""Export scan results to JSON and CSV."""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timezone
from io import StringIO
from typing import Any

from scanner.ping import PingResult
from scanner.portscan import HostScanResult


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


# ── Serialisation helpers ─────────────────────────────────────────────

def _ping_to_dict(pr: PingResult) -> dict[str, Any]:
    return {
        "ip": pr.ip,
        "alive": pr.alive,
        "response_time_ms": pr.response_time_ms,
        "method": pr.method,
    }


def _host_scan_to_dict(hs: HostScanResult) -> dict[str, Any]:
    return {
        "ip": hs.ip,
        "open_ports": [
            {"port": p.port, "state": p.state, "service": p.service}
            for p in hs.open_ports
        ],
    }


# ── JSON export ───────────────────────────────────────────────────────

def export_json(
    ping_results: list[PingResult],
    scan_results: list[HostScanResult],
    filepath: str | None = None,
) -> str:
    """Export combined results to a JSON file.

    Returns the file path written to.
    """
    data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hosts": [],
    }

    ping_map = {pr.ip: pr for pr in ping_results}
    scan_map = {hs.ip: hs for hs in scan_results}

    all_ips = sorted(set(list(ping_map.keys()) + list(scan_map.keys())))

    for ip in all_ips:
        entry: dict[str, Any] = {"ip": ip}
        if ip in ping_map:
            pr = ping_map[ip]
            entry["alive"] = pr.alive
            entry["response_time_ms"] = pr.response_time_ms
            entry["ping_method"] = pr.method
        if ip in scan_map:
            hs = scan_map[ip]
            entry["open_ports"] = [
                {"port": p.port, "state": p.state, "service": p.service}
                for p in hs.open_ports
            ]
        data["hosts"].append(entry)

    if filepath is None:
        filepath = os.path.join(os.getcwd(), f"lanlord_scan_{_timestamp()}.json")

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)

    return filepath


# ── CSV export ────────────────────────────────────────────────────────

def export_csv(
    ping_results: list[PingResult],
    scan_results: list[HostScanResult],
    filepath: str | None = None,
) -> str:
    """Export combined results to a CSV file.

    Returns the file path written to.
    """
    ping_map = {pr.ip: pr for pr in ping_results}
    scan_map = {hs.ip: hs for hs in scan_results}
    all_ips = sorted(set(list(ping_map.keys()) + list(scan_map.keys())))

    if filepath is None:
        filepath = os.path.join(os.getcwd(), f"lanlord_scan_{_timestamp()}.csv")

    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["IP", "Alive", "Response Time (ms)", "Ping Method", "Open Ports"])

        for ip in all_ips:
            alive = ""
            rtt = ""
            method = ""
            ports_str = ""
            if ip in ping_map:
                pr = ping_map[ip]
                alive = str(pr.alive)
                rtt = str(pr.response_time_ms or "")
                method = pr.method
            if ip in scan_map:
                hs = scan_map[ip]
                ports_str = "; ".join(
                    f"{p.port}/{p.service or '?'}" for p in hs.open_ports
                )
            writer.writerow([ip, alive, rtt, method, ports_str])

    return filepath


def results_to_text(
    ping_results: list[PingResult],
    scan_results: list[HostScanResult],
) -> str:
    """Return a human-readable text summary (used for clipboard / log)."""
    buf = StringIO()
    buf.write(f"LANlord Scan Results – {datetime.now(timezone.utc).isoformat()}\n")
    buf.write("=" * 60 + "\n\n")

    ping_map = {pr.ip: pr for pr in ping_results}
    scan_map = {hs.ip: hs for hs in scan_results}
    all_ips = sorted(set(list(ping_map.keys()) + list(scan_map.keys())))

    for ip in all_ips:
        if ip in ping_map:
            pr = ping_map[ip]
            status = "ONLINE" if pr.alive else "OFFLINE"
            rtt = f"  ({pr.response_time_ms:.1f} ms)" if pr.response_time_ms else ""
            buf.write(f"  {ip:>15}  [{status}]{rtt}\n")
        if ip in scan_map:
            hs = scan_map[ip]
            if hs.open_ports:
                for p in hs.open_ports:
                    buf.write(f"{'':>19}  ├─ {p.port}/tcp  {p.state}  {p.service}\n")
            else:
                buf.write(f"{'':>19}  └─ no open ports\n")
        buf.write("\n")

    return buf.getvalue()
