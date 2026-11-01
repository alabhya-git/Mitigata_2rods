from __future__ import annotations

import ipaddress
import json
import subprocess
import sys
from pathlib import Path

from .scope import ScopeGuard


def routing_snapshot(address: str):
    """Read OS routing state only. No DNS, ping, socket creation or target connection."""
    target = ipaddress.ip_address(address)
    routes = []
    try:
        if sys.platform == "win32":
            script = "Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric | ConvertTo-Json -Compress"
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                timeout=15,
                check=True,
            )
            data = json.loads(result.stdout)
            for row in data if isinstance(data, list) else [data]:
                network = ipaddress.ip_network(row["DestinationPrefix"], strict=False)
                if target in network:
                    routes.append(
                        {
                            "prefix": str(network),
                            "interface": row["InterfaceIndex"],
                            "next_hop": row["NextHop"],
                            "metric": row["RouteMetric"],
                        }
                    )
        elif sys.platform == "linux":
            for line in Path("/proc/net/route").read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) < 8 or not int(fields[3], 16) & 1:
                    continue
                decode = lambda field: str(ipaddress.ip_address(int(field, 16).to_bytes(4, "little")))
                network = ipaddress.ip_network(decode(fields[1]) + "/" + decode(fields[7]), strict=False)
                if target in network:
                    routes.append(
                        {
                            "prefix": str(network),
                            "interface": fields[0],
                            "next_hop": decode(fields[2]),
                            "metric": int(fields[6]),
                        }
                    )
        else:
            return {"status": "unavailable", "reachability": "not_tested"}
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        return {"status": "unavailable", "reachability": "not_tested"}
    routes.sort(key=lambda row: (-ipaddress.ip_network(row["prefix"]).prefixlen, row["metric"]))
    return {
        "status": "specific_route"
        if routes and routes[0]["prefix"] != "0.0.0.0/0"
        else "default_route_only"
        if routes
        else "no_route",
        "matching_routes": routes,
        "reachability": "not_tested",
    }


def plan(manifest, *, include_routes=False):
    guard = ScopeGuard(manifest)
    seeds = [guard.destination(url).url for url in manifest.seed_urls]
    value = {
        "network_activity": False,
        "mode": manifest.mode,
        "execution_profile": manifest.execution_profile,
        "addresses": list(manifest.addresses),
        "excluded_addresses": manifest.excluded_addresses,
        "selected_hosts": len(guard.addresses),
        "priority_addresses": manifest.priority_addresses,
        "selected_ports": len(guard.ports),
        "target_pairs": guard.target_count,
        "targets": [guard.target_at(i) for i in range(min(16, guard.target_count))],
        "target_list_truncated": guard.target_count > 16,
        "seeds": seeds,
        "priority_ports": [p for p in manifest.priority_ports if p in guard.ports],
        "credential_use": manifest.allow_credential_use,
        "allowed_actions": manifest.allowed_actions,
        "queue_window": manifest.budgets.queue_window,
        "request_budget": manifest.budgets.requests,
        "time_budget_seconds": manifest.budgets.seconds,
        "optimistic_full_scan_seconds": round(guard.target_count / manifest.budgets.rate_per_second, 1),
        "full_port_inventory_fits_request_budget": guard.target_count <= manifest.budgets.requests,
        "coverage_note": "Protocol identification, crawling and verification also consume requests. Unvisited targets remain explicitly untested; completion is not guaranteed by an allowlist.",
    }
    if include_routes and guard.addresses:
        value["routing"] = routing_snapshot(guard.addresses[0])
    return value
