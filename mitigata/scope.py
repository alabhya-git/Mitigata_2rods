from __future__ import annotations

import ipaddress
import posixpath
from dataclasses import dataclass
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from .config import ScopeManifest


class ScopeDenied(ValueError):
    pass


@dataclass(frozen=True)
class Destination:
    url: str
    scheme: str
    hostname: str
    address: str
    port: int
    request_target: str


class ScopeGuard:
    """Pure validation. Hostnames use frozen numeric bindings, never ambient DNS."""

    def __init__(self, manifest: ScopeManifest):
        self.manifest = manifest
        self.networks = [ipaddress.ip_network(a, strict=False) for a in manifest.addresses]
        self.ports = frozenset(manifest.selected_ports())
        self.exclusions = tuple(ipaddress.ip_network(a) for a in manifest.excluded_addresses)
        self.allowed_paths = tuple(manifest.allowed_paths)
        self.excluded_paths = tuple(manifest.excluded_paths)
        self.bindings = {k.lower().rstrip("."): tuple(v) for k, v in manifest.hostnames.items()}
        addresses = set()
        for network in self.networks:
            candidates = (
                network
                if manifest.mode == "LOCAL_LAB" or manifest.include_network_broadcast
                else network.hosts()
            )
            addresses.update(
                str(ip)
                for ip in candidates
                if not any(ip.version == e.version and ip in e for e in self.exclusions)
            )
        self.addresses = tuple(
            sorted(addresses, key=lambda a: (ipaddress.ip_address(a).version, int(ipaddress.ip_address(a))))
        )
        if any(a not in addresses for a in manifest.priority_addresses):
            raise ScopeDenied("Priority addresses cannot include excluded network/broadcast addresses")
        self.addresses = tuple(dict.fromkeys([*manifest.priority_addresses, *self.addresses]))
        if not self.addresses:
            raise ScopeDenied("Scope exclusions removed every usable address")
        self.address_set = frozenset(self.addresses)
        priority = [p for p in dict.fromkeys(manifest.priority_ports) if p in self.ports]
        self.ordered_ports = tuple(priority + sorted(self.ports - set(priority)))
        self.target_count = len(self.addresses) * len(self.ports)

    def address_allowed(self, address: str, port: int) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return port in self.ports and str(ip) in self.address_set

    def targets(self):
        for index in range(self.target_count):
            yield self.target_at(index)

    def target_at(self, index: int):
        if not 0 <= index < self.target_count:
            raise IndexError("Discovery frontier index outside scope")
        port_index, address_index = divmod(index, len(self.addresses))
        return self.addresses[address_index], self.ordered_ports[port_index]

    def destination(self, url: str) -> Destination:
        if len(url) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in url) or "\\" in url:
            raise ScopeDenied("Malformed or oversized URL")
        try:
            parts = urlsplit(url)
            if parts.scheme not in {"http", "https"} or not parts.hostname:
                raise ScopeDenied("Only absolute HTTP(S) URLs are supported")
            if parts.username is not None or parts.password is not None:
                raise ScopeDenied("Credentials in URLs are prohibited")
            host = parts.hostname.lower().rstrip(".")
            port = parts.port if parts.port is not None else (443 if parts.scheme == "https" else 80)
        except ValueError as exc:
            raise ScopeDenied("Invalid URL authority") from exc
        try:
            addresses = (str(ipaddress.ip_address(host)),)
        except ValueError:
            addresses = self.bindings.get(host, ())
        if not addresses or not all(self.address_allowed(a, port) for a in addresses):
            raise ScopeDenied("Destination is outside the frozen address/port/hostname allowlist")
        raw_path = parts.path or "/"
        decoded = raw_path
        for _ in range(4):
            next_path = unquote(decoded)
            if next_path == decoded:
                break
            decoded = next_path
        if "%" in decoded or "\\" in decoded or any(ord(c) < 32 for c in decoded):
            raise ScopeDenied("Ambiguous URL path encoding")
        if any(segment in {".", ".."} for segment in decoded.split("/")):
            raise ScopeDenied("Dot path segments are prohibited")
        normalized = posixpath.normpath(decoded)
        if decoded.endswith("/") and normalized != "/":
            normalized += "/"
        if not normalized.startswith("/") or normalized.startswith("//"):
            raise ScopeDenied("Invalid absolute path")

        def matches(rule):
            return (
                rule == "/" or normalized == rule.rstrip("/") or normalized.startswith(rule.rstrip("/") + "/")
            )

        if not any(matches(p) for p in self.allowed_paths) or any(matches(p) for p in self.excluded_paths):
            raise ScopeDenied("URL path is outside the approved path policy")
        encoded = quote(normalized, safe="/!$&'()*+,;=:@-._~")
        authority = f"[{host}]" if ":" in host else host
        default = 443 if parts.scheme == "https" else 80
        if port != default:
            authority += f":{port}"
        canonical = urlunsplit((parts.scheme, authority, encoded, parts.query, ""))
        return Destination(
            canonical,
            parts.scheme,
            host,
            addresses[0],
            port,
            encoded + ("?" + parts.query if parts.query else ""),
        )
