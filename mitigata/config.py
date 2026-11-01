from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


def default_paths():
    from importlib.resources import files

    return files("mitigata").joinpath("data/paths.txt").read_text(encoding="utf-8").splitlines()


def default_credential_pairs():
    from importlib.resources import files

    lines = files("mitigata").joinpath("data/default-credentials.txt").read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def expand_ports(ports, port_ranges=(), excluded_ports=()):
    values = set(ports)
    if any(not isinstance(p, int) or not 1 <= p <= 65535 for p in values | set(excluded_ports)):
        raise ValueError("Ports must be in 1..65535")
    for span in port_ranges:
        parts = span.split("-")
        if len(parts) != 2 or not all(p.isascii() and p.isdecimal() for p in parts):
            raise ValueError("Port ranges must use inclusive START-END syntax")
        start, end = map(int, parts)
        if not 1 <= start <= end <= 65535:
            raise ValueError("Port ranges must be within 1..65535")
        values.update(range(start, end + 1))
    return tuple(sorted(values - set(excluded_ports)))


class Budgets(Contract):
    seconds: float = Field(default=180, ge=1, le=3600)
    requests: int = Field(default=400, ge=1, le=1000000)
    rate_per_second: float = Field(default=30, gt=0, le=1000)
    workers: int = Field(default=4, ge=1, le=128)
    timeout: float = Field(default=2, ge=0.1, le=20)
    max_body_bytes: int = Field(default=262144, ge=1024, le=4194304)
    max_artifact_bytes: int = Field(default=4194304, ge=128, le=16777216)
    max_pages: int = Field(default=100, ge=1, le=1000)
    max_depth: int = Field(default=5, ge=1, le=12)
    max_briefing_bytes: int = Field(default=8192, ge=1024, le=32768)
    max_auth_attempts: int = Field(default=6, ge=0, le=50)
    connect_timeout: float | None = Field(default=None, ge=0.1, le=20)
    queue_window: int = Field(default=64, ge=1, le=512)


class DiscoverySettings(Contract):
    batched: bool = False
    batch_size: int = Field(default=128, ge=8, le=4096)
    concurrency: int = Field(default=96, ge=1, le=128)
    backend: Literal["builtin", "auto", "nmap"] = "builtin"


class InvestigationSettings(Contract):
    enabled: bool = False
    allow_partial_responses: bool = False
    decode_compression: bool = False
    allow_unverified_tls: bool = False
    denied_action_segments: list[str] = Field(
        default_factory=lambda: [
            "delete",
            "remove",
            "destroy",
            "drop",
            "shutdown",
            "restart",
            "logout",
            "purge",
            "reset",
        ],
        max_length=40,
    )
    follow_same_ip_hostnames: bool = False
    discover_artifacts: bool = False
    browser: bool = False
    hint_path_boost: bool = True
    max_artifacts: int = Field(default=12, ge=0, le=32)
    max_path_probes: int = Field(default=40, ge=0, le=2000)
    max_hint_probes: int = Field(default=24, ge=0, le=200)
    max_header_bypass_ips: int = Field(default=8, ge=0, le=32)
    max_cases: int = Field(default=12, ge=1, le=64)
    paths: list[str] = Field(default_factory=default_paths, max_length=2000)
    flag_patterns: list[str] = Field(default_factory=list, max_length=8)
    default_credentials: list[str] = Field(default_factory=default_credential_pairs, max_length=200)


class AISettings(Contract):
    enabled: bool = False
    required: bool = False
    model: Literal["claude-sonnet-5-5", "claude-haiku-5-5", "claude-sonnet-4-6"] = "claude-sonnet-5-5"
    budget_usd: float = Field(default=1.0, ge=0.01, le=20)
    max_calls: int = Field(default=24, ge=1, le=200)
    max_rounds_per_case: int = Field(default=4, ge=1, le=8)
    max_output_tokens: int = Field(default=1000, ge=128, le=4096)
    max_context_bytes: int = Field(default=24000, ge=4000, le=100000)
    timeout: float = Field(default=45, ge=1, le=120)
    gateway_address: str | None = None
    gateway_port: int = Field(default=8090, ge=1024, le=65535)


class ToolSettings(Contract):
    nmap: bool = False
    katana: bool = False
    ffuf: bool = False
    nuclei: bool = False
    binary_tools: bool = False
    proxy_port: int = Field(default=11080, ge=1024, le=65535)
    timeout: float = Field(default=120, ge=1, le=600)


class ScopeManifest(Contract):
    name: str = Field(default="Authorized local assessment", max_length=200)
    mode: Literal["LOCAL_LAB", "DISCOVERY_ONLY", "AUTHORIZED_ASSESSMENT"] = "LOCAL_LAB"
    execution_profile: Literal["local", "native_guarded", "linux_confined"] = "local"
    authorized: bool = False
    authorization_reference: str = Field(default="", max_length=500)
    addresses: list[str] = Field(min_length=1, max_length=64)
    ports: list[int] = Field(default_factory=list, max_length=65535)
    port_ranges: list[str] = Field(default_factory=list, max_length=64)
    excluded_addresses: list[str] = Field(default_factory=list, max_length=64)
    excluded_ports: list[int] = Field(default_factory=list, max_length=65535)
    include_network_broadcast: bool = False
    priority_addresses: list[str] = Field(default_factory=list, max_length=256)
    priority_ports: list[int] = Field(
        default_factory=lambda: [
            80,
            443,
            8000,
            8080,
            8443,
            22,
            21,
            25,
            53,
            110,
            139,
            143,
            445,
            465,
            587,
            993,
            995,
            1433,
            1521,
            3000,
            3306,
            3389,
            5000,
            5432,
            5900,
            6379,
            8008,
            8081,
            8888,
            9000,
            9090,
            9200,
            27017,
        ],
        max_length=256,
    )
    hostnames: dict[str, list[str]] = Field(default_factory=dict)
    seed_urls: list[str] = Field(default_factory=list, max_length=16)
    baseline_urls: list[str] = Field(default_factory=list, max_length=64)
    allowed_paths: list[str] = Field(default_factory=lambda: ["/"])
    excluded_paths: list[str] = Field(default_factory=list)
    permitted_checks: list[str] = Field(default_factory=lambda: ["*"])
    allow_credential_use: bool = False
    allowed_actions: list[
        Literal[
            "http_get",
            "redis_info",
            "input_reflection",
            "credential_validation",
            "session_authentication",
            "service_identification",
            "challenge_interaction",
            "default_credential_probe",
            "injection_probe",
            "header_spoof_probe",
            "protocol_scripting",
        ]
    ] = Field(default_factory=lambda: ["http_get"])
    artifacts: list[str] = Field(default_factory=list, max_length=32)
    artifact_root: str | None = None
    budgets: Budgets = Field(default_factory=Budgets)
    discovery: DiscoverySettings = Field(default_factory=DiscoverySettings)
    investigation: InvestigationSettings = Field(default_factory=InvestigationSettings)
    ai: AISettings = Field(default_factory=AISettings)
    tools: ToolSettings = Field(default_factory=ToolSettings)
    validation_url: str | None = None
    validation_token: str | None = Field(default=None, exclude=True, repr=False)
    validation_address: str | None = None
    enabled: bool = True
    control_port: int | None = Field(default=None, ge=1024, le=65535)

    @model_validator(mode="before")
    @classmethod
    def normalize_public_snapshot(cls, value):
        if isinstance(value, dict) and "control_infrastructure" in value:
            value = dict(value)
            value.pop("control_infrastructure", None)
        return value

    @model_validator(mode="after")
    def validate_scope(self):
        if not self.enabled or not self.authorized or not self.authorization_reference.strip():
            raise ValueError("A frozen enabled scope and explicit authorization reference are required")
        networks = [ipaddress.ip_network(a, strict=True) for a in self.addresses]
        address_count = sum(n.num_addresses for n in networks)
        if address_count > 256:
            raise ValueError("This runner supports at most 256 explicitly scoped addresses")
        if any(p < 1 or p > 65535 for p in self.ports + self.excluded_ports + self.priority_ports):
            raise ValueError("Ports must be in 1..65535")
        self.ports = sorted(set(self.ports))
        selected_ports = self.selected_ports()
        if not selected_ports:
            raise ValueError("At least one non-excluded TCP port must be explicitly configured")
        if self.mode == "LOCAL_LAB" and address_count * len(selected_ports) > 4096:
            raise ValueError("This runner supports at most 4096 address/port pairs")
        if self.mode == "LOCAL_LAB" and self.execution_profile != "local":
            raise ValueError("LOCAL_LAB uses the local execution profile")
        if self.mode == "LOCAL_LAB" and any(
            not n.network_address.is_loopback or not n.broadcast_address.is_loopback for n in networks
        ):
            raise ValueError("LOCAL_LAB permits loopback addresses only")
        if self.mode != "LOCAL_LAB":
            if self.execution_profile == "local":
                raise ValueError("External assessment requires native_guarded or linux_confined execution")
            private = [
                ipaddress.ip_network(n)
                for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
            ]
            if any(n.version != 4 or not any(n.subnet_of(p) for p in private) for n in networks):
                raise ValueError(
                    "External profiles currently support explicitly scoped private IPv4 labs only"
                )
            if "*" in self.permitted_checks:
                raise ValueError("External modes require an explicit permitted_checks list")
            if self.mode == "DISCOVERY_ONLY" and (
                self.allow_credential_use or set(self.allowed_actions) - {"http_get"}
            ):
                raise ValueError("DISCOVERY_ONLY does not allow credentials, reflection probes or Redis INFO")
            if self.allow_credential_use and "credential_validation" not in self.allowed_actions:
                raise ValueError("Credential use requires the credential_validation action")
        if self.investigation.follow_same_ip_hostnames and address_count != 1:
            raise ValueError("Discovered authority pinning requires exactly one scoped address")
        if self.ai.gateway_address:
            gateway = ipaddress.ip_address(self.ai.gateway_address)
            if (
                gateway.version != 4
                or not gateway.is_private
                or gateway.is_unspecified
                or any(gateway in n for n in networks)
            ):
                raise ValueError("AI gateway must be a separate private numeric control-plane address")
        for pattern in self.investigation.flag_patterns:
            import re

            if len(pattern) > 256 or any(c in pattern for c in "()|") or re.search(r"\\[1-9]", pattern):
                raise ValueError("Flag patterns must be bounded character-class expressions")
            re.compile(pattern)
        for exclusion in self.excluded_addresses:
            excluded = ipaddress.ip_network(exclusion, strict=True)
            if not any(excluded.version == n.version and excluded.subnet_of(n) for n in networks):
                raise ValueError("Address exclusions must lie within the declared scope")
        for address in self.priority_addresses:
            ip = ipaddress.ip_address(address)
            if not any(ip in n for n in networks) or any(
                ip in ipaddress.ip_network(e) for e in self.excluded_addresses
            ):
                raise ValueError("Priority addresses must remain within non-excluded scope")
        for name, addresses in self.hostnames.items():
            if not name or any(c in name for c in "/:@\\\r\n") or not addresses:
                raise ValueError("Hostname bindings must be explicit names and numeric addresses")
            for address in addresses:
                ip = ipaddress.ip_address(address)
                if not any(ip in n for n in networks):
                    raise ValueError("Every hostname binding must be within the address allowlist")
                if any(
                    ip.version == e.version and ip in e
                    for e in [ipaddress.ip_network(x) for x in self.excluded_addresses]
                ):
                    raise ValueError("A hostname binding cannot point at an excluded address")
        if any(
            not p.startswith("/") or "\\" in p or ".." in p for p in self.allowed_paths + self.excluded_paths
        ):
            raise ValueError("Path rules must be absolute normalized URL prefixes")
        if self.artifacts and not self.artifact_root:
            raise ValueError("Artifacts require an explicit artifact_root")
        if self.artifact_root and self.artifact_root.startswith(("\\\\", "//")):
            raise ValueError("Network artifact roots are not supported")
        if self.validation_url and not (self.validation_address and self.validation_token):
            raise ValueError("Local validation needs an explicit numeric address and capability token")
        if self.validation_url:
            from urllib.parse import urlsplit

            checker = urlsplit(self.validation_url)
            address = ipaddress.ip_address(self.validation_address)
            if (
                not address.is_loopback
                or checker.scheme != "http"
                or checker.hostname != str(address)
                or checker.port is None
                or checker.path != "/validate"
                or checker.query
                or checker.fragment
                or checker.username is not None
                or checker.password is not None
            ):
                raise ValueError("Evaluator capability must identify the exact loopback /validate endpoint")
        return self

    def selected_ports(self) -> tuple[int, ...]:
        return expand_ports(self.ports, self.port_ranges, self.excluded_ports)

    def action_allowed(self, action: str) -> bool:
        return self.mode == "LOCAL_LAB" or action in self.allowed_actions

    def validated_snapshot(self):
        value = self.model_dump(mode="json")
        value["validation_token"] = self.validation_token
        return type(self).model_validate(value)

    def public(self) -> dict:
        value = self.model_dump(mode="json")
        value.pop("validation_url", None)
        value.pop("validation_address", None)
        value["control_infrastructure"] = []
        if self.control_port:
            value["control_infrastructure"].append(
                {"address": "127.0.0.1", "port": self.control_port, "purpose": "local_control_health"}
            )
        if self.ai.gateway_address:
            value["control_infrastructure"].append(
                {
                    "address": self.ai.gateway_address,
                    "port": self.ai.gateway_port,
                    "purpose": "claude_gateway",
                }
            )
        if self.tools.katana or self.tools.ffuf or self.tools.nuclei:
            value["control_infrastructure"].append(
                {"address": "127.0.0.1", "port": self.tools.proxy_port, "purpose": "scoped_http_proxy"}
            )
        if self.validation_url:
            from urllib.parse import urlsplit

            value["validation_infrastructure"] = {
                "address": self.validation_address,
                "port": urlsplit(self.validation_url).port,
            }
        return value

    def check_allowed(self, check_id: str) -> bool:
        return "*" in self.permitted_checks or check_id in self.permitted_checks


def load_manifest(path: str | Path) -> ScopeManifest:
    path = Path(path).resolve(strict=True)
    if path.stat().st_size > 65536:
        raise ValueError("Manifest exceeds 64 KiB")
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(value, dict):
        value.pop("control_infrastructure", None)
    manifest = ScopeManifest.model_validate(value)
    if manifest.artifact_root:
        root = Path(manifest.artifact_root)
        if not root.is_absolute():
            manifest.artifact_root = str((path.parent / root).resolve())
    return manifest


def dump_manifest(manifest: ScopeManifest, path: Path, *, include_capability: bool = False) -> None:
    value = manifest.model_dump(mode="json")
    if include_capability:
        value["validation_token"] = manifest.validation_token
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
