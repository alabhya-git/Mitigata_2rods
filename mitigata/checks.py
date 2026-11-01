from __future__ import annotations

from importlib.resources import files
from pathlib import Path

import yaml
from pydantic import Field

from .config import Contract

PRIMITIVES = {
    "directory_listing",
    "credential_literal",
    "verbose_error",
    "basic_auth",
    "binary_credential",
    "elf_pie",
    "redis_info",
    "json_document",
    "git_head",
    "source_map",
    "api_document",
    "structured_secret",
    "form_auth",
    "browser_xss",
    "default_credentials",
    "path_traversal",
    "sql_injection",
    "ssti",
    "open_redirect",
    "http_service_unauth",
    "header_access_bypass",
    "xor_encoded_credential",
    "sensitive_disclosure",
    "protocol_capture",
}


class Recipe(Contract):
    id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,80}$")
    surface: str = Field(pattern=r"^(web|network|binary)$")
    primitive: str
    title: str = Field(max_length=200)
    claim: str = Field(max_length=1000)
    severity: str = Field(pattern=r"^(info|low|medium|high)$")
    remediation: str = Field(max_length=1000)
    path_prefix: str = Field(default="/", max_length=512, pattern=r"^/")
    required_keys: list[str] = Field(default_factory=list, max_length=8)


class CheckRegistry:
    def __init__(self, extra_path: Path | None = None):
        source = files("mitigata").joinpath("data/checks.yaml").read_text(encoding="utf-8")
        self.recipes = {}
        self._load(yaml.safe_load(source))
        if extra_path:
            if extra_path.stat().st_size > 65536:
                raise ValueError("Check pack exceeds 64 KiB")
            self._load(yaml.safe_load(extra_path.read_text(encoding="utf-8")))

    def _load(self, value):
        if not isinstance(value, dict) or value.get("version") != 1:
            raise ValueError("Unsupported check-pack version")
        for raw in value.get("recipes", []):
            recipe = Recipe.model_validate(raw)
            if recipe.primitive not in PRIMITIVES:
                raise ValueError("Recipes may compose only registered verification primitives")
            if recipe.id in self.recipes:
                raise ValueError("Check pack cannot override an existing check identity")
            self.recipes[recipe.id] = recipe

    def for_surface(self, surface):
        return [r for r in self.recipes.values() if r.surface == surface]

    def by_primitive(self, primitive):
        return [r for r in self.recipes.values() if r.primitive == primitive]

    def public(self):
        return [r.model_dump() for r in self.recipes.values()]
