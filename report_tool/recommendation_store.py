"""Recommendation template data access with pluggable backends.

JSON is the default source today; backend abstraction keeps the API sqlite-ready.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping, Protocol

_DEFAULT_DATA_PATH = (
    Path(__file__).resolve().parent / "data" / "recommendation_templates.json"
)

_REQUIRED_TOP_LEVEL_KEYS = (
    "RECOMMENDATION_TEMPLATES",
    "EOL_UPGRADE_PATHS",
    "SERVICE_HARDENING",
)


class RecommendationTemplateStoreError(ValueError):
    """Raised when recommendation template data fails validation."""


class RecommendationStoreBackend(Protocol):
    """Backend contract for loading recommendation template data."""

    def load(self) -> dict[str, Any]:
        """Return the raw serialized store payload."""
        ...


@dataclass(frozen=True)
class JsonRecommendationStoreBackend:
    """JSON file backend for recommendation templates."""

    path: Path = _DEFAULT_DATA_PATH

    def load(self) -> dict[str, Any]:
        with self.path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise RecommendationTemplateStoreError(
                "Top-level JSON payload must be an object"
            )
        return payload


@dataclass(frozen=True)
class RecommendationTemplateStore:
    """In-memory validated recommendation template store."""

    templates: Mapping[str, str]
    eol_upgrade_paths: Mapping[str, Mapping[str, str]]
    service_hardening: Mapping[str, str]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RecommendationTemplateStore":
        missing = [key for key in _REQUIRED_TOP_LEVEL_KEYS if key not in payload]
        if missing:
            raise RecommendationTemplateStoreError(
                f"Missing required top-level keys: {', '.join(sorted(missing))}"
            )

        templates = _validate_templates(payload["RECOMMENDATION_TEMPLATES"])
        eol_upgrade_paths = _validate_eol_upgrade_paths(payload["EOL_UPGRADE_PATHS"])
        service_hardening = _validate_str_to_str(
            payload["SERVICE_HARDENING"],
            field_name="SERVICE_HARDENING",
        )

        return cls(
            templates=templates,
            eol_upgrade_paths=eol_upgrade_paths,
            service_hardening=service_hardening,
        )

    @classmethod
    def from_backend(
        cls, backend: RecommendationStoreBackend | None = None
    ) -> "RecommendationTemplateStore":
        selected_backend = backend or JsonRecommendationStoreBackend()
        return cls.from_payload(selected_backend.load())

    def get_template(self, template_key: str) -> str | None:
        return self.templates.get(template_key)


@lru_cache(maxsize=1)
def load_recommendation_template_store() -> RecommendationTemplateStore:
    """Load and cache recommendation template data from the default backend."""

    return RecommendationTemplateStore.from_backend()


def build_recommendation_template_store(
    backend: RecommendationStoreBackend | None = None,
) -> RecommendationTemplateStore:
    """Build an uncached recommendation template store (useful for tests)."""

    return RecommendationTemplateStore.from_backend(backend)


def get_recommendation_templates() -> Mapping[str, str]:
    return load_recommendation_template_store().templates


def get_eol_upgrade_paths() -> Mapping[str, Mapping[str, str]]:
    return load_recommendation_template_store().eol_upgrade_paths


def get_service_hardening() -> Mapping[str, str]:
    return load_recommendation_template_store().service_hardening


def _validate_templates(value: Any) -> dict[str, str]:
    templates = _validate_str_to_str(value, field_name="RECOMMENDATION_TEMPLATES")
    if not templates:
        raise RecommendationTemplateStoreError(
            "RECOMMENDATION_TEMPLATES cannot be empty"
        )
    return templates


def _validate_str_to_str(value: Any, field_name: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise RecommendationTemplateStoreError(f"{field_name} must be an object")

    parsed: dict[str, str] = {}
    for raw_key, raw_item in value.items():
        if not isinstance(raw_key, str):
            raise RecommendationTemplateStoreError(f"{field_name} keys must be strings")
        if not isinstance(raw_item, str):
            raise RecommendationTemplateStoreError(
                f"{field_name}[{raw_key}] must be a string"
            )
        parsed[raw_key] = raw_item
    return parsed


def _validate_eol_upgrade_paths(value: Any) -> dict[str, dict[str, str]]:
    if not isinstance(value, dict):
        raise RecommendationTemplateStoreError("EOL_UPGRADE_PATHS must be an object")

    parsed: dict[str, dict[str, str]] = {}
    for raw_key, raw_item in value.items():
        if not isinstance(raw_key, str):
            raise RecommendationTemplateStoreError(
                "EOL_UPGRADE_PATHS keys must be strings"
            )
        if not isinstance(raw_item, dict):
            raise RecommendationTemplateStoreError(
                f"EOL_UPGRADE_PATHS[{raw_key}] must be an object"
            )

        upgrade_targets = raw_item.get("upgrade_targets")
        template = raw_item.get("template")
        if not isinstance(upgrade_targets, str) or not isinstance(template, str):
            raise RecommendationTemplateStoreError(
                f"EOL_UPGRADE_PATHS[{raw_key}] requires string fields: upgrade_targets, template"
            )

        parsed[raw_key] = {
            "upgrade_targets": upgrade_targets,
            "template": template,
        }

    return parsed
