"""Pydantic models for raw and enriched indicators."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

IOC_TYPES = ("ipv4", "domain", "url", "sha256", "cve")
IocType = Literal["ipv4", "domain", "url", "sha256", "cve"]


def generate_ioc_id(ioc_type: str, value: str, source: str) -> str:
    """Generate a deterministic IOC ID: SHA-256(type || value || source)."""
    raw = f"{ioc_type}||{value}||{source}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class RawIndicator(BaseModel):
    """A single raw indicator of compromise."""

    ioc_id: str = Field(description="Deterministic: SHA-256(type + value + source)")
    ioc_type: IocType = Field(description="Type of IOC")
    value: str = Field(description="Normalized indicator value")
    source: str = Field(description="Origin (otx, file, manual)")
    source_context: str = Field(default="", description="Tags, pulse name, description")
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tlp: str = Field(default="TLP:CLEAR")

    @field_validator("ioc_type")
    @classmethod
    def validate_ioc_type(cls, v: str) -> str:
        if v not in IOC_TYPES:
            msg = f"ioc_type must be one of {IOC_TYPES}, got '{v}'"
            raise ValueError(msg)
        return v


class EnrichedIndicator(BaseModel):
    """An indicator with enrichment data from external providers."""

    indicator: RawIndicator
    enrichment: dict[str, Any] = Field(
        default_factory=dict,
        description="Keyed by provider (nvd, geo, dns)",
    )
    errors: dict[str, str] = Field(
        default_factory=dict,
        description="Provider → error message",
    )
    enrichment_status: Literal["ok", "partial", "failed"] = Field(default="ok")
