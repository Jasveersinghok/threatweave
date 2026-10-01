"""Pydantic model for a Case — a group of related enriched indicators."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from threatweave.models.indicators import EnrichedIndicator


class Case(BaseModel):
    """A case groups related enriched indicators for analysis."""

    case_id: str = Field(description="Unique case identifier")
    indicators: list[EnrichedIndicator] = Field(
        description="Enriched indicators belonging to this case"
    )
    grouping_reason: str = Field(
        description="Why these indicators are grouped together"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC)
    )
