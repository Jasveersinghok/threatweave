"""Abstract base class for enrichment providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from threatweave.models.indicators import RawIndicator


class EnrichmentProvider(ABC):
    """Base class for all enrichment providers.

    Each provider enriches a specific indicator type with external data.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name used as key in enrichment dict."""

    @property
    @abstractmethod
    def supported_types(self) -> set[str]:
        """Set of IOC types this provider supports."""

    def can_enrich(self, indicator: RawIndicator) -> bool:
        """Check if this provider can enrich the given indicator."""
        return indicator.ioc_type in self.supported_types

    @abstractmethod
    async def enrich(self, indicator: RawIndicator) -> dict[str, Any]:
        """Enrich a single indicator.

        Args:
            indicator: The indicator to enrich.

        Returns:
            Dict of enrichment data.

        Raises:
            Exception: On enrichment failure.
        """
