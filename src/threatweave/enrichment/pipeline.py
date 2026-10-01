"""Enrichment pipeline — async orchestrator for all enrichment providers.

For each indicator, runs applicable providers concurrently with
asyncio.gather. Catches per-provider errors, sets enrichment_status
to partial/failed, and returns list[EnrichedIndicator].
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from threatweave.enrichment.base import EnrichmentProvider
from threatweave.enrichment.dns_resolver import DnsResolverProvider
from threatweave.enrichment.geoip import GeoIpProvider
from threatweave.enrichment.nvd import NvdProvider
from threatweave.enrichment.otx import OtxProvider
from threatweave.models.indicators import EnrichedIndicator, RawIndicator

logger = logging.getLogger(__name__)


def get_default_providers() -> list[EnrichmentProvider]:
    """Return the default set of enrichment providers."""
    return [
        NvdProvider(),
        GeoIpProvider(),
        DnsResolverProvider(),
        OtxProvider(),
    ]


async def _enrich_single_indicator(
    indicator: RawIndicator,
    providers: list[EnrichmentProvider],
) -> EnrichedIndicator:
    """Enrich a single indicator with all applicable providers.

    Runs providers concurrently and catches per-provider errors.
    """
    applicable = [p for p in providers if p.can_enrich(indicator)]

    if not applicable:
        return EnrichedIndicator(
            indicator=indicator,
            enrichment={},
            enrichment_status="ok",
        )

    # Run all applicable providers concurrently
    tasks = [p.enrich(indicator) for p in applicable]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    enrichment: dict[str, Any] = {}
    errors: dict[str, str] = {}

    for provider, result in zip(applicable, results, strict=False):
        if isinstance(result, Exception):
            logger.warning(
                "Provider '%s' failed for %s: %s",
                provider.name,
                indicator.value,
                result,
            )
            errors[provider.name] = str(result)
        else:
            enrichment[provider.name] = result

    # Determine status
    if errors and not enrichment:
        status = "failed"
    elif errors:
        status = "partial"
    else:
        status = "ok"

    return EnrichedIndicator(
        indicator=indicator,
        enrichment=enrichment,
        errors=errors,
        enrichment_status=status,  # type: ignore[arg-type]
    )


async def enrich_indicators(
    indicators: list[RawIndicator],
    providers: list[EnrichmentProvider] | None = None,
    concurrency: int = 1,
) -> list[EnrichedIndicator]:
    """Enrich a batch of indicators using all available providers.

    Args:
        indicators: List of raw indicators to enrich.
        providers: Custom providers list (defaults to all built-in providers).
        concurrency: Max concurrent enrichment tasks.

    Returns:
        List of EnrichedIndicator with enrichment data and error tracking.
    """
    if providers is None:
        providers = get_default_providers()

    logger.info(
        "Enriching %d indicators with %d providers",
        len(indicators),
        len(providers),
    )

    # Use semaphore to limit concurrency
    semaphore = asyncio.Semaphore(concurrency)

    async def _limited_enrich(ind: RawIndicator) -> EnrichedIndicator:
        async with semaphore:
            return await _enrich_single_indicator(ind, providers)

    enriched = await asyncio.gather(
        *[_limited_enrich(ind) for ind in indicators]
    )

    ok_count = sum(1 for e in enriched if e.enrichment_status == "ok")
    partial_count = sum(1 for e in enriched if e.enrichment_status == "partial")
    failed_count = sum(1 for e in enriched if e.enrichment_status == "failed")

    logger.info(
        "Enrichment complete: %d ok, %d partial, %d failed",
        ok_count,
        partial_count,
        failed_count,
    )

    return list(enriched)
