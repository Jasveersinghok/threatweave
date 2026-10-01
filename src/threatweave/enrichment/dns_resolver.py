"""DNS resolver enrichment provider — resolve domain indicators.

Uses dnspython to resolve A, AAAA, and NS records for domain indicators.
"""

from __future__ import annotations

import logging
from typing import Any

from threatweave.enrichment.base import EnrichmentProvider
from threatweave.models.indicators import RawIndicator

logger = logging.getLogger(__name__)


class DnsResolverProvider(EnrichmentProvider):
    """Enriches domain indicators with DNS resolution data."""

    @property
    def name(self) -> str:
        return "dns"

    @property
    def supported_types(self) -> set[str]:
        return {"domain"}

    async def enrich(self, indicator: RawIndicator) -> dict[str, Any]:
        """Resolve DNS records for a domain.

        Returns dict with a_records, aaaa_records, ns_records.
        """
        import dns.resolver

        domain = indicator.value
        result: dict[str, Any] = {"domain": domain}

        # A records
        try:
            answers = dns.resolver.resolve(domain, "A")
            result["a_records"] = [str(r) for r in answers]
        except Exception:
            result["a_records"] = []

        # AAAA records
        try:
            answers = dns.resolver.resolve(domain, "AAAA")
            result["aaaa_records"] = [str(r) for r in answers]
        except Exception:
            result["aaaa_records"] = []

        # NS records
        try:
            answers = dns.resolver.resolve(domain, "NS")
            result["ns_records"] = [str(r) for r in answers]
        except Exception:
            result["ns_records"] = []

        logger.debug(
            "DNS resolved %s: A=%s, AAAA=%s, NS=%s",
            domain,
            result["a_records"],
            result["aaaa_records"],
            result["ns_records"],
        )

        return result
