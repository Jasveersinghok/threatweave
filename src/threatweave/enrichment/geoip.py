"""GeoIP enrichment provider — local MaxMind GeoLite2 lookups for IPv4.

Returns country, city, ASN, and organization. Gracefully skips if
the GeoLite2 database is not downloaded.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from threatweave.config import get_settings
from threatweave.enrichment.base import EnrichmentProvider
from threatweave.models.indicators import RawIndicator

logger = logging.getLogger(__name__)


class GeoIpProvider(EnrichmentProvider):
    """Enriches IPv4 indicators with GeoIP data from MaxMind GeoLite2."""

    @property
    def name(self) -> str:
        return "geo"

    @property
    def supported_types(self) -> set[str]:
        return {"ipv4"}

    async def enrich(self, indicator: RawIndicator) -> dict[str, Any]:
        """Look up GeoIP data for an IPv4 address.

        Returns dict with country, city, asn, org.
        """
        try:
            import geoip2.database
        except ImportError:
            logger.warning("geoip2 not installed — skipping GeoIP")
            return {"error": "geoip2_not_installed"}

        settings = get_settings()
        # Look for GeoLite2 databases in the data directory
        data_dir = Path(settings.attack_data_dir).parent
        city_db = data_dir / "geoip" / "GeoLite2-City.mmdb"
        asn_db = data_dir / "geoip" / "GeoLite2-ASN.mmdb"

        result: dict[str, Any] = {"ip": indicator.value}

        # City/Country lookup
        if city_db.exists():
            try:
                with geoip2.database.Reader(str(city_db)) as reader:
                    resp = reader.city(indicator.value)
                    result["country"] = resp.country.name or "Unknown"
                    result["country_code"] = resp.country.iso_code or ""
                    result["city"] = (
                        resp.city.name if resp.city.name else "Unknown"
                    )
                    if resp.location:
                        result["latitude"] = resp.location.latitude
                        result["longitude"] = resp.location.longitude
            except Exception as e:
                logger.debug("GeoIP city lookup failed for %s: %s", indicator.value, e)
                result["city_error"] = str(e)
        else:
            logger.debug(
                "GeoLite2-City.mmdb not found at %s — skipping city lookup",
                city_db,
            )

        # ASN lookup
        if asn_db.exists():
            try:
                with geoip2.database.Reader(str(asn_db)) as reader:
                    asn_resp = reader.asn(indicator.value)
                    result["asn"] = asn_resp.autonomous_system_number
                    result["org"] = (
                        asn_resp.autonomous_system_organization or "Unknown"
                    )
            except Exception as e:
                logger.debug("GeoIP ASN lookup failed for %s: %s", indicator.value, e)
                result["asn_error"] = str(e)
        else:
            logger.debug(
                "GeoLite2-ASN.mmdb not found at %s — skipping ASN lookup",
                asn_db,
            )

        return result
