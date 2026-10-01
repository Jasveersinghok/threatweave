"""NVD enrichment provider — query NVD API 2.0 for CVE indicators.

Extracts CVSS score, CWE, description, and affected products.
Includes in-memory caching (TTL: 24h) and rate limit handling.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx
import asyncio

from threatweave.config import get_settings
from threatweave.enrichment.base import EnrichmentProvider
from threatweave.models.indicators import RawIndicator

logger = logging.getLogger(__name__)

_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Simple in-memory cache: cve_id → (timestamp, data)
_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_CACHE_TTL = 86400  # 24 hours


def _get_from_cache(cve_id: str) -> dict[str, Any] | None:
    """Return cached result if within TTL."""
    entry = _cache.get(cve_id)
    if entry is None:
        return None
    ts, data = entry
    if time.time() - ts > _CACHE_TTL:
        del _cache[cve_id]
        return None
    return data


def _put_in_cache(cve_id: str, data: dict[str, Any]) -> None:
    """Store result in cache with current timestamp."""
    _cache[cve_id] = (time.time(), data)


class NvdProvider(EnrichmentProvider):
    """Enriches CVE indicators with NVD data."""

    @property
    def name(self) -> str:
        return "nvd"

    @property
    def supported_types(self) -> set[str]:
        return {"cve"}

    async def enrich(self, indicator: RawIndicator) -> dict[str, Any]:
        """Query NVD API 2.0 for CVE details.

        Returns dict with cvss_score, cwe, description, affected_products.
        """
        cve_id = indicator.value.upper()

        # Check cache first
        cached = _get_from_cache(cve_id)
        if cached is not None:
            logger.debug("NVD cache hit for %s", cve_id)
            return cached

        settings = get_settings()
        headers: dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        if settings.nvd_api_key and settings.nvd_api_key != "your_nvd_api_key_here":
            headers["apiKey"] = settings.nvd_api_key
        else:
            # Without an API key, NVD allows 5 requests per 30 seconds (~6s per request)
            logger.info("NVD API key missing, applying 6.5s delay to respect rate limits.")
            await asyncio.sleep(6.5)

        params = {"cveId": cve_id}

        max_retries = 2
        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    response = await client.get(
                        _NVD_BASE_URL, params=params, headers=headers
                    )
                    if response.status_code in (403, 429, 502, 503, 504):
                        logger.warning("NVD rate limit/overload (HTTP %d) hit for %s (attempt %d). Retrying...", response.status_code, cve_id, attempt+1)
                        await asyncio.sleep(3 ** attempt)
                        continue
                    elif response.status_code == 404:
                        logger.warning("NVD 404 for %s, skipping.", cve_id)
                        return {"cve_id": cve_id, "found": False}
                        
                    response.raise_for_status()
                    data = response.json()
                    break  # Success
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.error("NVD permanently failed for %s after %d retries: %r", cve_id, max_retries, e)
                    return {"error": repr(e), "cve_id": cve_id}
                
                logger.warning("NVD connection error for %s: %r. Retrying (%d/%d)...", cve_id, e, attempt+1, max_retries)
                await asyncio.sleep(3 ** attempt)
        else:
            return {"error": "max_retries_exceeded", "cve_id": cve_id}

        # Parse response
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {"cve_id": cve_id, "found": False}

        cve_data = vulns[0].get("cve", {})
        result = _parse_nvd_response(cve_id, cve_data)

        _put_in_cache(cve_id, result)
        return result


def _parse_nvd_response(
    cve_id: str, cve_data: dict[str, Any]
) -> dict[str, Any]:
    """Extract relevant fields from NVD CVE response."""
    # Description
    descriptions = cve_data.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    # CVSS score (try v3.1 first, then v3.0, then v2.0)
    metrics = cve_data.get("metrics", {})
    cvss_score = None
    cvss_version = None

    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_version = cvss_data.get("version", version_key)
            break

    # CWE
    weaknesses = cve_data.get("weaknesses", [])
    cwe_ids: list[str] = []
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            cwe_id = desc.get("value", "")
            if cwe_id.startswith("CWE-"):
                cwe_ids.append(cwe_id)

    # Affected products (CPE match strings)
    configurations = cve_data.get("configurations", [])
    affected: list[str] = []
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if criteria:
                    affected.append(criteria)

    return {
        "cve_id": cve_id,
        "found": True,
        "description": description[:500],
        "cvss_score": cvss_score,
        "cvss_version": cvss_version,
        "cwe": cwe_ids,
        "affected_products": affected[:10],
    }
