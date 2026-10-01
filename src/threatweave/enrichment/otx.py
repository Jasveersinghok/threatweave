"""OTX enrichment provider using direct HTTP API."""
import logging
import asyncio
import httpx
from typing import Any
from threatweave.config import get_settings
from threatweave.enrichment.base import EnrichmentProvider
from threatweave.models.indicators import RawIndicator

logger = logging.getLogger(__name__)

class OtxProvider(EnrichmentProvider):
    @property
    def name(self) -> str:
        return "otx"

    @property
    def supported_types(self) -> set[str]:
        return {"ipv4", "domain", "url", "sha256"}

    async def enrich(self, indicator: RawIndicator) -> dict[str, Any]:
        settings = get_settings()
        if not settings.otx_api_key or settings.otx_api_key == "your_otx_api_key_here":
            return {"error": "no_api_key"}

        otx_type = indicator.ioc_type
        api_type = ""
        if otx_type == "ipv4":
            api_type = "IPv4"
        elif otx_type == "domain":
            api_type = "domain"
        elif otx_type == "sha256":
            api_type = "file"
        else:
            return {"error": "unsupported_type"}

        url = f"https://otx.alienvault.com/api/v1/indicators/{api_type}/{indicator.value}/general"
        headers = {
            "X-OTX-API-KEY": settings.otx_api_key,
            "User-Agent": "Mozilla/5.0"
        }

        max_retries = 2
        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    response = await client.get(url, headers=headers)
                    
                    if response.status_code in (429, 403, 502, 503, 504):
                        logger.warning(f"OTX API overloaded/rate-limited (HTTP {response.status_code}). Retrying ({attempt+1}/{max_retries})...")
                        await asyncio.sleep(2 ** attempt)
                        continue
                        
                    if response.status_code == 404:
                        return {"found": False}
                        
                    response.raise_for_status()
                    data = response.json()
                    
                    pulses = data.get("pulse_info", {}).get("pulses", [])
                    names = [p.get("name") for p in pulses if p.get("name")]
                    tags = []
                    for p in pulses:
                        tags.extend(p.get("tags", []))
                    
                    return {
                        "pulses": names[:5],
                        "tags": list(set(tags))[:10],
                        "found": bool(pulses)
                    }
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.error("OTX request permanently failed for %s after %d retries: %r", indicator.value, max_retries, e)
                    return {"error": repr(e)}
                
                logger.warning("OTX connection error for %s: %r. Retrying (%d/%d)...", indicator.value, e, attempt+1, max_retries)
                await asyncio.sleep(3 ** attempt)
                
        return {"error": "max_retries_exceeded"}
