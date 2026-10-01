"""Tests for indicator normalization.

Tests:
- Refanging (hxxp, [.], [:], meow)
- Validation (good and bad inputs for each type)
- ID determinism
- Dedup
- Full normalize pipeline
"""

from __future__ import annotations

import pytest

from threatweave.collection.normalize import (
    generate_id,
    normalize,
    refang,
    validate_indicator,
)


# ---------------------------------------------------------------------------
# Refanging tests
# ---------------------------------------------------------------------------


class TestRefang:
    """Tests for defang→refang conversion."""

    def test_hxxp_to_http(self) -> None:
        assert refang("hxxp://evil.com") == "http://evil.com"

    def test_hxxps_to_https(self) -> None:
        assert refang("hxxps://evil.com") == "https://evil.com"

    def test_bracket_dot(self) -> None:
        assert refang("evil[.]com") == "evil.com"

    def test_bracket_colon(self) -> None:
        assert refang("http[:]//evil.com") == "http://evil.com"

    def test_dot_text(self) -> None:
        assert refang("evil[dot]com") == "evil.com"

    def test_meow_removed(self) -> None:
        assert refang("httpmeow://evil.com") == "http://evil.com"

    def test_combined(self) -> None:
        result = refang("hxxp[:]//evil[.]example[.]com/path")
        assert result == "http://evil.example.com/path"

    def test_already_clean(self) -> None:
        assert refang("http://clean.example.com") == "http://clean.example.com"

    def test_whitespace_stripped(self) -> None:
        assert refang("  evil.com  ") == "evil.com"


# ---------------------------------------------------------------------------
# Validation tests
# ---------------------------------------------------------------------------


class TestValidation:
    """Tests for type-specific indicator validation."""

    # IPv4
    def test_valid_ipv4(self) -> None:
        assert validate_indicator("ipv4", "192.168.1.1")
        assert validate_indicator("ipv4", "10.0.0.1")
        assert validate_indicator("ipv4", "255.255.255.255")

    def test_invalid_ipv4(self) -> None:
        assert not validate_indicator("ipv4", "256.1.1.1")
        assert not validate_indicator("ipv4", "1.1.1")
        assert not validate_indicator("ipv4", "not.an.ip.address")
        assert not validate_indicator("ipv4", "")

    # Domain
    def test_valid_domain(self) -> None:
        assert validate_indicator("domain", "example.com")
        assert validate_indicator("domain", "sub.example.co.uk")
        assert validate_indicator("domain", "evil-domain.example.com")

    def test_invalid_domain(self) -> None:
        assert not validate_indicator("domain", "not a domain")
        assert not validate_indicator("domain", "-invalid.com")
        assert not validate_indicator("domain", "")

    # URL
    def test_valid_url(self) -> None:
        assert validate_indicator("url", "http://example.com")
        assert validate_indicator("url", "https://example.com/path?q=1")

    def test_invalid_url(self) -> None:
        assert not validate_indicator("url", "ftp://not-http.com")
        assert not validate_indicator("url", "just-text")
        assert not validate_indicator("url", "")

    # SHA-256
    def test_valid_sha256(self) -> None:
        good = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert validate_indicator("sha256", good)

    def test_invalid_sha256(self) -> None:
        assert not validate_indicator("sha256", "abc123")  # Too short
        assert not validate_indicator("sha256", "g" * 64)  # Invalid hex
        assert not validate_indicator("sha256", "")

    # CVE
    def test_valid_cve(self) -> None:
        assert validate_indicator("cve", "CVE-2024-3400")
        assert validate_indicator("cve", "CVE-2023-46805")

    def test_invalid_cve(self) -> None:
        assert not validate_indicator("cve", "CVE-2024")  # Missing number
        assert not validate_indicator("cve", "not-a-cve")
        assert not validate_indicator("cve", "")

    # Unknown type
    def test_unknown_type_fails(self) -> None:
        assert not validate_indicator("unknown", "anything")


# ---------------------------------------------------------------------------
# ID generation tests
# ---------------------------------------------------------------------------


class TestIdGeneration:
    """Tests for deterministic ID generation."""

    def test_same_input_same_id(self) -> None:
        id1 = generate_id("ipv4", "1.2.3.4", "manual")
        id2 = generate_id("ipv4", "1.2.3.4", "manual")
        assert id1 == id2

    def test_different_input_different_id(self) -> None:
        id1 = generate_id("ipv4", "1.2.3.4", "manual")
        id2 = generate_id("ipv4", "5.6.7.8", "manual")
        assert id1 != id2

    def test_different_source_different_id(self) -> None:
        id1 = generate_id("ipv4", "1.2.3.4", "manual")
        id2 = generate_id("ipv4", "1.2.3.4", "otx")
        assert id1 != id2

    def test_id_is_hex_string(self) -> None:
        ioc_id = generate_id("ipv4", "1.2.3.4", "manual")
        assert len(ioc_id) == 64
        assert all(c in "0123456789abcdef" for c in ioc_id)


# ---------------------------------------------------------------------------
# Full normalize pipeline tests
# ---------------------------------------------------------------------------


class TestNormalize:
    """Tests for the full normalization pipeline."""

    def test_valid_indicators_pass(self) -> None:
        raw = [
            {"type": "ipv4", "value": "1.2.3.4"},
            {"type": "domain", "value": "evil.com"},
        ]
        result = normalize(raw)
        assert len(result) == 2

    def test_invalid_filtered_out(self) -> None:
        raw = [
            {"type": "ipv4", "value": "not-an-ip"},
            {"type": "domain", "value": "evil.com"},
        ]
        result = normalize(raw)
        assert len(result) == 1
        assert result[0]["ioc_type"] == "domain"

    def test_dedup(self) -> None:
        raw = [
            {"type": "ipv4", "value": "1.2.3.4", "source": "manual"},
            {"type": "ipv4", "value": "1.2.3.4", "source": "manual"},
        ]
        result = normalize(raw)
        assert len(result) == 1

    def test_refanging_applied(self) -> None:
        raw = [{"type": "domain", "value": "evil[.]example[.]com"}]
        result = normalize(raw)
        assert len(result) == 1
        assert result[0]["value"] == "evil.example.com"

    def test_preserves_context(self) -> None:
        raw = [
            {
                "type": "ipv4",
                "value": "1.2.3.4",
                "context": "C2 server",
            }
        ]
        result = normalize(raw)
        assert result[0]["source_context"] == "C2 server"

    def test_empty_input(self) -> None:
        assert normalize([]) == []
