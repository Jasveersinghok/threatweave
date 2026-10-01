"""Smoke tests for the ATT&CK knowledge base.

Tests:
1. ATT&CK ingestion parses 200+ techniques
2. Embedding + retrieval: "phishing email with malicious attachment"
   should return T1566 or T1566.001 in top-5
3. Exact lookup: T1566.001 returns data, T9999.999 returns None
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from threatweave.knowledge.attack_ingest import (
    download_attack_bundle,
    load_techniques,
    parse_techniques,
    save_techniques,
)
from threatweave.knowledge.embeddings import (
    build_index,
    get_embedding_model,
    search_techniques,
)
from threatweave.intelligence.tools.attack_lookup import (
    lookup_technique,
    reset_index,
)

# Use a temp directory for test artifacts
_FIXTURE_LOADED = False
_techniques: list[dict] = []


@pytest.fixture(scope="module")
def attack_techniques(tmp_path_factory: pytest.TempPathFactory) -> list[dict]:
    """Download and parse ATT&CK techniques (cached for the module)."""
    global _FIXTURE_LOADED, _techniques  # noqa: PLW0603
    if not _FIXTURE_LOADED:
        bundle = download_attack_bundle()
        _techniques = parse_techniques(bundle)
        _FIXTURE_LOADED = True
    return _techniques


@pytest.fixture(scope="module")
def techniques_file(
    tmp_path_factory: pytest.TempPathFactory,
    attack_techniques: list[dict],
) -> Path:
    """Save parsed techniques to a temp file."""
    tmp_dir = tmp_path_factory.mktemp("attack_data")
    output = tmp_dir / "techniques.json"
    save_techniques(attack_techniques, output)
    return output


@pytest.fixture(scope="module")
def qdrant_index(attack_techniques: list[dict]):
    """Build a Qdrant in-memory index from parsed techniques."""
    from qdrant_client import QdrantClient

    client = QdrantClient(location=":memory:")
    build_index(
        attack_techniques,
        collection_name="test_attack_techniques",
        client=client,
    )
    return client


class TestAttackIngestion:
    """Tests for ATT&CK STIX bundle parsing."""

    def test_parses_200_plus_techniques(self, attack_techniques: list[dict]) -> None:
        """ATT&CK ingestion should parse at least 200 techniques."""
        assert len(attack_techniques) >= 200, (
            f"Expected 200+ techniques, got {len(attack_techniques)}"
        )

    def test_technique_has_required_fields(self, attack_techniques: list[dict]) -> None:
        """Each parsed technique must have the essential fields."""
        required_fields = {"technique_id", "name", "description", "tactics", "platforms"}
        for tech in attack_techniques[:10]:  # Spot-check first 10
            missing = required_fields - set(tech.keys())
            assert not missing, f"Technique {tech.get('technique_id')} missing fields: {missing}"

    def test_technique_id_format(self, attack_techniques: list[dict]) -> None:
        """Technique IDs should match the T####(.###) pattern."""
        import re

        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        for tech in attack_techniques:
            assert pattern.match(tech["technique_id"]), (
                f"Invalid technique ID format: {tech['technique_id']}"
            )

    def test_save_and_load_roundtrip(
        self, attack_techniques: list[dict], techniques_file: Path
    ) -> None:
        """Saving and loading techniques should produce identical data."""
        loaded = load_techniques(techniques_file)
        assert len(loaded) == len(attack_techniques)
        assert loaded[0]["technique_id"] == attack_techniques[0]["technique_id"]


class TestEmbeddingAndRetrieval:
    """Tests for ATT&CK technique embedding and semantic search."""

    def test_phishing_query_returns_t1566(self, qdrant_index) -> None:
        """Querying for phishing should return T1566 or T1566.001 in top-5."""
        results = search_techniques(
            query="phishing email with malicious attachment",
            top_k=5,
            collection_name="test_attack_techniques",
            client=qdrant_index,
        )
        assert len(results) == 5, f"Expected 5 results, got {len(results)}"

        technique_ids = {r["technique_id"] for r in results}
        assert "T1566" in technique_ids or "T1566.001" in technique_ids, (
            f"Expected T1566 or T1566.001 in results, got: {technique_ids}"
        )

    def test_results_have_scores(self, qdrant_index) -> None:
        """Search results should include similarity scores."""
        results = search_techniques(
            query="credential dumping",
            top_k=3,
            collection_name="test_attack_techniques",
            client=qdrant_index,
        )
        for r in results:
            assert "score" in r
            assert isinstance(r["score"], float)
            assert 0 <= r["score"] <= 1.0

    def test_results_have_full_metadata(self, qdrant_index) -> None:
        """Each search result should carry full technique metadata."""
        results = search_techniques(
            query="lateral movement using remote services",
            top_k=1,
            collection_name="test_attack_techniques",
            client=qdrant_index,
        )
        assert len(results) >= 1
        result = results[0]
        for key in ("technique_id", "name", "tactics", "platforms", "description"):
            assert key in result, f"Missing key '{key}' in result"


class TestExactLookup:
    """Tests for ATT&CK exact ID lookup."""

    def test_lookup_existing_technique(self, techniques_file: Path, monkeypatch) -> None:
        """Looking up T1566.001 should return technique data."""
        # Point the settings to our temp file
        monkeypatch.setenv("ATTACK_TECHNIQUES_FILE", str(techniques_file))
        reset_index()

        # Patch settings to use temp file
        from threatweave.config import Settings
        monkeypatch.setattr(
            "threatweave.intelligence.tools.attack_lookup.get_settings",
            lambda: Settings(attack_techniques_file=str(techniques_file)),
        )
        reset_index()

        result = lookup_technique("T1566.001")
        assert result is not None, "T1566.001 should exist in ATT&CK data"
        assert result["technique_id"] == "T1566.001"
        assert result["name"]  # Should have a name

    def test_lookup_nonexistent_technique(self, techniques_file: Path, monkeypatch) -> None:
        """Looking up T9999.999 should return None."""
        from threatweave.config import Settings
        monkeypatch.setattr(
            "threatweave.intelligence.tools.attack_lookup.get_settings",
            lambda: Settings(attack_techniques_file=str(techniques_file)),
        )
        reset_index()

        result = lookup_technique("T9999.999")
        assert result is None, "T9999.999 should NOT exist in ATT&CK data"
