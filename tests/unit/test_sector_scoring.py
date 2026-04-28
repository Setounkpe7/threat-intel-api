"""Unit tests for the SectorScoringService — one test per rule + combined cases."""

import uuid
from datetime import UTC, datetime

import pytest

from threat_intel.models.base import Severity
from threat_intel.models.cwe import CWE
from threat_intel.models.sector_profile import SectorProfile
from threat_intel.models.threat import Threat
from threat_intel.services.sector_scoring import (
    BOOST_POINTS,
    CVSS_POINTS,
    CWE_POINTS,
    EXCLUSION_PENALTY,
    KEYWORD_POINTS,
    TECH_POINTS,
    SectorScoringService,
)


def _threat(
    *,
    title: str = "Vulnerability",
    description: str = "A remote attacker can exploit this issue.",
    affected_products: list[str] | None = None,
    references: list[str] | None = None,
    cvss_score: float | None = 8.0,
    cwe_ids: list[str] | None = None,
) -> Threat:
    now = datetime.now(UTC)
    t = Threat(
        id=uuid.uuid4(),
        source_id=1,
        external_id="CVE-TEST-1",
        title=title,
        description=description,
        severity=Severity.high,
        cvss_score=cvss_score,
        cvss_vector=None,
        cvss_version=None,
        affected_products=affected_products or [],
        references=references or [],
        published_at=now,
        last_modified_at=now,
        raw_data={},
    )
    t.cwes = [CWE(id=cid, name="X") for cid in (cwe_ids or [])]
    return t


def _profile(
    *,
    keywords: list[str] | None = None,
    technologies: list[str] | None = None,
    cwe_priorities: list[str] | None = None,
    excluded_keywords: list[str] | None = None,
    priority_boost_keywords: list[str] | None = None,
    cvss_threshold: float = 7.0,
) -> SectorProfile:
    return SectorProfile(
        id="test",
        name="Test",
        sector="x",
        keywords=keywords or [],
        technologies=technologies or [],
        cwe_priorities=cwe_priorities or [],
        excluded_keywords=excluded_keywords or [],
        priority_boost_keywords=priority_boost_keywords or [],
        compliance=[],
        cvss_threshold=cvss_threshold,
        loaded_at=datetime.now(UTC),
    )


# ---------- one test per rule ----------


def test_technology_match_in_description():
    t = _threat(description="Apache Tomcat is vulnerable to XSS.")
    p = _profile(technologies=["Tomcat"], cvss_threshold=99.0)  # disable other rules
    r = SectorScoringService.calculate_score(t, p)
    assert r.breakdown["technology_match"]["hit"] is True
    assert r.breakdown["technology_match"]["matched"] == ["Tomcat"]
    assert r.score == TECH_POINTS


def test_technology_match_in_affected_products():
    t = _threat(
        description="Generic CVE description.",
        affected_products=["cpe:2.3:a:apache:tomcat:9.0"],
    )
    p = _profile(technologies=["Tomcat"], cvss_threshold=99.0)
    r = SectorScoringService.calculate_score(t, p)
    assert r.score == TECH_POINTS


def test_keyword_match_in_title():
    t = _threat(title="Payment processing flaw", description="x", cvss_score=0.0)
    p = _profile(keywords=["payment"], cvss_threshold=99.0)
    r = SectorScoringService.calculate_score(t, p)
    assert r.breakdown["keyword_match"]["hit"] is True
    assert r.score == KEYWORD_POINTS


def test_cwe_match():
    t = _threat(cwe_ids=["CWE-79"], cvss_score=0.0)
    p = _profile(cwe_priorities=["CWE-79", "CWE-89"], cvss_threshold=99.0)
    r = SectorScoringService.calculate_score(t, p)
    assert r.breakdown["cwe_match"]["matched"] == ["CWE-79"]
    assert r.score == CWE_POINTS


def test_cvss_threshold_met():
    t = _threat(cvss_score=8.0)
    p = _profile(cvss_threshold=7.0)
    r = SectorScoringService.calculate_score(t, p)
    assert r.breakdown["cvss_threshold"]["hit"] is True
    assert r.score == CVSS_POINTS


def test_cvss_below_threshold_no_points():
    t = _threat(cvss_score=5.0)
    p = _profile(cvss_threshold=7.0)
    r = SectorScoringService.calculate_score(t, p)
    assert r.breakdown["cvss_threshold"]["hit"] is False
    assert r.score == 0


def test_cvss_none_no_points():
    t = _threat(cvss_score=None)
    p = _profile(cvss_threshold=7.0)
    r = SectorScoringService.calculate_score(t, p)
    assert r.breakdown["cvss_threshold"]["hit"] is False
    assert r.score == 0


def test_priority_boost_match():
    t = _threat(description="An RCE in the wire transfer module.", cvss_score=0.0)
    p = _profile(priority_boost_keywords=["wire transfer"], cvss_threshold=99.0)
    r = SectorScoringService.calculate_score(t, p)
    assert r.breakdown["priority_boost"]["hit"] is True
    assert r.score == BOOST_POINTS


def test_excluded_keyword_applies_penalty_clamped_to_zero():
    t = _threat(description="Minecraft mod vulnerability.", cvss_score=0.0)
    p = _profile(excluded_keywords=["minecraft"], cvss_threshold=99.0)
    r = SectorScoringService.calculate_score(t, p)
    assert r.breakdown["excluded"]["hit"] is True
    assert r.breakdown["excluded"]["points"] == EXCLUSION_PENALTY
    assert r.breakdown["raw_total"] == EXCLUSION_PENALTY
    assert r.score == 0  # clamped


# ---------- combined / boundary cases ----------


def test_full_match_clamped_to_100():
    t = _threat(
        title="Critical RCE",
        description="Apache Tomcat payment wire transfer flaw.",
        affected_products=["cpe:2.3:a:apache:tomcat:9.0"],
        cvss_score=9.8,
        cwe_ids=["CWE-79"],
    )
    p = _profile(
        keywords=["payment"],
        technologies=["Tomcat"],
        cwe_priorities=["CWE-79"],
        priority_boost_keywords=["wire transfer"],
        cvss_threshold=7.0,
    )
    r = SectorScoringService.calculate_score(t, p)
    assert r.breakdown["raw_total"] == 110  # 30+25+20+15+20
    assert r.score == 100.0  # clamped


def test_exclusion_offsets_other_signals():
    t = _threat(
        description="Apache Tomcat payment minecraft mod RCE.",
        cvss_score=0.0,
    )
    p = _profile(
        keywords=["payment"],
        technologies=["Tomcat"],
        excluded_keywords=["minecraft"],
        cvss_threshold=99.0,
    )
    r = SectorScoringService.calculate_score(t, p)
    # 30 (tech) + 25 (kw) - 30 (excl) = 25
    assert r.score == 25


def test_case_insensitive_match():
    t = _threat(description="JAVA serialization issue.", cvss_score=0.0)
    p = _profile(technologies=["java"], cvss_threshold=99.0)
    r = SectorScoringService.calculate_score(t, p)
    assert r.score == TECH_POINTS


def test_whole_word_boundary_java_does_not_match_javascript():
    t = _threat(description="JavaScript prototype pollution.", cvss_score=0.0)
    p = _profile(technologies=["Java"], cvss_threshold=99.0)
    r = SectorScoringService.calculate_score(t, p)
    assert r.breakdown["technology_match"]["hit"] is False
    assert r.score == 0


def test_keyword_with_punctuation_handled():
    t = _threat(description="Issue affects e-commerce checkout.", cvss_score=0.0)
    p = _profile(keywords=["checkout"], cvss_threshold=99.0)
    r = SectorScoringService.calculate_score(t, p)
    assert r.breakdown["keyword_match"]["hit"] is True
    assert r.score == KEYWORD_POINTS


def test_keywords_not_matched_against_references_urls():
    """The 'java.html' in a reference URL should NOT trigger the technology rule."""
    t = _threat(
        description="Generic flaw.",
        references=["https://example.test/security/java.html"],
        cvss_score=0.0,
    )
    p = _profile(technologies=["java"], cvss_threshold=99.0)
    r = SectorScoringService.calculate_score(t, p)
    assert r.breakdown["technology_match"]["hit"] is False
    assert r.score == 0


def test_breakdown_structure_complete():
    t = _threat(cvss_score=0.0)
    p = _profile(cvss_threshold=99.0)
    r = SectorScoringService.calculate_score(t, p)
    expected_rules = {
        "technology_match",
        "keyword_match",
        "cwe_match",
        "cvss_threshold",
        "priority_boost",
        "excluded",
    }
    assert expected_rules.issubset(r.breakdown.keys())
    assert "raw_total" in r.breakdown
    assert "final_score" in r.breakdown
    for rule in expected_rules:
        assert "hit" in r.breakdown[rule]
        assert "points" in r.breakdown[rule]


def test_breakdown_is_json_serializable():
    import json

    t = _threat(description="Apache Tomcat issue", cwe_ids=["CWE-79"])
    p = _profile(technologies=["Tomcat"], cwe_priorities=["CWE-79"], cvss_threshold=7.0)
    r = SectorScoringService.calculate_score(t, p)
    # Should round-trip via JSON without TypeError (relevant for the JSON column).
    payload = json.dumps(r.breakdown)
    assert json.loads(payload)["final_score"] == r.score


def test_no_cwes_attached_does_not_match():
    t = _threat(cwe_ids=[], cvss_score=0.0)
    p = _profile(cwe_priorities=["CWE-79"], cvss_threshold=99.0)
    r = SectorScoringService.calculate_score(t, p)
    assert r.breakdown["cwe_match"]["hit"] is False
    assert r.score == 0


def test_empty_profile_yields_zero():
    t = _threat(cvss_score=10.0)
    p = _profile(cvss_threshold=11.0)  # threshold above max so cvss rule fails too
    r = SectorScoringService.calculate_score(t, p)
    assert r.score == 0
    assert r.breakdown["raw_total"] == 0


def test_duplicate_keyword_in_corpus_counts_once():
    t = _threat(description="payment payment payment.", cvss_score=0.0)
    p = _profile(keywords=["payment"], cvss_threshold=99.0)
    r = SectorScoringService.calculate_score(t, p)
    assert r.breakdown["keyword_match"]["matched"] == ["payment"]
    assert r.score == KEYWORD_POINTS


@pytest.mark.parametrize(
    "score,threshold,expected_hit",
    [(7.0, 7.0, True), (7.1, 7.0, True), (6.9, 7.0, False), (0.0, 0.0, True)],
)
def test_cvss_threshold_boundary(score, threshold, expected_hit):
    t = _threat(cvss_score=score)
    p = _profile(cvss_threshold=threshold)
    r = SectorScoringService.calculate_score(t, p)
    assert r.breakdown["cvss_threshold"]["hit"] is expected_hit
