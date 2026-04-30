import uuid
from datetime import UTC, datetime

from threat_intel.models.base import IndicatorType, Severity
from threat_intel.models.sector_profile import SectorProfile
from threat_intel.models.threat import Threat
from threat_intel.models.threat_indicator import ThreatIndicator
from threat_intel.services.sector_scoring import (
    ACTIVELY_EXPLOITED_POINTS,
    KEV_POINTS,
    MULTI_SOURCE_2_POINTS,
    MULTI_SOURCE_3_PLUS_POINTS,
    PACKAGE_MATCH_POINTS,
    RANSOMWARE_POINTS,
    SectorScoringService,
)


def _profile(**overrides):  # type: ignore[no-untyped-def]
    base = dict(
        id="acme",
        name="Acme",
        sector="tech",
        description="",
        keywords=[],
        technologies=["React"],
        cwe_priorities=[],
        excluded_keywords=[],
        compliance=[],
        priority_boost_keywords=[],
        cvss_threshold=7.0,
        visibility="public",
        source_file=None,
        loaded_at=datetime.now(UTC),
    )
    base.update(overrides)
    return SectorProfile(**base)


def _threat(**overrides):  # type: ignore[no-untyped-def]
    base = dict(
        id=uuid.uuid4(),
        threat_type="cve",
        title="x",
        summary="y",
        severity=Severity.high,
        cvss_score=8.0,
        cvss_vector=None,
        cvss_version=None,
        tags=[],
        published_at=datetime.now(UTC),
        last_modified_at=datetime.now(UTC),
        cwes=[],
        sources=[],
    )
    base.update(overrides)
    t = Threat(**base)
    # Ensure runtime-attached collections behave like the relationships at scoring time.
    t.indicators = []  # type: ignore[attr-defined]
    return t


def test_kev_tag_adds_kev_points() -> None:
    threat = _threat(tags=["kev"])
    res = SectorScoringService.calculate_score(threat, _profile())
    assert res.breakdown["kev"]["points"] == KEV_POINTS


def test_actively_exploited_stacks_with_kev_and_ransomware() -> None:
    threat = _threat(tags=["kev", "actively-exploited", "ransomware"])
    res = SectorScoringService.calculate_score(threat, _profile())
    assert res.breakdown["kev"]["points"] == KEV_POINTS
    assert res.breakdown["actively_exploited"]["points"] == ACTIVELY_EXPLOITED_POINTS
    assert res.breakdown["ransomware"]["points"] == RANSOMWARE_POINTS


def test_two_sources_adds_5_three_or_more_adds_10_only() -> None:
    """Multi-source criterion is mutually exclusive: 5 OR 10, never both."""
    from types import SimpleNamespace

    # Bypass SQLAlchemy's relationship instrumentation so we can inject opaque
    # objects — the scoring code only checks len(), never accesses fields.
    def _with_sources(n: int) -> Threat:
        t = _threat()
        object.__setattr__(t, "__dict__", {**t.__dict__, "sources": [SimpleNamespace()] * n})
        return t

    t2 = _with_sources(2)
    res = SectorScoringService.calculate_score(t2, _profile())
    assert res.breakdown["multi_source"]["points"] == MULTI_SOURCE_2_POINTS

    t3 = _with_sources(3)
    res = SectorScoringService.calculate_score(t3, _profile())
    assert res.breakdown["multi_source"]["points"] == MULTI_SOURCE_3_PLUS_POINTS


def test_package_indicator_matches_profile_technology() -> None:
    t = _threat()
    t.indicators = [  # type: ignore[attr-defined]
        ThreatIndicator(
            threat_id=t.id,
            indicator_type=IndicatorType.package,
            value="npm:react",
            first_seen=datetime.now(UTC),
        ),
    ]
    res = SectorScoringService.calculate_score(t, _profile(technologies=["React"]))
    assert res.breakdown["package_match"]["points"] == PACKAGE_MATCH_POINTS
    assert res.breakdown["package_match"]["matched"] == ["npm:react"]


def test_package_indicator_no_match_no_points() -> None:
    t = _threat()
    t.indicators = [  # type: ignore[attr-defined]
        ThreatIndicator(
            threat_id=t.id,
            indicator_type=IndicatorType.package,
            value="npm:lodash",
            first_seen=datetime.now(UTC),
        ),
    ]
    res = SectorScoringService.calculate_score(t, _profile(technologies=["React"]))
    assert res.breakdown["package_match"]["points"] == 0
