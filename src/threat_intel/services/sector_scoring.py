"""SectorScoringService — score a Threat against a SectorProfile (M2).

Scoring rules (additive, then clamped to [0, 100]):

    +30  any `technology` mentioned in description or affected_products
    +25  any `keyword` mentioned in title/description/affected_products
    +20  any threat CWE listed in `cwe_priorities`
    +15  threat cvss_score >= profile.cvss_threshold
    +20  any `priority_boost_keyword` mentioned (bonus)
    -30  any `excluded_keyword` mentioned (penalty)

Matching is case-insensitive, whole-word (regex \\b{kw}\\b on lower-cased
input). Keywords are NOT matched against `references` (URLs), to avoid noise
from CDN paths and tracking IDs.

The returned `ScoreResult.breakdown` is JSON-safe and lists every rule's
inputs and points, so callers can persist or display it for transparency.
"""

import re
from dataclasses import dataclass
from typing import Any

from threat_intel.models.sector_profile import SectorProfile
from threat_intel.models.threat import Threat

TECH_POINTS = 30
KEYWORD_POINTS = 25
CWE_POINTS = 20
CVSS_POINTS = 15
BOOST_POINTS = 20
EXCLUSION_PENALTY = -30
SCORE_MIN = 0.0
SCORE_MAX = 100.0


@dataclass(frozen=True)
class ScoreResult:
    score: float
    breakdown: dict[str, Any]


def _find_matches(corpus: str, terms: list[str]) -> list[str]:
    """Case-insensitive whole-word search; returns the original terms found.

    The match is on lower-cased corpus with `re.escape` to handle punctuation
    safely. Empty / whitespace-only terms are silently skipped.
    """
    if not terms or not corpus:
        return []
    lower = corpus.lower()
    matched: list[str] = []
    for term in terms:
        t = term.strip()
        if not t:
            continue
        if re.search(rf"\b{re.escape(t.lower())}\b", lower):
            matched.append(term)
    return matched


def _build_corpus(threat: Threat) -> str:
    """Searchable text: title + description + affected_products joined.

    Multiple spaces are normalized so that '\\b' boundaries behave predictably.
    """
    parts = [
        threat.title or "",
        threat.description or "",
        " ".join(threat.affected_products or []),
    ]
    return re.sub(r"\s+", " ", " ".join(parts)).strip()


class SectorScoringService:
    """Pure scoring: takes hydrated Threat + SectorProfile, returns ScoreResult.

    The service does NOT touch the DB. Caller must ensure `threat.cwes` is
    eagerly loaded (selectinload) when the CWE rule needs to be evaluated.
    """

    @staticmethod
    def calculate_score(threat: Threat, profile: SectorProfile) -> ScoreResult:
        corpus = _build_corpus(threat)

        tech_matches = _find_matches(corpus, profile.technologies)
        kw_matches = _find_matches(corpus, profile.keywords)
        boost_matches = _find_matches(corpus, profile.priority_boost_keywords)
        excl_matches = _find_matches(corpus, profile.excluded_keywords)

        threat_cwe_ids = {c.id for c in (threat.cwes or [])}
        cwe_matches = sorted(threat_cwe_ids & set(profile.cwe_priorities))

        cvss_hit = (
            threat.cvss_score is not None
            and threat.cvss_score >= profile.cvss_threshold
        )

        breakdown: dict[str, Any] = {
            "technology_match": {
                "hit": bool(tech_matches),
                "matched": tech_matches,
                "points": TECH_POINTS if tech_matches else 0,
            },
            "keyword_match": {
                "hit": bool(kw_matches),
                "matched": kw_matches,
                "points": KEYWORD_POINTS if kw_matches else 0,
            },
            "cwe_match": {
                "hit": bool(cwe_matches),
                "matched": cwe_matches,
                "points": CWE_POINTS if cwe_matches else 0,
            },
            "cvss_threshold": {
                "hit": cvss_hit,
                "threshold": profile.cvss_threshold,
                "cvss_score": threat.cvss_score,
                "points": CVSS_POINTS if cvss_hit else 0,
            },
            "priority_boost": {
                "hit": bool(boost_matches),
                "matched": boost_matches,
                "points": BOOST_POINTS if boost_matches else 0,
            },
            "excluded": {
                "hit": bool(excl_matches),
                "matched": excl_matches,
                "points": EXCLUSION_PENALTY if excl_matches else 0,
            },
        }
        raw_total = sum(int(rule["points"]) for rule in breakdown.values())
        final_score = max(SCORE_MIN, min(SCORE_MAX, float(raw_total)))
        breakdown["raw_total"] = raw_total
        breakdown["final_score"] = final_score
        return ScoreResult(score=final_score, breakdown=breakdown)


__all__ = [
    "SectorScoringService",
    "ScoreResult",
    "TECH_POINTS",
    "KEYWORD_POINTS",
    "CWE_POINTS",
    "CVSS_POINTS",
    "BOOST_POINTS",
    "EXCLUSION_PENALTY",
    "SCORE_MIN",
    "SCORE_MAX",
]
