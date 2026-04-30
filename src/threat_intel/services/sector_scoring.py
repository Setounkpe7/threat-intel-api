"""SectorScoringService — score a Threat against a SectorProfile (M2/M3a).

Scoring rules (additive, then clamped to [0, 100]):

    +30  any `technology` mentioned in title/summary/affected_products (via sources)
    +25  any `keyword` mentioned in title/summary/affected_products
    +20  any threat CWE listed in `cwe_priorities`
    +15  threat cvss_score >= profile.cvss_threshold
    +20  any `priority_boost_keyword` mentioned (bonus)
    -30  any `excluded_keyword` mentioned (penalty)

    (M3a additions)
    +25  threat has tag `kev`
    +15  threat has tag `actively-exploited`
    +15  threat has tag `ransomware`
    +5   threat is documented by exactly 2 sources
    +10  threat is documented by 3+ sources (replaces the +5; mutually exclusive)
    +20  at least one indicator of type `package` matches a profile `technology`

Matching is case-insensitive, whole-word (regex \\b{kw}\\b on lower-cased
input). Keywords are NOT matched against `references` (URLs), to avoid noise
from CDN paths and tracking IDs.

The returned `ScoreResult.breakdown` is JSON-safe and lists every rule's
inputs and points, so callers can persist or display it for transparency.
"""

import re
from dataclasses import dataclass
from typing import Any

from threat_intel.models.base import IndicatorType
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

KEV_POINTS = 25
ACTIVELY_EXPLOITED_POINTS = 15
RANSOMWARE_POINTS = 15
MULTI_SOURCE_2_POINTS = 5
MULTI_SOURCE_3_PLUS_POINTS = 10
PACKAGE_MATCH_POINTS = 20


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
    """Searchable text: title + summary + affected_products (from sources) joined.

    Multiple spaces are normalized so that '\\b' boundaries behave predictably.
    """
    products: list[str] = []
    for ts in threat.sources or []:
        for p in getattr(ts, "affected_products", None) or []:
            if p not in products:
                products.append(p)
    parts = [
        threat.title or "",
        threat.summary or "",
        " ".join(products),
    ]
    return re.sub(r"\s+", " ", " ".join(parts)).strip()


class SectorScoringService:
    """Pure scoring: takes hydrated Threat + SectorProfile, returns ScoreResult.

    The service does NOT touch the DB. Caller must ensure `threat.cwes`,
    `threat.sources`, and `threat.indicators` are eagerly loaded (selectinload)
    when the respective rules need to be evaluated.
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

        cvss_hit = threat.cvss_score is not None and threat.cvss_score >= profile.cvss_threshold

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

        # --- M3a additions ---
        tags = set(threat.tags or [])
        kev_points = KEV_POINTS if "kev" in tags else 0
        ae_points = ACTIVELY_EXPLOITED_POINTS if "actively-exploited" in tags else 0
        rw_points = RANSOMWARE_POINTS if "ransomware" in tags else 0

        n_sources = len(threat.sources or [])
        if n_sources >= 3:
            ms_points = MULTI_SOURCE_3_PLUS_POINTS
        elif n_sources == 2:
            ms_points = MULTI_SOURCE_2_POINTS
        else:
            ms_points = 0

        pkg_matched: list[str] = []
        techs_lower = {t.lower() for t in (profile.technologies or [])}
        for ind in getattr(threat, "indicators", None) or []:
            if ind.indicator_type != IndicatorType.package:
                continue
            value_lower = ind.value.lower()
            name_part = value_lower.split(":", 1)[-1] if ":" in value_lower else value_lower
            tokens = set(re.split(r"[\/:\-]", name_part))
            tokens.add(name_part)
            if any(t and t in tokens for t in techs_lower):
                pkg_matched.append(ind.value)
        pkg_points = PACKAGE_MATCH_POINTS if pkg_matched else 0

        breakdown["kev"] = {"hit": "kev" in tags, "points": kev_points}
        breakdown["actively_exploited"] = {"hit": "actively-exploited" in tags, "points": ae_points}
        breakdown["ransomware"] = {"hit": "ransomware" in tags, "points": rw_points}
        breakdown["multi_source"] = {
            "hit": n_sources >= 2,
            "source_count": n_sources,
            "points": ms_points,
        }
        breakdown["package_match"] = {
            "hit": bool(pkg_matched),
            "matched": pkg_matched,
            "points": pkg_points,
        }

        raw_total = sum(
            int(rule["points"])
            for k, rule in breakdown.items()
            if k not in {"raw_total", "final_score"}
        )
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
    "KEV_POINTS",
    "ACTIVELY_EXPLOITED_POINTS",
    "RANSOMWARE_POINTS",
    "MULTI_SOURCE_2_POINTS",
    "MULTI_SOURCE_3_PLUS_POINTS",
    "PACKAGE_MATCH_POINTS",
]
