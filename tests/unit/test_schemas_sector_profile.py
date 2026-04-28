import pytest
from pydantic import ValidationError

from threat_intel.schemas.sector_profile import SectorProfileSchema


def _base(**overrides):
    payload = {
        "id": "finance",
        "name": "Finance",
        "sector": "banking",
        "keywords": ["payment", "swift"],
        "technologies": ["Java", "PostgreSQL"],
        "cwe_priorities": ["CWE-79", "CWE-89"],
        "excluded_keywords": ["minecraft"],
        "compliance": ["PCI-DSS"],
        "priority_boost_keywords": ["wire transfer"],
        "cvss_threshold": 7.5,
    }
    payload.update(overrides)
    return payload


def test_valid_minimal_profile():
    p = SectorProfileSchema(id="saas", name="SaaS", sector="software")
    assert p.id == "saas"
    assert p.cvss_threshold == 7.0
    assert p.keywords == []
    assert p.visibility is None


def test_valid_full_profile():
    p = SectorProfileSchema(**_base())
    assert p.id == "finance"
    assert p.cvss_threshold == 7.5
    assert "Java" in p.technologies


def test_id_must_be_slug():
    with pytest.raises(ValidationError):
        SectorProfileSchema(**_base(id="Has Spaces"))
    with pytest.raises(ValidationError):
        SectorProfileSchema(**_base(id="UPPERCASE"))
    with pytest.raises(ValidationError):
        SectorProfileSchema(**_base(id="-leading-dash"))


def test_id_allows_kebab_and_snake():
    SectorProfileSchema(**_base(id="my-org_2"))


def test_cwe_format_validation():
    with pytest.raises(ValidationError) as exc:
        SectorProfileSchema(**_base(cwe_priorities=["CWE-79", "not-a-cwe"]))
    assert "CWE" in str(exc.value)


def test_cvss_threshold_bounds():
    with pytest.raises(ValidationError):
        SectorProfileSchema(**_base(cvss_threshold=-0.1))
    with pytest.raises(ValidationError):
        SectorProfileSchema(**_base(cvss_threshold=10.1))


def test_extra_fields_forbidden():
    with pytest.raises(ValidationError):
        SectorProfileSchema(**_base(unexpected_field="x"))


def test_duplicate_keywords_rejected_case_insensitive():
    with pytest.raises(ValidationError) as exc:
        SectorProfileSchema(**_base(keywords=["Payment", "payment"]))
    assert "duplicate" in str(exc.value).lower()


def test_keyword_whitespace_stripped_and_blanks_dropped():
    p = SectorProfileSchema(**_base(keywords=["  ach  ", "", "swift"]))
    assert p.keywords == ["ach", "swift"]


def test_visibility_optional_and_literal():
    p = SectorProfileSchema(**_base(visibility="private"))
    assert p.visibility == "private"
    with pytest.raises(ValidationError):
        SectorProfileSchema(**_base(visibility="secret"))
