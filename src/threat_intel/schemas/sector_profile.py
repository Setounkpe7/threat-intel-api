"""Pydantic schema for sector profile YAML files (M2)."""

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
CWE_RE = re.compile(r"^CWE-\d+$")

Visibility = Literal["public", "private"]


class SectorProfileSchema(BaseModel):
    """Strict schema for profiles/<visibility>/*.yaml files.

    `visibility` is normally inferred from the source folder. If present in
    the YAML it must match the folder; mismatch is the loader's concern.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str
    name: str = Field(min_length=1, max_length=200)
    sector: str = Field(min_length=1, max_length=100)
    description: str | None = None
    visibility: Visibility | None = None

    keywords: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    cwe_priorities: list[str] = Field(default_factory=list)
    excluded_keywords: list[str] = Field(default_factory=list)
    compliance: list[str] = Field(default_factory=list)
    priority_boost_keywords: list[str] = Field(default_factory=list)

    cvss_threshold: float = Field(default=7.0, ge=0.0, le=10.0)

    @field_validator("id")
    @classmethod
    def _validate_slug(cls, v: str) -> str:
        if not SLUG_RE.match(v):
            raise ValueError(f"profile id must be a slug matching {SLUG_RE.pattern!r}, got {v!r}")
        return v

    @field_validator("cwe_priorities")
    @classmethod
    def _validate_cwe_format(cls, v: list[str]) -> list[str]:
        for c in v:
            if not CWE_RE.match(c):
                raise ValueError(f"invalid CWE id: {c!r} (expected 'CWE-NNN')")
        return v

    @field_validator(
        "keywords",
        "technologies",
        "excluded_keywords",
        "priority_boost_keywords",
        "compliance",
        mode="after",
    )
    @classmethod
    def _clean_string_list(cls, v: list[str]) -> list[str]:
        cleaned = [s.strip() for s in v if s and s.strip()]
        lowered = [s.lower() for s in cleaned]
        if len(lowered) != len(set(lowered)):
            raise ValueError("duplicate entries (case-insensitive)")
        return cleaned


__all__ = ["SectorProfileSchema", "Visibility", "SLUG_RE", "CWE_RE"]
