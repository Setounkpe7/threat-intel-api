from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, ClassVar

from threat_intel.collectors._sanitize import clean_text
from threat_intel.collectors.base import APIGraphQLCollector, RawEvent
from threat_intel.core.exceptions import CollectorParseError
from threat_intel.models.base import Severity, SourceKind
from threat_intel.schemas.ingest import CollectedEvent, CollectedIndicator

GHSA_ENDPOINT = "https://api.github.com/graphql"

_SEVERITY_MAP = {
    "CRITICAL": Severity.critical,
    "HIGH": Severity.high,
    "MODERATE": Severity.medium,
    "LOW": Severity.low,
}

_QUERY = """
query SecurityAdvisories($since: DateTime!, $cursor: String) {
  securityAdvisories(
    first: 50
    publishedSince: $since
    orderBy: { field: PUBLISHED_AT, direction: ASC }
    after: $cursor
  ) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      updatedAt
      identifiers { type value }
      vulnerabilities(first: 20) {
        nodes {
          package { ecosystem name }
          vulnerableVersionRange
        }
      }
      references { url }
      cwes(first: 10) { nodes { cweId } }
    }
  }
}
"""


def _parse_dt(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


class GitHubAdvisoriesCollector(APIGraphQLCollector):
    source_name: ClassVar[str] = "github_advisories"
    source_kind: ClassVar[SourceKind] = SourceKind.advisory
    base_interval_minutes: ClassVar[int] = 120
    endpoint_url: ClassVar[str] = GHSA_ENDPOINT
    auth_token_env: ClassVar[str] = "GITHUB_TOKEN"  # noqa: S105

    async def fetch(self, since: datetime) -> AsyncIterator[RawEvent]:
        if not self.enabled:
            return
        cursor: str | None = None
        while True:
            data = await self._execute_query(
                _QUERY, {"since": since.isoformat(), "cursor": cursor}
            )
            page = data["data"]["securityAdvisories"]
            for node in page["nodes"]:
                yield RawEvent(
                    external_id=node["ghsaId"],
                    payload=node,
                    fetched_at=datetime.now(UTC),
                )
            if not page["pageInfo"]["hasNextPage"]:
                break
            cursor = page["pageInfo"]["endCursor"]

    def to_event(self, raw: RawEvent) -> CollectedEvent:
        try:
            n: dict[str, Any] = raw.payload
            ghsa_id: str = n["ghsaId"]

            cve_ids = [
                ident["value"]
                for ident in (n.get("identifiers") or [])
                if ident.get("type") == "CVE"
            ]
            packages: list[tuple[str, str]] = []
            for v in (n.get("vulnerabilities") or {}).get("nodes") or []:
                pkg = v.get("package") or {}
                eco = (pkg.get("ecosystem") or "").lower()
                name = pkg.get("name") or ""
                if eco and name:
                    packages.append((eco, name))

            indicators: list[CollectedIndicator] = [
                CollectedIndicator(type="ghsa", value=ghsa_id)
            ]
            for cid in cve_ids:
                indicators.append(CollectedIndicator(type="cve", value=cid))
            for eco, name in packages:
                indicators.append(
                    CollectedIndicator(type="package", value=f"{eco}:{name}"[:512])
                )

            tags = ["github-advisory"]
            for eco, _ in packages:
                if eco not in tags:
                    tags.append(eco)

            cwe_ids = [c["cweId"] for c in (n.get("cwes") or {}).get("nodes") or []]

            severity = _SEVERITY_MAP.get((n.get("severity") or "").upper())
            references = [r["url"] for r in (n.get("references") or []) if r.get("url")]

            return CollectedEvent(
                source_name=self.source_name,
                external_id=ghsa_id,
                title=clean_text(n.get("summary")),
                summary=clean_text(n.get("description")),
                severity=severity,
                cwe_ids=cwe_ids,
                tags=tags,
                indicators=indicators,
                published_at=_parse_dt(n["publishedAt"]),
                last_modified_at=_parse_dt(n["updatedAt"]),
                raw_data={
                    "title": clean_text(n.get("summary")),
                    "summary": clean_text(n.get("description")),
                    "severity": severity.value if severity else None,
                    "cwe_ids": cwe_ids,
                    "references": references,
                    "_payload": n,
                },
            )
        except (KeyError, TypeError, ValueError) as e:
            raise CollectorParseError(
                f"GHSA payload malformed for {raw.external_id}: {e}"
            ) from e
