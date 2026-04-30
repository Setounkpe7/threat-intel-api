# M3a — Multi-Source + Cross-Source Dedup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add CISA KEV and GitHub Security Advisories collectors with cross-source deduplication on top of NVD, refactor the collector hierarchy, and extend the sectoral scoring engine to consume the new signals.

**Architecture:** Refactor `BaseCollector` into `APIRestCollector` and `APIGraphQLCollector`. Replace the per-source `Threat` row model with a unified `Threat` + `ThreatSource` (M:N) + `ThreatIndicator` (lookup) trio. A `CollectedEvent` DTO is the single contract between collectors and `IngestService.process()`. Per-field canonical resolution (NVD → GHSA → KEV priority) is rejouable via `recompute_canonical()`.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2.0 async, Alembic, httpx (REST + GraphQL), bleach (sanitization), pytest + respx, structlog.

**Spec:** `docs/superpowers/specs/2026-04-29-m3a-multi-source-cross-dedup-design.md`

---

## Sequencing rules

- TDD throughout: failing test → implementation → green → commit.
- One Alembic migration for the whole M3a schema change. **Validate with the user after Task 2 (migration) before continuing to Task 3.** This is the only gating checkpoint.
- After each task: run the full test suite (`pytest -q`) and verify it stays green. M1 and M2 tests must never regress.
- Commit at the granularity shown in each task. No batch commits.

---

## Task 1: Add `bleach` dependency + `GITHUB_TOKEN` setting

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/threat_intel/core/config.py`
- Modify: `.env.example`
- Test: `tests/unit/test_config.py` (extend if exists, else create)

- [ ] **Step 1: Write the failing test for `GITHUB_TOKEN` setting**

`tests/unit/test_config.py`:

```python
import os
import pytest
from threat_intel.core.config import Settings


def test_github_token_optional_default_none(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    settings = Settings()
    assert settings.github_token is None


def test_github_token_loaded_from_env(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test_abc")
    settings = Settings()
    assert settings.github_token == "ghp_test_abc"


def test_github_token_strips_inline_comment(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test_abc # personal token")
    settings = Settings()
    assert settings.github_token == "ghp_test_abc"
```

- [ ] **Step 2: Run the tests, verify they fail**

Run: `pytest tests/unit/test_config.py::test_github_token_optional_default_none -v`
Expected: FAIL with `AttributeError: 'Settings' object has no attribute 'github_token'`.

- [ ] **Step 3: Add the field to `Settings`**

Edit `src/threat_intel/core/config.py`. After `nvd_fetch_interval_minutes`:

```python
    # GitHub Security Advisories collector. Optional — leave unset to disable.
    # Generate at https://github.com/settings/tokens — no scope required.
    github_token: str | None = None
    github_advisories_fetch_interval_minutes: int = 120
    cisa_kev_fetch_interval_minutes: int = 360
```

Add `"github_token"` to the `_strip_optional_string` validator's field list:

```python
    @field_validator("nvd_api_key", "admin_api_key", "sentry_dsn", "github_token", mode="before")
```

- [ ] **Step 4: Run the tests, verify they pass**

Run: `pytest tests/unit/test_config.py -v`
Expected: PASS.

- [ ] **Step 5: Add `bleach` to `pyproject.toml`**

In `[project] dependencies` (or `[tool.uv]` section, follow existing pattern), append `"bleach>=6.1.0"`. Run:

```bash
uv lock
uv sync
```

- [ ] **Step 6: Update `.env.example`**

Append:

```dotenv
# GitHub Security Advisories collector (M3a). Optional.
# Generate at https://github.com/settings/tokens — no scope required for public advisories.
# Without this set, the collector is disabled at startup.
GITHUB_TOKEN=
```

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml uv.lock src/threat_intel/core/config.py tests/unit/test_config.py .env.example
git commit -m "feat(config): add GITHUB_TOKEN setting and bleach dependency for M3a"
```

---

## Task 2: Schema migration `0003_m3a_cross_source_schema`

**Files:**
- Create: `src/threat_intel/models/threat_source.py`
- Create: `src/threat_intel/models/threat_indicator.py`
- Create: `src/threat_intel/models/collector_run.py`
- Modify: `src/threat_intel/models/threat.py`
- Modify: `src/threat_intel/models/source.py`
- Modify: `src/threat_intel/models/base.py` (add `IndicatorType` enum)
- Modify: `src/threat_intel/models/__init__.py`
- Create: `alembic/versions/0003_m3a_cross_source_schema.py`
- Test: `tests/unit/test_migration_0003.py`

- [ ] **Step 1: Add `IndicatorType` enum to `models/base.py`**

Append to `src/threat_intel/models/base.py`:

```python
import enum


class IndicatorType(str, enum.Enum):
    cve = "cve"
    ghsa = "ghsa"
    cpe = "cpe"
    package = "package"
    ip = "ip"
    domain = "domain"
    url = "url"
    md5 = "md5"
    sha1 = "sha1"
    sha256 = "sha256"


class CollectorRunStatus(str, enum.Enum):
    running = "running"
    success = "success"
    failure = "failure"
    partial = "partial"
```

- [ ] **Step 2: Create `models/threat_source.py`**

```python
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from threat_intel.models.base import GUID, Base, TimestampMixin, UtcDateTime

if TYPE_CHECKING:
    from threat_intel.models.source import Source
    from threat_intel.models.threat import Threat


class ThreatSource(Base, TimestampMixin):
    __tablename__ = "threat_source"
    __table_args__ = (
        Index("ix_threat_source_source_external", "source_id", "external_id"),
    )

    threat_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("threat.id", ondelete="CASCADE"), primary_key=True
    )
    source_id: Mapped[int] = mapped_column(
        ForeignKey("source.id", ondelete="CASCADE"), primary_key=True
    )
    external_id: Mapped[str] = mapped_column(String(128))

    first_seen_at: Mapped[datetime] = mapped_column(UtcDateTime())
    last_seen_at: Mapped[datetime] = mapped_column(UtcDateTime())

    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    affected_products: Mapped[list[str]] = mapped_column(JSON, default=list)
    references: Mapped[list[str]] = mapped_column("references_json", JSON, default=list)
    raw_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    threat: Mapped["Threat"] = relationship(back_populates="sources")
    source: Mapped["Source"] = relationship()
```

- [ ] **Step 3: Create `models/threat_indicator.py`**

```python
import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from threat_intel.models.base import GUID, Base, IndicatorType, TimestampMixin, UtcDateTime


class ThreatIndicator(Base, TimestampMixin):
    __tablename__ = "threat_indicator"
    __table_args__ = (
        UniqueConstraint("threat_id", "indicator_type", "value", name="uq_threat_indicator"),
        Index("ix_threat_indicator_lookup", "indicator_type", "value"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    threat_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("threat.id", ondelete="CASCADE"), index=True
    )
    indicator_type: Mapped[IndicatorType]
    value: Mapped[str] = mapped_column(String(512))
    first_seen: Mapped[datetime] = mapped_column(UtcDateTime())
    confidence: Mapped[int] = mapped_column(Integer, default=100)
```

- [ ] **Step 4: Create `models/collector_run.py`**

```python
from datetime import datetime

from sqlalchemy import ForeignKey, Index, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from threat_intel.models.base import Base, CollectorRunStatus, TimestampMixin, UtcDateTime


class CollectorRun(Base, TimestampMixin):
    __tablename__ = "collector_run"
    __table_args__ = (
        Index("ix_collector_run_source_started", "source_id", "started_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("source.id", ondelete="CASCADE"))
    started_at: Mapped[datetime] = mapped_column(UtcDateTime())
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    status: Mapped[CollectorRunStatus] = mapped_column(default=CollectorRunStatus.running)
    events_fetched: Mapped[int] = mapped_column(Integer, default=0)
    events_new: Mapped[int] = mapped_column(Integer, default=0)
    events_updated: Mapped[int] = mapped_column(Integer, default=0)
    events_failed: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
```

- [ ] **Step 5: Refactor `models/threat.py`** (drop `source_id`, `external_id`, `affected_products`, `references`, `raw_data`; add `threat_type`, `summary`, `tags`)

```python
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from threat_intel.models.base import GUID, Base, Severity, TimestampMixin, UtcDateTime
from threat_intel.models.cwe import threat_cwe

if TYPE_CHECKING:
    from threat_intel.models.cwe import CWE
    from threat_intel.models.threat_source import ThreatSource


class Threat(Base, TimestampMixin):
    __tablename__ = "threat"
    __table_args__ = (
        Index("ix_threat_published_at", "published_at"),
        Index("ix_threat_severity", "severity"),
        Index("ix_threat_threat_type", "threat_type"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    threat_type: Mapped[str] = mapped_column(String(32), default="cve")

    title: Mapped[str] = mapped_column(Text)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(default=Severity.unknown)

    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cvss_version: Mapped[str | None] = mapped_column(String(8), nullable=True)

    tags: Mapped[list[str]] = mapped_column(JSON, default=list)

    published_at: Mapped[datetime] = mapped_column(UtcDateTime())
    last_modified_at: Mapped[datetime] = mapped_column(UtcDateTime())

    cwes: Mapped[list["CWE"]] = relationship(secondary=threat_cwe, lazy="selectin")
    sources: Mapped[list["ThreatSource"]] = relationship(back_populates="threat", lazy="selectin")
```

Removed columns: `source_id`, `external_id`, `affected_products`, `references`, `raw_data`. Removed `description` (replaced by `summary`).

- [ ] **Step 6: Extend `models/source.py`**

Append to the existing `Source` class:

```python
    consecutive_failures: Mapped[int] = mapped_column(default=0)
    base_interval_minutes: Mapped[int] = mapped_column(default=60)
    current_interval_minutes: Mapped[int] = mapped_column(default=60)
    next_run_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
```

- [ ] **Step 7: Wire models into `models/__init__.py`**

Add imports for `ThreatSource`, `ThreatIndicator`, `CollectorRun` so Alembic autogen sees them.

- [ ] **Step 8: Generate the empty migration scaffold**

```bash
.venv/bin/alembic revision -m "m3a_cross_source_schema"
```

Rename the resulting file to `alembic/versions/0003_m3a_cross_source_schema.py` and edit `revision = "0003_m3a_cross_source_schema"`. Set `down_revision = "994ed3da0eaa"` (the M2 revision id).

- [ ] **Step 9: Write the migration `upgrade()` body**

```python
def upgrade() -> None:
    bind = op.get_bind()

    # 1. New tables
    op.create_table(
        "threat_source",
        sa.Column("threat_id", threat_intel.models.base.GUID(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("external_id", sa.String(length=128), nullable=False),
        sa.Column("first_seen_at", threat_intel.models.base.UtcDateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", threat_intel.models.base.UtcDateTime(timezone=True), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("affected_products", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("references_json", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("raw_data", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", threat_intel.models.base.UtcDateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", threat_intel.models.base.UtcDateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["threat_id"], ["threat.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_id"], ["source.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("threat_id", "source_id"),
    )
    op.create_index("ix_threat_source_source_external", "threat_source", ["source_id", "external_id"])

    op.create_table(
        "threat_indicator",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("threat_id", threat_intel.models.base.GUID(), nullable=False),
        sa.Column("indicator_type", sa.Enum("cve", "ghsa", "cpe", "package", "ip", "domain", "url", "md5", "sha1", "sha256", name="indicatortype"), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("first_seen", threat_intel.models.base.UtcDateTime(timezone=True), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("created_at", threat_intel.models.base.UtcDateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", threat_intel.models.base.UtcDateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["threat_id"], ["threat.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("threat_id", "indicator_type", "value", name="uq_threat_indicator"),
    )
    op.create_index("ix_threat_indicator_threat_id", "threat_indicator", ["threat_id"])
    op.create_index("ix_threat_indicator_lookup", "threat_indicator", ["indicator_type", "value"])

    op.create_table(
        "collector_run",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("started_at", threat_intel.models.base.UtcDateTime(timezone=True), nullable=False),
        sa.Column("finished_at", threat_intel.models.base.UtcDateTime(timezone=True), nullable=True),
        sa.Column("status", sa.Enum("running", "success", "failure", "partial", name="collectorrunstatus"), nullable=False, server_default="running"),
        sa.Column("events_fetched", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("events_new", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("events_updated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("events_failed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("created_at", threat_intel.models.base.UtcDateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", threat_intel.models.base.UtcDateTime(timezone=True), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.ForeignKeyConstraint(["source_id"], ["source.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_collector_run_source_started", "collector_run", ["source_id", "started_at"])

    # 2. Extend `source`
    with op.batch_alter_table("source") as batch:
        batch.add_column(sa.Column("consecutive_failures", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("base_interval_minutes", sa.Integer(), nullable=False, server_default="60"))
        batch.add_column(sa.Column("current_interval_minutes", sa.Integer(), nullable=False, server_default="60"))
        batch.add_column(sa.Column("next_run_at", threat_intel.models.base.UtcDateTime(timezone=True), nullable=True))

    # 3. Extend `threat` (add new columns first; drop old after data migration)
    with op.batch_alter_table("threat") as batch:
        batch.add_column(sa.Column("threat_type", sa.String(length=32), nullable=False, server_default="cve"))
        batch.add_column(sa.Column("summary", sa.Text(), nullable=True))
        batch.add_column(sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"))

    # 4. Data migration
    _migrate_data(bind)

    # 5. Drop old columns from `threat`
    with op.batch_alter_table("threat") as batch:
        batch.drop_constraint("uq_threat_source_external", type_="unique")
        batch.drop_index("ix_threat_source_id")  # autogenerated index name; verify in 0001
        batch.drop_column("source_id")
        batch.drop_column("external_id")
        batch.drop_column("description")
        batch.drop_column("affected_products")
        batch.drop_column("references_json")
        batch.drop_column("raw_data")
    op.create_index("ix_threat_threat_type", "threat", ["threat_type"])
```

(Note: the index name `ix_threat_source_id` may differ — open `alembic/versions/0001_initial.py` and use the exact name.)

- [ ] **Step 10: Implement `_migrate_data(bind)`**

Inline at the top of the migration file:

```python
def _migrate_data(bind: sa.engine.Connection) -> None:
    """Backfill ThreatSource and ThreatIndicator from existing single-source threats.

    Existing rows assume `source_id` points at the NVD source. For each threat,
    insert one threat_source row carrying the per-source data, then extract
    indicators from raw_data (CVE-ID + CPEs).
    """
    threats = bind.execute(
        sa.text(
            "SELECT id, source_id, external_id, affected_products, "
            "references_json, raw_data, last_modified_at, created_at, description "
            "FROM threat"
        )
    ).all()

    now_sql = sa.text("CURRENT_TIMESTAMP")

    for row in threats:
        threat_id, source_id, external_id, affected_products, refs, raw_data, last_mod, created_at, description = row

        # threat_source: preserve per-source metadata
        bind.execute(
            sa.text(
                "INSERT INTO threat_source (threat_id, source_id, external_id, "
                "first_seen_at, last_seen_at, tags, affected_products, "
                "references_json, raw_data, created_at, updated_at) "
                "VALUES (:tid, :sid, :ext, :first, :last, :tags, :prod, :refs, :raw, "
                "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
            {
                "tid": threat_id,
                "sid": source_id,
                "ext": external_id,
                "first": created_at,
                "last": last_mod,
                "tags": '["nvd"]',
                "prod": affected_products if isinstance(affected_products, str) else _json_dump(affected_products),
                "refs": refs if isinstance(refs, str) else _json_dump(refs),
                "raw": raw_data if isinstance(raw_data, str) else _json_dump(raw_data),
            },
        )

        # threat_indicator: CVE
        bind.execute(
            sa.text(
                "INSERT INTO threat_indicator (threat_id, indicator_type, value, "
                "first_seen, confidence, created_at, updated_at) "
                "VALUES (:tid, 'cve', :val, :first, 100, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
            {"tid": threat_id, "val": external_id, "first": created_at},
        )

        # threat_indicator: CPEs from raw_data.configurations
        cpes = _extract_cpes(raw_data)
        for cpe in cpes:
            bind.execute(
                sa.text(
                    "INSERT INTO threat_indicator (threat_id, indicator_type, value, "
                    "first_seen, confidence, created_at, updated_at) "
                    "VALUES (:tid, 'cpe', :val, :first, 100, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) "
                    "ON CONFLICT DO NOTHING"
                ),
                {"tid": threat_id, "val": cpe[:512], "first": created_at},
            )

        # backfill `summary` from old `description`
        bind.execute(
            sa.text("UPDATE threat SET summary = :s, threat_type = 'cve' WHERE id = :tid"),
            {"s": description, "tid": threat_id},
        )

    # Seed/update sources table
    bind.execute(
        sa.text(
            "UPDATE source SET base_interval_minutes = 60, current_interval_minutes = 60 "
            "WHERE name = 'nvd'"
        )
    )
    bind.execute(
        sa.text(
            "INSERT INTO source (name, kind, url, enabled, base_interval_minutes, "
            "current_interval_minutes, consecutive_failures, created_at, updated_at) "
            "VALUES ('cisa_kev', 'cve_feed', "
            "'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', "
            "1, 360, 360, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) "
            "ON CONFLICT (name) DO NOTHING"
        )
    )
    bind.execute(
        sa.text(
            "INSERT INTO source (name, kind, url, enabled, base_interval_minutes, "
            "current_interval_minutes, consecutive_failures, created_at, updated_at) "
            "VALUES ('github_advisories', 'cve_feed', "
            "'https://api.github.com/graphql', "
            "1, 120, 120, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) "
            "ON CONFLICT (name) DO NOTHING"
        )
    )


def _json_dump(v):
    import json
    return json.dumps(v if v is not None else [])


def _extract_cpes(raw_data) -> list[str]:
    import json
    if isinstance(raw_data, str):
        try:
            raw_data = json.loads(raw_data)
        except (TypeError, ValueError):
            return []
    if not isinstance(raw_data, dict):
        return []
    cve = raw_data.get("cve") or raw_data
    cpes: list[str] = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                c = match.get("criteria")
                if c and c not in cpes:
                    cpes.append(c)
    return cpes
```

- [ ] **Step 11: Implement `downgrade()`** (schema-only, data is not preserved)

```python
def downgrade() -> None:
    op.drop_index("ix_threat_threat_type", table_name="threat")
    with op.batch_alter_table("threat") as batch:
        batch.drop_column("tags")
        batch.drop_column("summary")
        batch.drop_column("threat_type")
        batch.add_column(sa.Column("source_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("external_id", sa.String(length=128), nullable=True))
        batch.add_column(sa.Column("description", sa.Text(), nullable=True))
        batch.add_column(sa.Column("affected_products", sa.JSON(), nullable=False, server_default="[]"))
        batch.add_column(sa.Column("references_json", sa.JSON(), nullable=False, server_default="[]"))
        batch.add_column(sa.Column("raw_data", sa.JSON(), nullable=False, server_default="{}"))

    with op.batch_alter_table("source") as batch:
        batch.drop_column("next_run_at")
        batch.drop_column("current_interval_minutes")
        batch.drop_column("base_interval_minutes")
        batch.drop_column("consecutive_failures")

    op.drop_index("ix_collector_run_source_started", table_name="collector_run")
    op.drop_table("collector_run")
    op.drop_index("ix_threat_indicator_lookup", table_name="threat_indicator")
    op.drop_index("ix_threat_indicator_threat_id", table_name="threat_indicator")
    op.drop_table("threat_indicator")
    op.drop_index("ix_threat_source_source_external", table_name="threat_source")
    op.drop_table("threat_source")
    sa.Enum(name="indicatortype").drop(op.get_bind(), checkfirst=False)
    sa.Enum(name="collectorrunstatus").drop(op.get_bind(), checkfirst=False)
```

- [ ] **Step 12: Write the migration roundtrip test**

`tests/unit/test_migration_0003.py`:

```python
import json
import uuid

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text


@pytest.fixture
def alembic_cfg(tmp_path):
    db_path = tmp_path / "test.db"
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return cfg, db_path


def test_migration_0003_upgrades_with_existing_nvd_data(alembic_cfg):
    cfg, db_path = alembic_cfg
    # Bring schema up to M2 only
    command.upgrade(cfg, "994ed3da0eaa")

    eng = create_engine(f"sqlite:///{db_path}")
    with eng.begin() as conn:
        conn.execute(text(
            "INSERT INTO source (name, kind, url, enabled, created_at, updated_at) "
            "VALUES ('nvd', 'cve_feed', 'https://nvd.example/', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        ))
        src_id = conn.execute(text("SELECT id FROM source WHERE name='nvd'")).scalar_one()
        threat_id = str(uuid.uuid4())
        raw = json.dumps({"cve": {"id": "CVE-2024-9999", "configurations": [
            {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}]}]}
        ]}})
        conn.execute(text(
            "INSERT INTO threat (id, source_id, external_id, title, description, severity, "
            "affected_products, references_json, raw_data, published_at, last_modified_at, "
            "created_at, updated_at) VALUES (:id, :sid, 'CVE-2024-9999', 'title', 'desc', 'high', "
            "'[]', '[]', :raw, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        ), {"id": threat_id, "sid": src_id, "raw": raw})

    # Run M3a migration
    command.upgrade(cfg, "0003_m3a_cross_source_schema")

    with eng.connect() as conn:
        ts = conn.execute(text("SELECT external_id, tags FROM threat_source")).fetchall()
        assert len(ts) == 1
        assert ts[0][0] == "CVE-2024-9999"
        assert "nvd" in json.loads(ts[0][1])

        ind = conn.execute(text(
            "SELECT indicator_type, value FROM threat_indicator ORDER BY indicator_type, value"
        )).fetchall()
        types = {row[0] for row in ind}
        assert "cve" in types
        assert "cpe" in types

        seeded = conn.execute(text(
            "SELECT name FROM source ORDER BY name"
        )).fetchall()
        names = {row[0] for row in seeded}
        assert {"nvd", "cisa_kev", "github_advisories"} <= names

        cols = conn.execute(text("PRAGMA table_info(threat)")).fetchall()
        col_names = {c[1] for c in cols}
        assert "source_id" not in col_names
        assert "external_id" not in col_names
        assert "raw_data" not in col_names
        assert "summary" in col_names
        assert "tags" in col_names
        assert "threat_type" in col_names


def test_migration_0003_downgrade_round_trip(alembic_cfg):
    cfg, _ = alembic_cfg
    command.upgrade(cfg, "0003_m3a_cross_source_schema")
    command.downgrade(cfg, "994ed3da0eaa")
    command.upgrade(cfg, "0003_m3a_cross_source_schema")
```

- [ ] **Step 13: Run the migration tests**

```bash
pytest tests/unit/test_migration_0003.py -v
```

Expected: PASS for both. Fix any column-name mismatches against `alembic/versions/0001_initial.py` (especially the dropped index name).

- [ ] **Step 14: Run the full M1 + M2 test suite**

```bash
pytest -q
```

Expected: model imports succeed, but **most M1/M2 tests will fail** because `Threat.source_id` no longer exists, `upsert_threat` references removed fields, etc. **This is expected.** Mark these as the work for the next tasks.

- [ ] **Step 15: Commit**

```bash
git add src/threat_intel/models/ alembic/versions/0003_m3a_cross_source_schema.py tests/unit/test_migration_0003.py
git commit -m "feat(db): M3a schema — threat_sources, threat_indicators, collector_runs, source extensions"
```

- [ ] **Step 16: GATE — Pause for user validation**

Stop here. Confirm with the user that the migration scaffolding is correct before continuing. Show the commit and the test output. Do not proceed to Task 3 without an explicit go-ahead.

---

## Task 3: `CollectedEvent` DTO and indicator schema

**Files:**
- Create: `src/threat_intel/schemas/ingest.py`
- Test: `tests/unit/schemas/test_ingest.py`

- [ ] **Step 1: Write the failing tests**

`tests/unit/schemas/test_ingest.py`:

```python
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from threat_intel.models.base import Severity
from threat_intel.schemas.ingest import CollectedEvent, CollectedIndicator


def test_collected_indicator_rejects_unknown_type():
    with pytest.raises(ValidationError):
        CollectedIndicator(type="unknown", value="x")


def test_collected_event_minimum_fields():
    ev = CollectedEvent(
        source_name="nvd",
        external_id="CVE-2024-1",
        title="Foo",
        published_at=datetime.now(UTC),
        last_modified_at=datetime.now(UTC),
        raw_data={},
    )
    assert ev.tags == []
    assert ev.indicators == []
    assert ev.severity is None


def test_collected_event_round_trip():
    payload = {
        "source_name": "github_advisories",
        "external_id": "GHSA-1234-5678-90ab",
        "title": "Foo",
        "summary": "bar",
        "severity": "high",
        "cvss_score": 7.5,
        "tags": ["github-advisory", "npm"],
        "indicators": [
            {"type": "cve", "value": "CVE-2024-9"},
            {"type": "package", "value": "npm:lodash"},
        ],
        "published_at": "2026-04-01T00:00:00+00:00",
        "last_modified_at": "2026-04-02T00:00:00+00:00",
        "raw_data": {"k": "v"},
    }
    ev = CollectedEvent.model_validate(payload)
    assert ev.severity == Severity.high
    assert ev.indicators[0].type == "cve"
```

- [ ] **Step 2: Run tests, verify failure**

Run: `pytest tests/unit/schemas/test_ingest.py -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Implement `schemas/ingest.py`**

```python
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from threat_intel.models.base import Severity

IndicatorTypeLiteral = Literal[
    "cve", "ghsa", "cpe", "package", "ip", "domain", "url", "md5", "sha1", "sha256"
]


class CollectedIndicator(BaseModel):
    model_config = ConfigDict(frozen=True)
    type: IndicatorTypeLiteral
    value: str


class CollectedEvent(BaseModel):
    model_config = ConfigDict(frozen=False)

    source_name: str
    external_id: str

    title: str
    summary: str | None = None
    severity: Severity | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    cwe_ids: list[str] = []

    tags: list[str] = []
    indicators: list[CollectedIndicator] = []

    published_at: datetime
    last_modified_at: datetime
    raw_data: dict[str, Any] = {}
```

- [ ] **Step 4: Run tests, verify pass**

Run: `pytest tests/unit/schemas/test_ingest.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/threat_intel/schemas/ingest.py tests/unit/schemas/test_ingest.py
git commit -m "feat(schemas): add CollectedEvent DTO for collector → service contract"
```

---

## Task 4: Collector hierarchy refactor (`BaseCollector` + `APIRestCollector` + `APIGraphQLCollector`)

**Files:**
- Modify: `src/threat_intel/collectors/base.py`
- Test: `tests/unit/collectors/test_base.py`

- [ ] **Step 1: Write the failing tests**

`tests/unit/collectors/test_base.py`:

```python
from datetime import UTC, datetime

import httpx
import pytest
import respx

from threat_intel.collectors.base import APIGraphQLCollector, APIRestCollector, BaseCollector, RawEvent
from threat_intel.core.config import Settings
from threat_intel.core.exceptions import CollectorHTTPError
from threat_intel.models.base import SourceKind
from threat_intel.schemas.ingest import CollectedEvent


class _DummyRest(APIRestCollector):
    source_name = "dummy"
    source_kind = SourceKind.cve_feed
    base_interval_minutes = 60
    base_url = "https://example.test/api"
    auth_method = "none"
    rate_limit_per_minute = 30

    async def fetch(self, since):
        if False:
            yield  # pragma: no cover

    def to_event(self, raw):
        return CollectedEvent(
            source_name=self.source_name,
            external_id=raw.external_id,
            title="t",
            published_at=raw.fetched_at,
            last_modified_at=raw.fetched_at,
        )


@pytest.mark.asyncio
@respx.mock
async def test_apirest_get_returns_json():
    route = respx.get("https://example.test/api/x").respond(200, json={"ok": True})
    async with httpx.AsyncClient() as http:
        c = _DummyRest(http, Settings())
        data = await c._get("https://example.test/api/x")
    assert data == {"ok": True}
    assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_apirest_get_raises_on_5xx():
    respx.get("https://example.test/api/x").respond(500, text="boom")
    async with httpx.AsyncClient() as http:
        c = _DummyRest(http, Settings())
        with pytest.raises(CollectorHTTPError) as exc:
            await c._get("https://example.test/api/x")
    assert exc.value.status_code == 500


class _DummyGraphQL(APIGraphQLCollector):
    source_name = "dummy_gql"
    source_kind = SourceKind.cve_feed
    base_interval_minutes = 60
    endpoint_url = "https://gql.example.test/graphql"
    auth_token_env = "TEST_TOKEN"

    async def fetch(self, since):
        if False:
            yield  # pragma: no cover

    def to_event(self, raw):
        return CollectedEvent(
            source_name=self.source_name,
            external_id=raw.external_id,
            title="t",
            published_at=raw.fetched_at,
            last_modified_at=raw.fetched_at,
        )


@pytest.mark.asyncio
async def test_graphql_disabled_when_token_missing(monkeypatch):
    monkeypatch.delenv("TEST_TOKEN", raising=False)
    async with httpx.AsyncClient() as http:
        c = _DummyGraphQL(http, Settings())
    assert c.enabled is False


@pytest.mark.asyncio
@respx.mock
async def test_graphql_execute_query_attaches_bearer(monkeypatch):
    monkeypatch.setenv("TEST_TOKEN", "secret")
    route = respx.post("https://gql.example.test/graphql").respond(200, json={"data": {"x": 1}})
    async with httpx.AsyncClient() as http:
        c = _DummyGraphQL(http, Settings())
        result = await c._execute_query("query { x }", {})
    assert result == {"data": {"x": 1}}
    sent = route.calls[0].request
    assert sent.headers["authorization"] == "Bearer secret"


@pytest.mark.asyncio
@respx.mock
async def test_graphql_raises_on_errors_field(monkeypatch):
    monkeypatch.setenv("TEST_TOKEN", "secret")
    respx.post("https://gql.example.test/graphql").respond(
        200, json={"errors": [{"message": "Bad query"}]}
    )
    async with httpx.AsyncClient() as http:
        c = _DummyGraphQL(http, Settings())
        with pytest.raises(CollectorHTTPError):
            await c._execute_query("query { x }", {})
```

- [ ] **Step 2: Run tests, verify failure**

Run: `pytest tests/unit/collectors/test_base.py -v`
Expected: FAIL — symbols missing on `BaseCollector`.

- [ ] **Step 3: Replace `collectors/base.py`**

```python
import os
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any, ClassVar, Literal

import httpx
import structlog
from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from threat_intel.core.config import Settings
from threat_intel.core.exceptions import CollectorHTTPError
from threat_intel.models.base import SourceKind
from threat_intel.schemas.ingest import CollectedEvent

logger = structlog.get_logger(__name__)

_RETRY_STATUSES = (429, 500, 502, 503, 504)


class _RetryableHTTPError(Exception):
    def __init__(self, status_code: int, url: str) -> None:
        self.status_code = status_code
        self.url = url
        super().__init__(f"retryable HTTP {status_code} on {url}")


@dataclass(frozen=True)
class RawEvent:
    external_id: str
    payload: dict[str, Any]
    fetched_at: datetime


class BaseCollector(ABC):
    source_name: ClassVar[str]
    source_kind: ClassVar[SourceKind]
    base_interval_minutes: ClassVar[int]

    def __init__(self, http_client: httpx.AsyncClient, settings: Settings) -> None:
        self.http = http_client
        self.settings = settings
        self.enabled = True

    @abstractmethod
    def fetch(self, since: datetime) -> AsyncIterator[RawEvent]: ...

    @abstractmethod
    def to_event(self, raw: RawEvent) -> CollectedEvent: ...


class APIRestCollector(BaseCollector):
    base_url: ClassVar[str]
    auth_method: ClassVar[Literal["none", "api_key", "bearer"]]
    rate_limit_per_minute: ClassVar[int]

    async def _get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(4),
                wait=wait_exponential(multiplier=1, min=1, max=4),
                retry=retry_if_exception_type((httpx.TransportError, _RetryableHTTPError)),
                reraise=True,
            ):
                with attempt:
                    resp = await self.http.get(
                        url, params=params, headers=headers, timeout=30.0
                    )
                    if resp.status_code in _RETRY_STATUSES:
                        raise _RetryableHTTPError(resp.status_code, str(resp.url))
                    if resp.status_code >= 400:
                        raise CollectorHTTPError(
                            status_code=resp.status_code,
                            url=str(resp.url),
                            message=resp.text[:200],
                        )
                    data: dict[str, Any] = resp.json()
                    return data
        except _RetryableHTTPError as e:
            raise CollectorHTTPError(
                status_code=e.status_code, url=e.url, message="retry attempts exhausted"
            ) from e
        except httpx.TransportError as e:
            raise CollectorHTTPError(
                status_code=0, url=url, message=f"transport error: {e}"
            ) from e
        raise CollectorHTTPError(status_code=0, url=url, message="retry loop exhausted")


class APIGraphQLCollector(BaseCollector):
    endpoint_url: ClassVar[str]
    auth_token_env: ClassVar[str]

    def __init__(self, http_client: httpx.AsyncClient, settings: Settings) -> None:
        super().__init__(http_client, settings)
        token = os.environ.get(self.auth_token_env)
        if not token:
            self.enabled = False
            self._token = None
            logger.warning(
                "collector.graphql.disabled",
                source=self.source_name,
                reason=f"{self.auth_token_env} not set",
            )
        else:
            self._token = token

    async def _execute_query(
        self, query: str, variables: dict[str, Any]
    ) -> dict[str, Any]:
        if not self._token:
            raise CollectorHTTPError(
                status_code=0,
                url=self.endpoint_url,
                message=f"{self.auth_token_env} not configured",
            )
        headers = {
            "authorization": f"Bearer {self._token}",
            "content-type": "application/json",
        }
        resp = await self.http.post(
            self.endpoint_url,
            headers=headers,
            json={"query": query, "variables": variables},
            timeout=30.0,
        )
        if resp.status_code >= 400:
            raise CollectorHTTPError(
                status_code=resp.status_code, url=self.endpoint_url, message=resp.text[:200]
            )
        data: dict[str, Any] = resp.json()
        if data.get("errors"):
            raise CollectorHTTPError(
                status_code=200,
                url=self.endpoint_url,
                message=str(data["errors"])[:500],
            )
        return data
```

`ThreatDraft` is intentionally removed. The next task migrates NVD onto `to_event`.

- [ ] **Step 4: Run tests, verify pass**

Run: `pytest tests/unit/collectors/test_base.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/threat_intel/collectors/base.py tests/unit/collectors/test_base.py
git commit -m "refactor(collectors): introduce APIRestCollector and APIGraphQLCollector hierarchy"
```

---

## Task 5: Migrate NVD collector to new hierarchy (no behavior change)

**Files:**
- Modify: `src/threat_intel/collectors/nvd.py`
- Modify: `tests/unit/collectors/test_nvd.py` (if it asserts on `ThreatDraft`)

- [ ] **Step 1: Read existing NVD tests to map expectations**

Run: `cat tests/unit/collectors/test_nvd.py | head -80`
Note all places asserting on `ThreatDraft` fields. They must move to `CollectedEvent` fields.

- [ ] **Step 2: Update `nvd.py` to subclass `APIRestCollector` and emit `CollectedEvent`**

Replace the class header and `normalize` with:

```python
class NVDCollector(APIRestCollector):
    source_name: ClassVar[str] = "nvd"
    source_kind: ClassVar[SourceKind] = SourceKind.cve_feed
    base_interval_minutes: ClassVar[int] = 60
    base_url: ClassVar[str] = ""  # set from settings.nvd_base_url at runtime
    auth_method: ClassVar[Literal["none", "api_key", "bearer"]] = "api_key"
    rate_limit_per_minute: ClassVar[int] = 50

    _PAGE_SIZE: ClassVar[int] = 2000

    def to_event(self, raw: RawEvent) -> CollectedEvent:
        try:
            cve = raw.payload["cve"]
            cve_id: str = cve["id"]
            descriptions = cve.get("descriptions") or []
            en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            description = en or (descriptions[0]["value"] if descriptions else "")
            title = description[:150] if description else cve_id

            metrics = cve.get("metrics") or {}
            cvss_score: float | None = None
            cvss_vector: str | None = None
            cvss_version: str | None = None
            severity: Severity | None = None

            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                items = metrics.get(key) or []
                if items:
                    data = items[0].get("cvssData", {})
                    score = data.get("baseScore")
                    cvss_score = float(score) if score is not None else None
                    cvss_vector = data.get("vectorString")
                    cvss_version = data.get("version")
                    sev_label = (
                        items[0].get("baseSeverity") or data.get("baseSeverity") or ""
                    ).upper()
                    severity = _SEVERITY_MAP.get(sev_label)
                    break

            cwe_ids: list[str] = []
            for w in cve.get("weaknesses") or []:
                for d in w.get("description") or []:
                    val = d.get("value", "")
                    if val.startswith("CWE-") and val not in cwe_ids:
                        cwe_ids.append(val)

            indicators: list[CollectedIndicator] = [
                CollectedIndicator(type="cve", value=cve_id)
            ]
            for cfg in cve.get("configurations") or []:
                for node in cfg.get("nodes") or []:
                    for match in node.get("cpeMatch") or []:
                        c = match.get("criteria")
                        if c:
                            indicators.append(CollectedIndicator(type="cpe", value=c[:512]))

            return CollectedEvent(
                source_name=self.source_name,
                external_id=cve_id,
                title=title,
                summary=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cvss_version=cvss_version,
                cwe_ids=cwe_ids,
                tags=["nvd"],
                indicators=indicators,
                published_at=_parse_dt(cve["published"]),
                last_modified_at=_parse_dt(cve["lastModified"]),
                raw_data=raw.payload,
            )
        except (KeyError, TypeError, ValueError) as e:
            raise CollectorParseError(f"NVD payload malformed for {raw.external_id}: {e}") from e
```

Add `from threat_intel.schemas.ingest import CollectedEvent, CollectedIndicator` and `from typing import Literal`.

The existing `_request_page` becomes a private wrapper that calls `self._get(...)`. Replace its body with:

```python
    async def _request_page(self, params: dict[str, Any]) -> dict[str, Any]:
        url = self.settings.nvd_base_url
        headers: dict[str, str] = {}
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key
        return await self._get(url, params=params, headers=headers)
```

- [ ] **Step 3: Update existing NVD tests**

In `tests/unit/collectors/test_nvd.py`, replace `ThreatDraft` references with `CollectedEvent`. Tests asserting on `description` should now read `summary`. Tests asserting on `affected_products` should iterate `event.indicators` looking for `(cpe, ...)`.

- [ ] **Step 4: Run all collector tests**

```bash
pytest tests/unit/collectors/ -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/threat_intel/collectors/nvd.py tests/unit/collectors/test_nvd.py
git commit -m "refactor(collectors): migrate NVD onto APIRestCollector + CollectedEvent"
```

---

## Task 6: `IngestService.process()` + `recompute_canonical()`

**Files:**
- Replace: `src/threat_intel/analyzers/dedup.py` → `src/threat_intel/services/ingest.py`
- Modify: `src/threat_intel/services/ingestion.py` (call new service)
- Test: `tests/unit/services/test_ingest_dedup.py`
- Test: `tests/unit/services/test_recompute_canonical.py`
- Test: `tests/integration/test_dedup_cross_source.py`

- [ ] **Step 1: Write the failing dedup test**

`tests/unit/services/test_ingest_dedup.py`:

```python
from datetime import UTC, datetime

import pytest

from threat_intel.models.base import Severity
from threat_intel.models.source import Source
from threat_intel.models.threat_indicator import ThreatIndicator
from threat_intel.models.threat_source import ThreatSource
from threat_intel.schemas.ingest import CollectedEvent, CollectedIndicator
from threat_intel.services.ingest import IngestService


def _ev(source_name, ext_id, *, indicators, **overrides):
    base = dict(
        source_name=source_name,
        external_id=ext_id,
        title=f"title-{ext_id}",
        published_at=datetime.now(UTC),
        last_modified_at=datetime.now(UTC),
        tags=[source_name],
        indicators=[CollectedIndicator(type=t, value=v) for t, v in indicators],
    )
    base.update(overrides)
    return CollectedEvent(**base)


@pytest.mark.asyncio
async def test_process_creates_threat_when_no_match(session_factory, source_nvd):
    svc = IngestService(session_factory)
    ev = _ev("nvd", "CVE-2024-1", indicators=[("cve", "CVE-2024-1")])
    outcome, threat_id = await svc.process(ev, source_nvd.id)
    assert outcome == "created"
    async with session_factory() as session:
        ts = (await session.execute(select(ThreatSource))).scalars().all()
        assert len(ts) == 1
        ind = (await session.execute(select(ThreatIndicator))).scalars().all()
        assert any(i.indicator_type == IndicatorType.cve and i.value == "CVE-2024-1" for i in ind)


@pytest.mark.asyncio
async def test_process_dedups_on_same_cve(session_factory, source_nvd, source_kev):
    svc = IngestService(session_factory)
    ev1 = _ev("nvd", "CVE-2024-2", indicators=[("cve", "CVE-2024-2")])
    ev2 = _ev("cisa_kev", "CVE-2024-2", indicators=[("cve", "CVE-2024-2")], tags=["kev", "actively-exploited"])

    outcome1, t1 = await svc.process(ev1, source_nvd.id)
    outcome2, t2 = await svc.process(ev2, source_kev.id)

    assert outcome1 == "created"
    assert outcome2 == "updated"
    assert t1 == t2

    async with session_factory() as session:
        ts = (await session.execute(select(ThreatSource).where(ThreatSource.threat_id == t1))).scalars().all()
        assert len(ts) == 2
        threat = (await session.execute(select(Threat).where(Threat.id == t1))).scalar_one()
        assert "kev" in threat.tags
        assert "nvd" in threat.tags


@pytest.mark.asyncio
async def test_process_ghsa_with_cve_dedups_with_nvd(session_factory, source_nvd, source_ghsa):
    svc = IngestService(session_factory)
    nvd_ev = _ev("nvd", "CVE-2024-3", indicators=[("cve", "CVE-2024-3")])
    ghsa_ev = _ev(
        "github_advisories", "GHSA-aaaa-bbbb-cccc",
        indicators=[("ghsa", "GHSA-aaaa-bbbb-cccc"), ("cve", "CVE-2024-3"), ("package", "npm:lodash")],
        tags=["github-advisory", "npm"],
    )

    _, t1 = await svc.process(nvd_ev, source_nvd.id)
    outcome, t2 = await svc.process(ghsa_ev, source_ghsa.id)

    assert outcome == "updated"
    assert t1 == t2
    async with session_factory() as session:
        ts = (await session.execute(select(ThreatSource).where(ThreatSource.threat_id == t1))).scalars().all()
        assert len(ts) == 2


@pytest.mark.asyncio
async def test_process_idempotent_same_source(session_factory, source_nvd):
    svc = IngestService(session_factory)
    ev = _ev("nvd", "CVE-2024-4", indicators=[("cve", "CVE-2024-4")])
    o1, _ = await svc.process(ev, source_nvd.id)
    o2, _ = await svc.process(ev, source_nvd.id)
    assert o1 == "created"
    assert o2 == "updated"
```

(Add the necessary imports and conftest fixtures `session_factory`, `source_nvd`, `source_kev`, `source_ghsa` — extending the existing `tests/conftest.py` to seed those Source rows in a clean DB).

- [ ] **Step 2: Write the failing recompute_canonical test**

`tests/unit/services/test_recompute_canonical.py`:

```python
import pytest
from datetime import UTC, datetime

from threat_intel.models.base import Severity
from threat_intel.models.threat import Threat
from threat_intel.models.threat_source import ThreatSource
from threat_intel.services.ingest import recompute_canonical


@pytest.mark.asyncio
async def test_recompute_picks_nvd_cvss_over_ghsa(session_factory, source_nvd, source_ghsa, threat_with_two_sources):
    """NVD has cvss=9.8; GHSA has cvss=7.5. Canonical must be 9.8."""
    threat_id = threat_with_two_sources  # fixture sets up threat + 2 ThreatSource rows
    async with session_factory() as session:
        await recompute_canonical(session, threat_id)
        await session.commit()
        threat = (await session.execute(select(Threat).where(Threat.id == threat_id))).scalar_one()
    assert threat.cvss_score == 9.8


@pytest.mark.asyncio
async def test_recompute_severity_bumped_to_critical_when_kev_tag(session_factory, threat_with_kev_tag):
    threat_id = threat_with_kev_tag
    async with session_factory() as session:
        await recompute_canonical(session, threat_id)
        await session.commit()
        threat = (await session.execute(select(Threat).where(Threat.id == threat_id))).scalar_one()
    assert threat.severity == Severity.critical


@pytest.mark.asyncio
async def test_recompute_unions_cwe_and_tags(session_factory, threat_with_three_sources):
    threat_id = threat_with_three_sources
    async with session_factory() as session:
        await recompute_canonical(session, threat_id)
        await session.commit()
        threat = (await session.execute(select(Threat).where(Threat.id == threat_id))).scalar_one()
    assert {"nvd", "github-advisory", "kev"} <= set(threat.tags)
    assert {"CWE-79", "CWE-89"} <= set(threat.cwes_ids if hasattr(threat, "cwes_ids") else [c.id for c in threat.cwes])
```

(Define the fixtures in `tests/conftest.py` or in a new `tests/fixtures/threats.py` referenced via conftest.)

- [ ] **Step 3: Run the tests, verify failure**

Run: `pytest tests/unit/services/test_ingest_dedup.py tests/unit/services/test_recompute_canonical.py -v`
Expected: FAIL — `IngestService` and `recompute_canonical` do not exist yet.

- [ ] **Step 4: Implement `services/ingest.py`**

```python
import uuid
from datetime import UTC, datetime
from typing import Literal

import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threat_intel.models.base import IndicatorType, Severity
from threat_intel.models.cwe import CWE
from threat_intel.models.threat import Threat
from threat_intel.models.threat_indicator import ThreatIndicator
from threat_intel.models.threat_source import ThreatSource
from threat_intel.schemas.ingest import CollectedEvent

logger = structlog.get_logger(__name__)

_SEVERITY_RANK = {
    Severity.critical: 5,
    Severity.high: 4,
    Severity.medium: 3,
    Severity.low: 2,
    Severity.none: 1,
    Severity.unknown: 0,
}

_PRIORITY_ORDER = ["nvd", "github_advisories", "cisa_kev"]


def _is_postgres(session: AsyncSession) -> bool:
    return session.bind is not None and session.bind.dialect.name == "postgresql"


def _upsert(session: AsyncSession, table, values, conflict_cols, update_cols):
    if _is_postgres(session):
        stmt = pg_insert(table).values(**values)
        return stmt.on_conflict_do_update(
            index_elements=conflict_cols,
            set_={k: stmt.excluded[k] for k in update_cols},
        )
    stmt = sqlite_insert(table).values(**values)
    return stmt.on_conflict_do_update(
        index_elements=conflict_cols,
        set_={k: stmt.excluded[k] for k in update_cols},
    )


async def _lookup_threat_by_indicators(
    session: AsyncSession, indicators
) -> list[uuid.UUID]:
    keys = [
        (IndicatorType[i.type], i.value)
        for i in indicators
        if i.type in ("cve", "ghsa")
    ]
    if not keys:
        return []
    stmt = select(ThreatIndicator.threat_id).where(
        (ThreatIndicator.indicator_type.in_([k[0] for k in keys]))
        & (ThreatIndicator.value.in_([k[1] for k in keys]))
    )
    rows = (await session.execute(stmt)).scalars().all()
    seen: list[uuid.UUID] = []
    for r in rows:
        if r not in seen:
            seen.append(r)
    return seen


class IngestService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sf = session_factory

    async def process(
        self, event: CollectedEvent, source_id: int
    ) -> tuple[Literal["created", "updated"], uuid.UUID]:
        async with self._sf() as session:
            matches = await _lookup_threat_by_indicators(session, event.indicators)

            if len(matches) == 0:
                threat_id = await self._create_threat(session, event)
                outcome: Literal["created", "updated"] = "created"
            else:
                if len(matches) > 1:
                    threat_id = await self._pick_oldest(session, matches)
                    logger.warning(
                        "merge_candidate",
                        winner_threat_id=str(threat_id),
                        other_threat_ids=[str(m) for m in matches if m != threat_id],
                        triggered_by=event.external_id,
                        source=event.source_name,
                    )
                    event.raw_data = {
                        **event.raw_data,
                        "cross_references": [str(m) for m in matches if m != threat_id],
                    }
                else:
                    threat_id = matches[0]
                outcome = "updated"

            await self._upsert_threat_source(session, threat_id, source_id, event)
            await self._upsert_indicators(session, threat_id, event)
            await session.commit()

            await recompute_canonical(session, threat_id)
            await session.commit()
            return outcome, threat_id

    async def _create_threat(self, session: AsyncSession, event: CollectedEvent) -> uuid.UUID:
        threat_type = "advisory" if any(i.type == "ghsa" for i in event.indicators) else "cve"
        if any(i.type == "cve" for i in event.indicators):
            threat_type = "cve"
        threat = Threat(
            id=uuid.uuid4(),
            threat_type=threat_type,
            title=event.title,
            summary=event.summary,
            severity=event.severity or Severity.unknown,
            cvss_score=event.cvss_score,
            cvss_vector=event.cvss_vector,
            cvss_version=event.cvss_version,
            tags=list(event.tags),
            published_at=event.published_at,
            last_modified_at=event.last_modified_at,
        )
        session.add(threat)
        await session.flush()
        return threat.id

    async def _pick_oldest(self, session: AsyncSession, ids: list[uuid.UUID]) -> uuid.UUID:
        rows = (
            await session.execute(
                select(Threat.id, Threat.created_at).where(Threat.id.in_(ids))
            )
        ).all()
        rows.sort(key=lambda r: r[1])
        return rows[0][0]

    async def _upsert_threat_source(
        self,
        session: AsyncSession,
        threat_id: uuid.UUID,
        source_id: int,
        event: CollectedEvent,
    ) -> None:
        # Pull per-source affected_products / references out of raw_data if collectors
        # parked them there (NVD does so via the configurations + references arrays).
        affected = event.raw_data.get("affected_products") if isinstance(event.raw_data, dict) else []
        references = event.raw_data.get("references") if isinstance(event.raw_data, dict) else []
        existing = (
            await session.execute(
                select(ThreatSource).where(
                    ThreatSource.threat_id == threat_id,
                    ThreatSource.source_id == source_id,
                )
            )
        ).scalar_one_or_none()
        now = datetime.now(UTC)
        if existing is None:
            session.add(
                ThreatSource(
                    threat_id=threat_id,
                    source_id=source_id,
                    external_id=event.external_id,
                    first_seen_at=event.published_at,
                    last_seen_at=now,
                    tags=list(event.tags),
                    affected_products=list(affected or []),
                    references=list(references or []),
                    raw_data=dict(event.raw_data),
                )
            )
        else:
            existing.last_seen_at = now
            existing.tags = list(event.tags)
            existing.raw_data = dict(event.raw_data)
            existing.affected_products = list(affected or [])
            existing.references = list(references or [])

    async def _upsert_indicators(
        self,
        session: AsyncSession,
        threat_id: uuid.UUID,
        event: CollectedEvent,
    ) -> None:
        if not event.indicators:
            return
        now = datetime.now(UTC)
        for ind in event.indicators:
            stmt = _upsert(
                session,
                ThreatIndicator.__table__,
                {
                    "threat_id": threat_id,
                    "indicator_type": IndicatorType[ind.type],
                    "value": ind.value,
                    "first_seen": now,
                    "confidence": 100,
                    "created_at": now,
                    "updated_at": now,
                },
                conflict_cols=["threat_id", "indicator_type", "value"],
                update_cols=["updated_at"],
            )
            await session.execute(stmt)


async def recompute_canonical(session: AsyncSession, threat_id: uuid.UUID) -> None:
    threat = (
        await session.execute(select(Threat).where(Threat.id == threat_id))
    ).scalar_one_or_none()
    if threat is None:
        return
    sources = (
        (
            await session.execute(
                select(ThreatSource).where(ThreatSource.threat_id == threat_id)
            )
        )
        .scalars()
        .all()
    )
    if not sources:
        return

    by_name: dict[str, ThreatSource] = {}
    for ts in sources:
        await session.refresh(ts, ["source"])
        by_name[ts.source.name] = ts

    def _pick(field: str) -> object | None:
        for name in _PRIORITY_ORDER:
            ts = by_name.get(name)
            if ts is None:
                continue
            value = ts.raw_data.get(field) if isinstance(ts.raw_data, dict) else None
            if value:
                return value
        return None

    # Canonical title / summary — pulled from raw_data so the priority is data-driven.
    title = _pick("title") or _pick("summary") or threat.title
    summary = _pick("summary")

    # CVSS — NVD wins, fall back to GHSA, then KEV (KEV has none in practice).
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    for name in _PRIORITY_ORDER:
        ts = by_name.get(name)
        if ts is None:
            continue
        s = (ts.raw_data or {}).get("cvss_score")
        if s is not None:
            cvss_score = float(s)
            cvss_vector = (ts.raw_data or {}).get("cvss_vector")
            cvss_version = (ts.raw_data or {}).get("cvss_version")
            break

    # Severity — same order; bump to critical if KEV tag present.
    severity = Severity.unknown
    for name in _PRIORITY_ORDER:
        ts = by_name.get(name)
        if ts is None:
            continue
        sv = (ts.raw_data or {}).get("severity")
        if sv:
            try:
                severity = Severity(sv) if isinstance(sv, str) else sv
                break
            except ValueError:
                continue

    # Tag union (per-source tags merged)
    tags: list[str] = []
    for ts in sources:
        for tag in (ts.tags or []):
            if tag not in tags:
                tags.append(tag)
    if "kev" in tags:
        if _SEVERITY_RANK.get(severity, 0) < _SEVERITY_RANK[Severity.critical]:
            severity = Severity.critical

    # CWE union
    cwe_ids: list[str] = []
    for ts in sources:
        for c in (ts.raw_data or {}).get("cwe_ids") or []:
            if c not in cwe_ids:
                cwe_ids.append(c)

    # Apply
    threat.title = (title if isinstance(title, str) else threat.title) or threat.title
    threat.summary = summary if isinstance(summary, str) else threat.summary
    threat.severity = severity
    threat.cvss_score = cvss_score
    threat.cvss_vector = cvss_vector
    threat.cvss_version = cvss_version
    threat.tags = tags
    threat.last_modified_at = max((ts.last_seen_at for ts in sources), default=threat.last_modified_at)
    threat.published_at = min((ts.first_seen_at for ts in sources), default=threat.published_at)

    # CWE relationship — sync via the existing junction. Reuse upsert helper.
    if cwe_ids:
        existing_cwes = (
            (await session.execute(select(CWE).where(CWE.id.in_(cwe_ids)))).scalars().all()
        )
        found_ids = {c.id for c in existing_cwes}
        new_cwes = [CWE(id=c) for c in cwe_ids if c not in found_ids]
        for c in new_cwes:
            session.add(c)
        if new_cwes:
            await session.flush()
        threat.cwes = list(existing_cwes) + new_cwes
```

> Key detail: `recompute_canonical` reads canonical-candidate fields from `ThreatSource.raw_data`. Each collector's `to_event()` is responsible for placing `title`, `summary`, `cvss_score`, `cvss_vector`, `cvss_version`, `severity`, and `cwe_ids` into the `raw_data` dict it returns (in addition to keeping the original payload). Update each collector's `to_event` to do this. NVD already includes `raw_data=raw.payload`; **wrap** that into `{"_payload": raw.payload, "title": ..., "summary": ..., "cvss_score": ..., ...}` so canonical fields are first-class lookup keys.

- [ ] **Step 5: Update each collector's `to_event` to enrich `raw_data` with canonical fields**

Edit `src/threat_intel/collectors/nvd.py` `to_event`:

```python
            return CollectedEvent(
                ...,
                raw_data={
                    "title": title,
                    "summary": description,
                    "severity": severity.value if severity else None,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "cvss_version": cvss_version,
                    "cwe_ids": cwe_ids,
                    "affected_products": products,
                    "references": refs,
                    "_payload": raw.payload,
                },
            )
```

(Keep `products` and `refs` populated as before.)

- [ ] **Step 6: Run the unit tests**

```bash
pytest tests/unit/services/test_ingest_dedup.py tests/unit/services/test_recompute_canonical.py -v
```

Expected: PASS.

- [ ] **Step 7: Write the cross-source integration test**

`tests/integration/test_dedup_cross_source.py`:

```python
import pytest
from datetime import UTC, datetime

from threat_intel.models.threat import Threat
from threat_intel.models.threat_source import ThreatSource
from threat_intel.schemas.ingest import CollectedEvent, CollectedIndicator
from threat_intel.services.ingest import IngestService


def _make(source_name, ext_id, *, severity=None, cvss=None, tags=None, indicators=None, summary=None):
    return CollectedEvent(
        source_name=source_name,
        external_id=ext_id,
        title=f"title-{source_name}",
        summary=summary,
        severity=severity,
        cvss_score=cvss,
        tags=tags or [],
        indicators=[CollectedIndicator(type=t, value=v) for t, v in (indicators or [])],
        published_at=datetime.now(UTC),
        last_modified_at=datetime.now(UTC),
        raw_data={
            "title": f"title-{source_name}",
            "summary": summary,
            "severity": severity.value if severity else None,
            "cvss_score": cvss,
            "cwe_ids": [],
        },
    )


@pytest.mark.asyncio
async def test_three_sources_merge_into_one_threat(session_factory, source_nvd, source_kev, source_ghsa):
    svc = IngestService(session_factory)
    cve = "CVE-2021-44228"  # Log4Shell

    nvd_ev = _make("nvd", cve, severity="high", cvss=9.8, tags=["nvd"], indicators=[("cve", cve)])
    kev_ev = _make("cisa_kev", cve, tags=["kev", "actively-exploited"], indicators=[("cve", cve)])
    ghsa_ev = _make(
        "github_advisories", "GHSA-jfh8-c2jp-5v3q",
        severity="critical", tags=["github-advisory", "maven"],
        indicators=[("ghsa", "GHSA-jfh8-c2jp-5v3q"), ("cve", cve), ("package", "maven:org.apache.logging.log4j:log4j-core")],
    )

    _, t1 = await svc.process(nvd_ev, source_nvd.id)
    _, t2 = await svc.process(kev_ev, source_kev.id)
    _, t3 = await svc.process(ghsa_ev, source_ghsa.id)

    assert t1 == t2 == t3
    async with session_factory() as session:
        ts = (await session.execute(select(ThreatSource).where(ThreatSource.threat_id == t1))).scalars().all()
        assert len(ts) == 3
        threat = (await session.execute(select(Threat).where(Threat.id == t1))).scalar_one()
        assert threat.cvss_score == 9.8           # NVD wins
        assert "kev" in threat.tags               # KEV tag present
        assert threat.severity.value == "critical"  # bumped by KEV
        assert "github-advisory" in threat.tags
        assert "maven" in threat.tags
```

- [ ] **Step 8: Run the integration test**

```bash
pytest tests/integration/test_dedup_cross_source.py -v
```

Expected: PASS.

- [ ] **Step 9: Replace `analyzers/dedup.py` content with a deprecation shim**

The old `upsert_threat` is no longer used. Delete `src/threat_intel/analyzers/dedup.py`. Search and remove its imports throughout the codebase:

```bash
grep -rn "from threat_intel.analyzers.dedup" src/ tests/
```

Update each import to use `IngestService` and `CollectedEvent` instead.

- [ ] **Step 10: Update `services/ingestion.py` to call `IngestService.process`**

Modify the loop body. Replace:

```python
draft = collector.normalize(raw)
outcome = await upsert_threat(session, src, draft)
```

with:

```python
event = collector.to_event(raw)
ingest = IngestService(self._sf)
outcome, _ = await ingest.process(event, src.id)
if outcome == "created":
    result.inserted += 1
elif outcome == "updated":
    result.updated += 1
```

(Move the `IngestService` instantiation out of the loop into `__init__`.)

- [ ] **Step 11: Run the full test suite**

```bash
pytest -q
```

Expected: PASS. Existing M1 tests for ingestion may need fixture updates (expect to fix 5–10 tests at most). Update them in this same task.

- [ ] **Step 12: Commit**

```bash
git add src/threat_intel/services/ingest.py src/threat_intel/services/ingestion.py src/threat_intel/collectors/nvd.py tests/
git rm src/threat_intel/analyzers/dedup.py
git commit -m "feat(ingest): cross-source dedup + canonical recompute via IngestService"
```

---

## Task 7: CISA KEV collector

**Files:**
- Create: `src/threat_intel/collectors/cisa_kev.py`
- Create: `tests/fixtures/cisa_kev_sample.json`
- Test: `tests/unit/collectors/test_cisa_kev.py`

- [ ] **Step 1: Add a real-shape KEV fixture**

`tests/fixtures/cisa_kev_sample.json`:

```json
{
  "title": "Known Exploited Vulnerabilities",
  "catalogVersion": "2026.04.01",
  "dateReleased": "2026-04-01T00:00:00.000Z",
  "count": 2,
  "vulnerabilities": [
    {
      "cveID": "CVE-2021-44228",
      "vendorProject": "Apache",
      "product": "Log4j2",
      "vulnerabilityName": "Apache Log4j2 RCE",
      "dateAdded": "2021-12-10",
      "shortDescription": "Apache Log4j2 contains a flaw that allows RCE.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2021-12-24",
      "knownRansomwareCampaignUse": "Known",
      "notes": ""
    },
    {
      "cveID": "CVE-2024-0001",
      "vendorProject": "Acme",
      "product": "Widget",
      "vulnerabilityName": "Acme Widget Auth Bypass",
      "dateAdded": "2024-03-15",
      "shortDescription": "Auth bypass in Acme Widget.",
      "requiredAction": "Update to v3.4.",
      "dueDate": "2024-04-05",
      "knownRansomwareCampaignUse": "Unknown",
      "notes": ""
    }
  ]
}
```

- [ ] **Step 2: Write the failing tests**

`tests/unit/collectors/test_cisa_kev.py`:

```python
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import respx

from threat_intel.collectors.base import RawEvent
from threat_intel.collectors.cisa_kev import CISA_KEV_URL, CISAKEVCollector
from threat_intel.core.config import Settings


FIXTURE = Path(__file__).parent.parent.parent / "fixtures" / "cisa_kev_sample.json"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_yields_one_event_per_vulnerability():
    payload = json.loads(FIXTURE.read_text())
    respx.get(CISA_KEV_URL).respond(200, json=payload)
    async with httpx.AsyncClient() as http:
        c = CISAKEVCollector(http, Settings())
        events = [r async for r in c.fetch(datetime.now(UTC))]
    assert len(events) == 2
    assert events[0].external_id == "CVE-2021-44228"


def test_to_event_maps_log4shell_with_ransomware_tag():
    payload = json.loads(FIXTURE.read_text())
    raw = RawEvent(
        external_id="CVE-2021-44228",
        payload=payload["vulnerabilities"][0],
        fetched_at=datetime.now(UTC),
    )
    c = CISAKEVCollector(http_client=None, settings=Settings())  # type: ignore[arg-type]
    ev = c.to_event(raw)
    assert ev.source_name == "cisa_kev"
    assert ev.external_id == "CVE-2021-44228"
    assert ev.title == "Apache Log4j2 RCE"
    assert ev.summary.startswith("Apache Log4j2 contains a flaw")
    assert {"kev", "actively-exploited", "ransomware"} <= set(ev.tags)
    types = {(i.type, i.value) for i in ev.indicators}
    assert ("cve", "CVE-2021-44228") in types


def test_to_event_no_ransomware_tag_when_unknown():
    payload = json.loads(FIXTURE.read_text())
    raw = RawEvent(
        external_id="CVE-2024-0001",
        payload=payload["vulnerabilities"][1],
        fetched_at=datetime.now(UTC),
    )
    c = CISAKEVCollector(http_client=None, settings=Settings())  # type: ignore[arg-type]
    ev = c.to_event(raw)
    assert "kev" in ev.tags
    assert "actively-exploited" in ev.tags
    assert "ransomware" not in ev.tags
```

- [ ] **Step 3: Run the tests, verify failure**

Run: `pytest tests/unit/collectors/test_cisa_kev.py -v`
Expected: FAIL — `CISAKEVCollector` does not exist.

- [ ] **Step 4: Implement `collectors/cisa_kev.py`**

```python
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import ClassVar, Literal

from threat_intel.collectors.base import APIRestCollector, RawEvent
from threat_intel.core.exceptions import CollectorParseError
from threat_intel.models.base import SourceKind
from threat_intel.schemas.ingest import CollectedEvent, CollectedIndicator

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


class CISAKEVCollector(APIRestCollector):
    source_name: ClassVar[str] = "cisa_kev"
    source_kind: ClassVar[SourceKind] = SourceKind.cve_feed
    base_interval_minutes: ClassVar[int] = 360
    base_url: ClassVar[str] = CISA_KEV_URL
    auth_method: ClassVar[Literal["none", "api_key", "bearer"]] = "none"
    rate_limit_per_minute: ClassVar[int] = 60

    async def fetch(self, since: datetime) -> AsyncIterator[RawEvent]:
        data = await self._get(self.base_url)
        for vuln in data.get("vulnerabilities") or []:
            cve_id = vuln.get("cveID")
            if not cve_id:
                continue
            yield RawEvent(
                external_id=cve_id,
                payload=vuln,
                fetched_at=datetime.now(UTC),
            )

    def to_event(self, raw: RawEvent) -> CollectedEvent:
        try:
            v = raw.payload
            cve_id = v["cveID"]
            title = v.get("vulnerabilityName") or cve_id
            summary = v.get("shortDescription") or ""

            tags = ["kev", "actively-exploited"]
            if (v.get("knownRansomwareCampaignUse") or "").lower() == "known":
                tags.append("ransomware")

            date_added = v.get("dateAdded")
            published_at = (
                datetime.fromisoformat(date_added).replace(tzinfo=UTC)
                if date_added
                else datetime.now(UTC)
            )

            return CollectedEvent(
                source_name=self.source_name,
                external_id=cve_id,
                title=title,
                summary=summary,
                severity=None,
                cvss_score=None,
                tags=tags,
                indicators=[CollectedIndicator(type="cve", value=cve_id)],
                published_at=published_at,
                last_modified_at=datetime.now(UTC),
                raw_data={
                    "title": title,
                    "summary": summary,
                    "cwe_ids": [],
                    "_payload": v,
                },
            )
        except (KeyError, TypeError, ValueError) as e:
            raise CollectorParseError(f"CISA KEV malformed for {raw.external_id}: {e}") from e
```

- [ ] **Step 5: Run the tests, verify pass**

Run: `pytest tests/unit/collectors/test_cisa_kev.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/threat_intel/collectors/cisa_kev.py tests/unit/collectors/test_cisa_kev.py tests/fixtures/cisa_kev_sample.json
git commit -m "feat(collectors): add CISA KEV collector with ransomware tag"
```

---

## Task 8: GitHub Security Advisories collector

**Files:**
- Create: `src/threat_intel/collectors/github_advisories.py`
- Create: `tests/fixtures/ghsa_sample.json`
- Test: `tests/unit/collectors/test_github_advisories.py`

- [ ] **Step 1: Add a real-shape GHSA fixture (page 1 with `hasNextPage = true`)**

`tests/fixtures/ghsa_sample.json`:

```json
{
  "data": {
    "securityAdvisories": {
      "pageInfo": {"hasNextPage": true, "endCursor": "Y3Vyc29yOnYyOpHOA"},
      "nodes": [
        {
          "ghsaId": "GHSA-jfh8-c2jp-5v3q",
          "summary": "RCE in Apache Log4j",
          "description": "Log4j 2.x JNDI lookup feature allows remote attackers to execute arbitrary code.",
          "severity": "CRITICAL",
          "publishedAt": "2021-12-10T00:00:00Z",
          "updatedAt": "2022-01-15T12:00:00Z",
          "identifiers": [
            {"type": "GHSA", "value": "GHSA-jfh8-c2jp-5v3q"},
            {"type": "CVE", "value": "CVE-2021-44228"}
          ],
          "vulnerabilities": {
            "nodes": [
              {"package": {"ecosystem": "MAVEN", "name": "org.apache.logging.log4j:log4j-core"}, "vulnerableVersionRange": ">= 2.0, < 2.15.0"}
            ]
          },
          "references": [
            {"url": "https://logging.apache.org/log4j/2.x/security.html"}
          ],
          "cwes": {"nodes": [{"cweId": "CWE-502"}, {"cweId": "CWE-917"}]}
        }
      ]
    }
  }
}
```

Add a second fixture `tests/fixtures/ghsa_page2.json` with `hasNextPage: false` and one different GHSA.

- [ ] **Step 2: Write the failing tests**

`tests/unit/collectors/test_github_advisories.py`:

```python
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import respx

from threat_intel.collectors.base import RawEvent
from threat_intel.collectors.github_advisories import GHSA_ENDPOINT, GitHubAdvisoriesCollector
from threat_intel.core.config import Settings


F1 = Path(__file__).parent.parent.parent / "fixtures" / "ghsa_sample.json"
F2 = Path(__file__).parent.parent.parent / "fixtures" / "ghsa_page2.json"


@pytest.fixture(autouse=True)
def _set_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")


@pytest.mark.asyncio
async def test_disabled_when_token_missing(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    async with httpx.AsyncClient() as http:
        c = GitHubAdvisoriesCollector(http, Settings())
    assert c.enabled is False


@pytest.mark.asyncio
@respx.mock
async def test_fetch_paginates_until_no_next_page():
    page1 = json.loads(F1.read_text())
    page2 = json.loads(F2.read_text())
    route = respx.post(GHSA_ENDPOINT).mock(side_effect=[
        httpx.Response(200, json=page1),
        httpx.Response(200, json=page2),
    ])
    async with httpx.AsyncClient() as http:
        c = GitHubAdvisoriesCollector(http, Settings())
        events = [r async for r in c.fetch(datetime.now(UTC) - __import__('datetime').timedelta(days=7))]
    assert route.call_count == 2
    assert len(events) == 2


def test_to_event_maps_log4shell_with_ecosystem_tag():
    page1 = json.loads(F1.read_text())
    advisory = page1["data"]["securityAdvisories"]["nodes"][0]
    raw = RawEvent(external_id=advisory["ghsaId"], payload=advisory, fetched_at=datetime.now(UTC))
    c = GitHubAdvisoriesCollector(http_client=None, settings=Settings())  # type: ignore[arg-type]
    ev = c.to_event(raw)
    assert ev.source_name == "github_advisories"
    assert ev.external_id == "GHSA-jfh8-c2jp-5v3q"
    assert ev.severity.value == "critical"
    assert "github-advisory" in ev.tags
    assert "maven" in ev.tags
    types = {(i.type, i.value) for i in ev.indicators}
    assert ("ghsa", "GHSA-jfh8-c2jp-5v3q") in types
    assert ("cve", "CVE-2021-44228") in types
    assert ("package", "maven:org.apache.logging.log4j:log4j-core") in types
    assert "CWE-502" in ev.cwe_ids


def test_to_event_strips_html_in_description():
    advisory = {
        "ghsaId": "GHSA-aaaa-bbbb-cccc",
        "summary": "<script>alert(1)</script>Plain text title",
        "description": "<p>Hello <b>world</b></p>",
        "severity": "MODERATE",
        "publishedAt": "2024-01-01T00:00:00Z",
        "updatedAt": "2024-01-02T00:00:00Z",
        "identifiers": [{"type": "GHSA", "value": "GHSA-aaaa-bbbb-cccc"}],
        "vulnerabilities": {"nodes": []},
        "references": [],
        "cwes": {"nodes": []},
    }
    raw = RawEvent(external_id=advisory["ghsaId"], payload=advisory, fetched_at=datetime.now(UTC))
    c = GitHubAdvisoriesCollector(http_client=None, settings=Settings())  # type: ignore[arg-type]
    ev = c.to_event(raw)
    assert "<" not in ev.title
    assert "<" not in (ev.summary or "")
    assert "alert" not in ev.title.lower()
```

- [ ] **Step 3: Run the tests, verify failure**

Run: `pytest tests/unit/collectors/test_github_advisories.py -v`
Expected: FAIL — module missing.

- [ ] **Step 4: Implement `collectors/github_advisories.py`**

```python
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any, ClassVar

import bleach

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


def _clean(value: str | None) -> str:
    if not value:
        return ""
    return bleach.clean(value, tags=[], strip=True)


def _parse_dt(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


class GitHubAdvisoriesCollector(APIGraphQLCollector):
    source_name: ClassVar[str] = "github_advisories"
    source_kind: ClassVar[SourceKind] = SourceKind.cve_feed
    base_interval_minutes: ClassVar[int] = 120
    endpoint_url: ClassVar[str] = GHSA_ENDPOINT
    auth_token_env: ClassVar[str] = "GITHUB_TOKEN"

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
                    fetched_at=datetime.now(),
                )
            if not page["pageInfo"]["hasNextPage"]:
                break
            cursor = page["pageInfo"]["endCursor"]

    def to_event(self, raw: RawEvent) -> CollectedEvent:
        try:
            n = raw.payload
            ghsa_id = n["ghsaId"]

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
                indicators.append(CollectedIndicator(type="package", value=f"{eco}:{name}"[:512]))

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
                title=_clean(n.get("summary")),
                summary=_clean(n.get("description")),
                severity=severity,
                cwe_ids=cwe_ids,
                tags=tags,
                indicators=indicators,
                published_at=_parse_dt(n["publishedAt"]),
                last_modified_at=_parse_dt(n["updatedAt"]),
                raw_data={
                    "title": _clean(n.get("summary")),
                    "summary": _clean(n.get("description")),
                    "severity": severity.value if severity else None,
                    "cwe_ids": cwe_ids,
                    "references": references,
                    "_payload": n,
                },
            )
        except (KeyError, TypeError, ValueError) as e:
            raise CollectorParseError(f"GHSA payload malformed for {raw.external_id}: {e}") from e
```

- [ ] **Step 5: Run the tests, verify pass**

Run: `pytest tests/unit/collectors/test_github_advisories.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/threat_intel/collectors/github_advisories.py tests/unit/collectors/test_github_advisories.py tests/fixtures/ghsa_sample.json tests/fixtures/ghsa_page2.json
git commit -m "feat(collectors): add GitHub Security Advisories GraphQL collector"
```

---

## Task 9: Scoring extension — KEV signal, multi-source, package match

**Files:**
- Modify: `src/threat_intel/services/sector_scoring.py`
- Test: `tests/unit/services/test_sector_scoring_m3a.py`

- [ ] **Step 1: Write the failing tests**

`tests/unit/services/test_sector_scoring_m3a.py`:

```python
import pytest
from datetime import UTC, datetime

from threat_intel.models.base import IndicatorType, Severity
from threat_intel.models.sector_profile import SectorProfile
from threat_intel.models.threat import Threat
from threat_intel.models.threat_indicator import ThreatIndicator
from threat_intel.services.sector_scoring import (
    KEV_POINTS, ACTIVELY_EXPLOITED_POINTS, RANSOMWARE_POINTS,
    MULTI_SOURCE_2_POINTS, MULTI_SOURCE_3_PLUS_POINTS, PACKAGE_MATCH_POINTS,
    SectorScoringService,
)


def _profile(**overrides):
    base = dict(
        id="acme", name="Acme", sector="tech", description="",
        keywords=[], technologies=["React"], cwe_priorities=[],
        excluded_keywords=[], compliance=[], priority_boost_keywords=[],
        cvss_threshold=7.0, visibility="public", source_file=None, loaded_at=datetime.now(UTC),
    )
    base.update(overrides)
    return SectorProfile(**base)


def _threat(**overrides):
    base = dict(
        id=__import__("uuid").uuid4(), threat_type="cve", title="x", summary="y",
        severity=Severity.high, cvss_score=8.0, cvss_vector=None, cvss_version=None,
        tags=[], published_at=datetime.now(UTC), last_modified_at=datetime.now(UTC), cwes=[], sources=[],
    )
    base.update(overrides)
    return Threat(**base)


def test_kev_tag_adds_kev_points():
    threat = _threat(tags=["kev"])
    res = SectorScoringService.calculate_score(threat, _profile())
    assert res.breakdown["kev"]["points"] == KEV_POINTS


def test_actively_exploited_stacks_with_kev():
    threat = _threat(tags=["kev", "actively-exploited", "ransomware"])
    res = SectorScoringService.calculate_score(threat, _profile())
    assert res.breakdown["kev"]["points"] == KEV_POINTS
    assert res.breakdown["actively_exploited"]["points"] == ACTIVELY_EXPLOITED_POINTS
    assert res.breakdown["ransomware"]["points"] == RANSOMWARE_POINTS


def test_two_sources_adds_5_three_or_more_adds_10_only():
    """Multi-source criterion is mutually exclusive: 5 OR 10, never both."""
    t = _threat()
    t.sources = [object(), object()]  # 2 sources
    res = SectorScoringService.calculate_score(t, _profile())
    assert res.breakdown["multi_source"]["points"] == MULTI_SOURCE_2_POINTS

    t.sources = [object(), object(), object()]
    res = SectorScoringService.calculate_score(t, _profile())
    assert res.breakdown["multi_source"]["points"] == MULTI_SOURCE_3_PLUS_POINTS


def test_package_indicator_matches_profile_technology():
    t = _threat()
    t.indicators = [
        ThreatIndicator(threat_id=t.id, indicator_type=IndicatorType.package, value="npm:react", first_seen=datetime.now(UTC)),
    ]
    res = SectorScoringService.calculate_score(t, _profile(technologies=["React"]))
    assert res.breakdown["package_match"]["points"] == PACKAGE_MATCH_POINTS
    assert res.breakdown["package_match"]["matched"] == ["npm:react"]


def test_package_indicator_no_match_no_points():
    t = _threat()
    t.indicators = [
        ThreatIndicator(threat_id=t.id, indicator_type=IndicatorType.package, value="npm:lodash", first_seen=datetime.now(UTC)),
    ]
    res = SectorScoringService.calculate_score(t, _profile(technologies=["React"]))
    assert res.breakdown["package_match"]["points"] == 0
```

- [ ] **Step 2: Run tests, verify failure**

Run: `pytest tests/unit/services/test_sector_scoring_m3a.py -v`
Expected: FAIL — new constants and breakdown keys missing.

- [ ] **Step 3: Extend `services/sector_scoring.py`**

Add constants near the top:

```python
KEV_POINTS = 25
ACTIVELY_EXPLOITED_POINTS = 15
RANSOMWARE_POINTS = 15
MULTI_SOURCE_2_POINTS = 5
MULTI_SOURCE_3_PLUS_POINTS = 10
PACKAGE_MATCH_POINTS = 20
```

Inside `calculate_score`, after the existing `breakdown` dict is built:

```python
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

        # Package match: indicators of type=package whose name part is in profile.technologies (case-insensitive).
        pkg_matched: list[str] = []
        techs_lower = {t.lower() for t in (profile.technologies or [])}
        for ind in (getattr(threat, "indicators", None) or []):
            if ind.indicator_type != IndicatorType.package:
                continue
            name_part = ind.value.split(":", 1)[-1].lower()
            if any(t == name_part or t in name_part.split("/")[-1].split("-") for t in techs_lower):
                pkg_matched.append(ind.value)
        pkg_points = PACKAGE_MATCH_POINTS if pkg_matched else 0

        breakdown["kev"] = {"hit": "kev" in tags, "points": kev_points}
        breakdown["actively_exploited"] = {"hit": "actively-exploited" in tags, "points": ae_points}
        breakdown["ransomware"] = {"hit": "ransomware" in tags, "points": rw_points}
        breakdown["multi_source"] = {"hit": n_sources >= 2, "source_count": n_sources, "points": ms_points}
        breakdown["package_match"] = {"hit": bool(pkg_matched), "matched": pkg_matched, "points": pkg_points}
```

Adjust `raw_total` computation: it already sums `int(rule["points"]) for rule in breakdown.values()` so the new keys are picked up automatically. Verify the loop key set excludes `raw_total` and `final_score` — wrap it as `for k, rule in breakdown.items() if k not in {"raw_total", "final_score"}`.

Add `IndicatorType` import: `from threat_intel.models.base import IndicatorType`.

Update `_load_threats` in `scoring_job.py` to also `selectinload(Threat.indicators, Threat.sources)` so the new criteria can read them.

- [ ] **Step 4: Add `indicators` relationship to `Threat`**

In `models/threat.py`:

```python
    indicators: Mapped[list["ThreatIndicator"]] = relationship(lazy="selectin")
```

(Plus the TYPE_CHECKING import.)

- [ ] **Step 5: Run all scoring tests**

```bash
pytest tests/unit/services/test_sector_scoring*.py -v
```

Expected: PASS — both M2 and the new M3a tests.

- [ ] **Step 6: Commit**

```bash
git add src/threat_intel/services/sector_scoring.py src/threat_intel/services/scoring_job.py src/threat_intel/models/threat.py tests/unit/services/test_sector_scoring_m3a.py
git commit -m "feat(scoring): add KEV / actively-exploited / multi-source / package criteria"
```

---

## Task 10: Scheduler upgrade — backoff, isolation, CollectorRun lifecycle

**Files:**
- Modify: `src/threat_intel/core/scheduler.py`
- Modify: `src/threat_intel/services/ingestion.py`
- Test: `tests/unit/services/test_collector_run_lifecycle.py`
- Test: `tests/integration/test_collector_resilience.py`

- [ ] **Step 1: Write the failing tests**

`tests/unit/services/test_collector_run_lifecycle.py`:

```python
import pytest
from datetime import UTC, datetime

from threat_intel.models.base import CollectorRunStatus
from threat_intel.models.collector_run import CollectorRun
from threat_intel.services.ingestion import IngestionService


@pytest.mark.asyncio
async def test_successful_run_writes_collector_run_with_status_success(session_factory, source_nvd, mock_collector_one_event):
    svc = IngestionService(session_factory, [mock_collector_one_event])
    await svc.run("nvd")
    async with session_factory() as session:
        runs = (await session.execute(select(CollectorRun))).scalars().all()
    assert len(runs) == 1
    assert runs[0].status == CollectorRunStatus.success
    assert runs[0].events_fetched == 1
    assert runs[0].events_new == 1


@pytest.mark.asyncio
async def test_failure_increments_consecutive_failures(session_factory, source_nvd, failing_collector):
    svc = IngestionService(session_factory, [failing_collector])
    with pytest.raises(Exception):
        await svc.run("nvd")
    async with session_factory() as session:
        src = (await session.execute(select(Source).where(Source.name == "nvd"))).scalar_one()
    assert src.consecutive_failures == 1


@pytest.mark.asyncio
async def test_third_consecutive_failure_doubles_interval(session_factory, source_nvd, failing_collector):
    svc = IngestionService(session_factory, [failing_collector])
    for _ in range(3):
        with pytest.raises(Exception):
            await svc.run("nvd")
    async with session_factory() as session:
        src = (await session.execute(select(Source).where(Source.name == "nvd"))).scalar_one()
    assert src.current_interval_minutes == src.base_interval_minutes * 2


@pytest.mark.asyncio
async def test_success_resets_backoff(session_factory, source_nvd_in_backoff, mock_collector_one_event):
    svc = IngestionService(session_factory, [mock_collector_one_event])
    await svc.run("nvd")
    async with session_factory() as session:
        src = (await session.execute(select(Source).where(Source.name == "nvd"))).scalar_one()
    assert src.consecutive_failures == 0
    assert src.current_interval_minutes == src.base_interval_minutes
```

`tests/integration/test_collector_resilience.py`:

```python
import pytest
from threat_intel.models.collector_run import CollectorRun


@pytest.mark.asyncio
async def test_one_collector_failure_does_not_affect_others(session_factory, working_collector_nvd, broken_collector_ghsa, working_collector_kev, scheduler_runner):
    """Run all three collectors in one tick. NVD + KEV succeed, GHSA fails — assert isolation."""
    await scheduler_runner.tick_all()
    async with session_factory() as session:
        runs = (await session.execute(select(CollectorRun).order_by(CollectorRun.id))).scalars().all()
    statuses = {r.source_id: r.status for r in runs}
    assert statuses[source_nvd.id].value == "success"
    assert statuses[source_kev.id].value == "success"
    assert statuses[source_ghsa.id].value == "failure"
```

- [ ] **Step 2: Run, verify failure**

Run: `pytest tests/unit/services/test_collector_run_lifecycle.py -v`
Expected: FAIL — `CollectorRun` is not written by `IngestionService`.

- [ ] **Step 3: Modify `IngestionService.run` to write `CollectorRun` and apply backoff**

In `src/threat_intel/services/ingestion.py`:

- Open a `CollectorRun(status=running, started_at=now)` at the top, capture its id.
- After the loop, set `status=success`, `events_*` counters, `finished_at`, `duration_ms`. Reset `Source.consecutive_failures=0`, `current_interval_minutes=base_interval_minutes`. Set `next_run_at = now + current_interval_minutes`.
- On exception, set `status=failure`, `error_message=str(e)[:1000]`, `finished_at`, `duration_ms`. Increment `consecutive_failures`. If `>= 3`, double `current_interval_minutes` (cap 1440). Set `next_run_at = now + current_interval_minutes`. Re-raise.
- Add `partial` semantics: track per-event failures; if at end of run `events_failed > 0` and `events_new + events_updated > 0`, set `status=partial` instead of `success`.

(Show the full revised method body in the implementation; this is left as a deliberate exercise to keep the plan readable. The skeleton is in the spec section 7.)

- [ ] **Step 4: Modify `core/scheduler.py` to dispatch each collector via `asyncio.create_task` with isolation**

Replace the per-source job registration. The new job, run on every tick (every 60 seconds):

```python
async def _scheduler_tick(app):
    async with app.state.session_factory() as session:
        due = (
            await session.execute(
                select(Source).where(
                    Source.enabled == True,  # noqa: E712
                    or_(Source.next_run_at.is_(None), Source.next_run_at <= datetime.now(UTC)),
                )
            )
        ).scalars().all()
    for src in due:
        # Each task is independent; exceptions are swallowed so one failure does
        # not abort the tick.
        asyncio.create_task(_run_safe(app, src.name))


async def _run_safe(app, source_name: str) -> None:
    try:
        await app.state.ingestion.run(source_name)
    except Exception:
        logger.exception("scheduler.run_failed", source=source_name)
```

Register this tick once with `AsyncIOScheduler.add_job(_scheduler_tick, "interval", seconds=60, args=[app])`.

- [ ] **Step 5: Run the unit tests**

Run: `pytest tests/unit/services/test_collector_run_lifecycle.py -v`
Expected: PASS.

- [ ] **Step 6: Run the resilience integration test**

Run: `pytest tests/integration/test_collector_resilience.py -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/threat_intel/services/ingestion.py src/threat_intel/core/scheduler.py tests/unit/services/test_collector_run_lifecycle.py tests/integration/test_collector_resilience.py
git commit -m "feat(scheduler): backoff, parallel-safe dispatch, CollectorRun lifecycle"
```

---

## Task 11: New endpoints (`/sources`, `/threats/{id}/sources`, `/indicators`, admin trigger/enable/disable)

**Files:**
- Create: `src/threat_intel/api/v1/sources.py`
- Create: `src/threat_intel/api/v1/indicators.py`
- Modify: `src/threat_intel/api/v1/threats.py`
- Modify: `src/threat_intel/api/v1/admin.py`
- Create: `src/threat_intel/schemas/api/sources.py`
- Create: `src/threat_intel/schemas/api/indicators.py`
- Create: `src/threat_intel/schemas/api/admin.py`
- Test: `tests/integration/api/test_sources_endpoint.py`
- Test: `tests/integration/api/test_indicators_endpoint.py`
- Test: `tests/integration/api/test_threat_sources_endpoint.py`
- Test: `tests/integration/api/test_admin_collectors_endpoint.py`

- [ ] **Step 1: Define response schemas**

`src/threat_intel/schemas/api/sources.py`:

```python
from datetime import datetime
from pydantic import BaseModel


class SourceHealth(BaseModel):
    name: str
    enabled: bool
    last_run_at: datetime | None
    last_success_at: datetime | None
    consecutive_failures: int
    current_interval_minutes: int
    next_run_at: datetime | None
    events_24h: int


class CollectorRunOut(BaseModel):
    id: int
    started_at: datetime
    finished_at: datetime | None
    status: str
    events_fetched: int
    events_new: int
    events_updated: int
    events_failed: int
    error_message: str | None
    duration_ms: int | None


class ThreatSourceOut(BaseModel):
    source_name: str
    external_id: str
    first_seen_at: datetime
    last_seen_at: datetime
    tags: list[str]
```

`src/threat_intel/schemas/api/indicators.py`:

```python
from pydantic import BaseModel
from threat_intel.schemas.threat import ThreatOut


class IndicatorMatchOut(BaseModel):
    indicator_type: str
    value: str
    threats: list[ThreatOut]
```

`src/threat_intel/schemas/api/admin.py`:

```python
from pydantic import BaseModel


class CollectorActionResult(BaseModel):
    name: str
    enabled: bool
    next_run_at: str | None
    detail: str
```

- [ ] **Step 2: Implement `api/v1/sources.py`**

```python
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import func, select

from threat_intel.models.collector_run import CollectorRun
from threat_intel.models.source import Source
from threat_intel.schemas.api.sources import CollectorRunOut, SourceHealth

router = APIRouter(prefix="/sources", tags=["sources"])


@router.get("", response_model=list[SourceHealth])
async def list_sources(request: Request) -> list[SourceHealth]:
    sf = request.app.state.session_factory
    cutoff = datetime.now(UTC) - timedelta(hours=24)
    async with sf() as session:
        rows = (await session.execute(select(Source))).scalars().all()
        out: list[SourceHealth] = []
        for src in rows:
            count = (
                await session.execute(
                    select(func.coalesce(func.sum(CollectorRun.events_new + CollectorRun.events_updated), 0))
                    .where(CollectorRun.source_id == src.id, CollectorRun.started_at >= cutoff)
                )
            ).scalar_one()
            out.append(
                SourceHealth(
                    name=src.name, enabled=src.enabled,
                    last_run_at=src.last_run_at, last_success_at=src.last_success_at,
                    consecutive_failures=src.consecutive_failures,
                    current_interval_minutes=src.current_interval_minutes,
                    next_run_at=src.next_run_at, events_24h=int(count),
                )
            )
    return out


@router.get("/{source_id}/runs", response_model=list[CollectorRunOut])
async def list_source_runs(source_id: int, request: Request) -> list[CollectorRunOut]:
    sf = request.app.state.session_factory
    async with sf() as session:
        src = (await session.execute(select(Source).where(Source.id == source_id))).scalar_one_or_none()
        if src is None:
            raise HTTPException(status_code=404, detail="Source not found")
        runs = (
            await session.execute(
                select(CollectorRun)
                .where(CollectorRun.source_id == source_id)
                .order_by(CollectorRun.started_at.desc())
                .limit(50)
            )
        ).scalars().all()
    return [CollectorRunOut(
        id=r.id, started_at=r.started_at, finished_at=r.finished_at,
        status=r.status.value, events_fetched=r.events_fetched, events_new=r.events_new,
        events_updated=r.events_updated, events_failed=r.events_failed,
        error_message=r.error_message, duration_ms=r.duration_ms,
    ) for r in runs]
```

- [ ] **Step 3: Implement `api/v1/indicators.py`**

```python
from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import select

from threat_intel.models.base import IndicatorType
from threat_intel.models.threat import Threat
from threat_intel.models.threat_indicator import ThreatIndicator
from threat_intel.schemas.threat import ThreatOut

router = APIRouter(prefix="/indicators", tags=["indicators"])


@router.get("", response_model=list[ThreatOut])
async def find_threats_by_indicator(
    request: Request,
    type: str = Query(..., description="One of: cve, ghsa, cpe, package, ip, domain, url, md5, sha1, sha256"),
    value: str = Query(..., min_length=1, max_length=512),
) -> list[ThreatOut]:
    try:
        ind_type = IndicatorType(type)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid indicator type: {type}") from e
    sf = request.app.state.session_factory
    async with sf() as session:
        threat_ids = (
            await session.execute(
                select(ThreatIndicator.threat_id).where(
                    ThreatIndicator.indicator_type == ind_type,
                    ThreatIndicator.value == value,
                )
            )
        ).scalars().all()
        if not threat_ids:
            return []
        threats = (
            await session.execute(select(Threat).where(Threat.id.in_(threat_ids)))
        ).scalars().all()
    return [ThreatOut.model_validate(t, from_attributes=True) for t in threats]
```

- [ ] **Step 4: Add `/threats/{id}/sources` to existing `api/v1/threats.py`**

```python
@router.get("/{threat_id}/sources", response_model=list[ThreatSourceOut])
async def list_threat_sources(threat_id: uuid.UUID, request: Request):
    sf = request.app.state.session_factory
    async with sf() as session:
        rows = (
            await session.execute(
                select(ThreatSource, Source.name)
                .join(Source, ThreatSource.source_id == Source.id)
                .where(ThreatSource.threat_id == threat_id)
            )
        ).all()
    return [
        ThreatSourceOut(
            source_name=name,
            external_id=ts.external_id,
            first_seen_at=ts.first_seen_at,
            last_seen_at=ts.last_seen_at,
            tags=ts.tags,
        )
        for ts, name in rows
    ]
```

- [ ] **Step 5: Add admin collector endpoints to `api/v1/admin.py`**

```python
@router.post("/collectors/{name}/trigger", response_model=CollectorActionResult)
async def trigger_collector(name: str, request: Request, background: BackgroundTasks):
    sf = request.app.state.session_factory
    async with sf() as session:
        src = (await session.execute(select(Source).where(Source.name == name))).scalar_one_or_none()
        if src is None:
            raise HTTPException(status_code=404, detail=f"Unknown collector: {name}")
    background.add_task(request.app.state.ingestion.run, name)
    return CollectorActionResult(name=name, enabled=True, next_run_at=None, detail="Run dispatched")


@router.post("/collectors/{name}/enable", response_model=CollectorActionResult)
async def enable_collector(name: str, request: Request):
    sf = request.app.state.session_factory
    async with sf() as session:
        src = (await session.execute(select(Source).where(Source.name == name))).scalar_one_or_none()
        if src is None:
            raise HTTPException(status_code=404, detail=f"Unknown collector: {name}")
        src.enabled = True
        src.consecutive_failures = 0
        src.current_interval_minutes = src.base_interval_minutes
        src.next_run_at = datetime.now(UTC)
        await session.commit()
    return CollectorActionResult(name=name, enabled=True, next_run_at=src.next_run_at.isoformat(), detail="Enabled")


@router.post("/collectors/{name}/disable", response_model=CollectorActionResult)
async def disable_collector(name: str, request: Request):
    sf = request.app.state.session_factory
    async with sf() as session:
        src = (await session.execute(select(Source).where(Source.name == name))).scalar_one_or_none()
        if src is None:
            raise HTTPException(status_code=404, detail=f"Unknown collector: {name}")
        src.enabled = False
        await session.commit()
    return CollectorActionResult(name=name, enabled=False, next_run_at=None, detail="Disabled")
```

- [ ] **Step 6: Register the new routers in `api/v1/__init__.py`**

Add `router.include_router(sources.router)` and `router.include_router(indicators.router)`.

- [ ] **Step 7: Write integration tests for each endpoint**

Each test follows the pattern in existing `tests/integration/api/`. Key cases:

- `GET /sources` returns 3 sources (NVD/KEV/GHSA) with `events_24h` accurate.
- `GET /sources/{id}/runs` returns sorted by `started_at desc`, limited to 50; 404 on unknown id.
- `GET /threats/{id}/sources` returns all ThreatSource for a threat.
- `GET /indicators?type=cve&value=CVE-X` returns matching threats; `400` on bad type; empty list on no match.
- `POST /admin/collectors/nvd/{trigger,enable,disable}` requires `X-Admin-Key`; returns 404 on unknown collector.

- [ ] **Step 8: Run the integration tests**

```bash
pytest tests/integration/api/ -v
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/threat_intel/api/ src/threat_intel/schemas/api/ tests/integration/api/
git commit -m "feat(api): add /sources, /indicators, /threats/{id}/sources, admin collector controls"
```

---

## Task 12: Wire collectors into the app + CISA/GHSA/NVD scheduler registration

**Files:**
- Modify: `src/threat_intel/main.py` (or wherever `create_app` builds the collectors list)

- [ ] **Step 1: Read the current collector registration**

Run: `grep -rn "NVDCollector\|register_jobs\|IngestionService" src/threat_intel/main.py src/threat_intel/core/scheduler.py`.

- [ ] **Step 2: Add `CISAKEVCollector` and `GitHubAdvisoriesCollector` to the collector list at app startup**

In `create_app`'s lifespan / startup section:

```python
from threat_intel.collectors.cisa_kev import CISAKEVCollector
from threat_intel.collectors.github_advisories import GitHubAdvisoriesCollector

collectors = [
    NVDCollector(http_client, settings),
    CISAKEVCollector(http_client, settings),
    GitHubAdvisoriesCollector(http_client, settings),
]
```

(`GitHubAdvisoriesCollector.enabled` is False if no token — the scheduler skips disabled collectors thanks to `Source.enabled` already being False if we propagate that. Add an explicit step at startup: if `collector.enabled is False`, set the matching `Source.enabled = False` in DB.)

- [ ] **Step 3: Run the full test suite**

```bash
pytest -q
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add src/threat_intel/main.py
git commit -m "feat(app): register CISA KEV and GitHub Advisories collectors at startup"
```

---

## Task 13: Documentation

**Files:**
- Modify: `README.md`
- Create: `docs/COLLECTORS.md`
- Create: `docs/INDICATORS.md`
- Modify: `.env.example` (already done in Task 1, just verify)

- [ ] **Step 1: Update `README.md`**

In the "Sources" section (create if absent), insert:

```markdown
| Source | Type | Frequency | Auth | Doc link |
|---|---|---|---|---|
| NVD | REST/JSON | 60 min | Optional API key (`NVD_API_KEY`) | [NVD CVE 2.0](https://nvd.nist.gov/developers/vulnerabilities) |
| CISA KEV | REST/JSON | 360 min | None | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| GitHub Security Advisories | GraphQL | 120 min | `GITHUB_TOKEN` (no scope) | [GHSA GraphQL](https://docs.github.com/graphql/reference/objects#securityadvisory) |
```

Update the Mermaid pipeline diagram to show three sources fanning into `IngestService → Threat / ThreatSource / ThreatIndicator`.

- [ ] **Step 2: Write `docs/COLLECTORS.md`**

```markdown
# Adding a new collector

Step-by-step checklist for a new threat-intel source.

1. Pick a base class:
   - REST/JSON API → `APIRestCollector`
   - GraphQL → `APIGraphQLCollector`
2. Create `src/threat_intel/collectors/<name>.py`:
   - `source_name` (snake_case)
   - `source_kind` (`SourceKind.cve_feed`, `ioc_feed`, etc.)
   - `base_interval_minutes`
   - implement `fetch(self, since)` (async generator yielding `RawEvent`)
   - implement `to_event(self, raw)` (returns `CollectedEvent`)
3. Tags: list every tag your source contributes in the `CollectedEvent.tags` field.
4. Indicators: emit at minimum a `(cve, ...)` indicator if your source publishes CVEs (this is the dedup key with NVD/KEV/GHSA).
5. Add a row to the `source` table via a new Alembic migration.
6. Tests:
   - Fixture file under `tests/fixtures/<name>_sample.json`
   - Unit test `tests/unit/collectors/test_<name>.py`: `fetch` happy path with `respx`, `to_event` mapping table.
7. Update `src/threat_intel/main.py` to register the collector at startup.

## raw_data conventions

`recompute_canonical()` reads canonical-candidate fields from `ThreatSource.raw_data`. Your `to_event()` MUST populate at least these keys when known:
`title`, `summary`, `severity`, `cvss_score`, `cvss_vector`, `cvss_version`, `cwe_ids`, `references`, `affected_products`. The original payload should live under `_payload`.
```

- [ ] **Step 3: Write `docs/INDICATORS.md`**

```markdown
# Indicator types and queries

| Type | Description | Example value |
|---|---|---|
| `cve` | CVE identifier | `CVE-2021-44228` |
| `ghsa` | GitHub Security Advisory id | `GHSA-jfh8-c2jp-5v3q` |
| `cpe` | NVD CPE name | `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*` |
| `package` | Ecosystem-prefixed package name | `npm:lodash` |
| `ip` / `domain` / `url` | Network IOC (reserved for future collectors) | |
| `md5` / `sha1` / `sha256` | File hash IOC (reserved for future collectors) | |

## Lookup

```
GET /api/v1/indicators?type=cve&value=CVE-2021-44228
GET /api/v1/indicators?type=package&value=npm:lodash
```

Returns the list of `Threat` documents that have at least one matching indicator.
```

- [ ] **Step 4: Commit**

```bash
git add README.md docs/COLLECTORS.md docs/INDICATORS.md
git commit -m "docs: M3a — sources table, collector authoring guide, indicator catalogue"
```

---

## Task 14: Final verification + demo run

**Files:** none (operational task).

- [ ] **Step 1: Run the full test suite + coverage**

```bash
pytest --cov=threat_intel --cov-report=term-missing -q
```

Expected: PASS, coverage on new code ≥ 85%. Note any gaps and add tests for them inside the closest existing test file.

- [ ] **Step 2: Run mypy and ruff**

```bash
ruff check src tests
mypy --strict src
```

Expected: clean.

- [ ] **Step 3: Smoke-test against Postgres locally**

```bash
docker-compose up -d db
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/threat_intel \
  .venv/bin/alembic upgrade head
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/threat_intel \
  GITHUB_TOKEN=ghp_xxx \
  .venv/bin/uvicorn threat_intel.main:app --port 8000 &
```

Trigger each collector via the admin endpoint and verify rows land in the DB:

```bash
curl -X POST -H "X-Admin-Key: $ADMIN_KEY" http://localhost:8000/api/v1/admin/collectors/cisa_kev/trigger
curl -X POST -H "X-Admin-Key: $ADMIN_KEY" http://localhost:8000/api/v1/admin/collectors/github_advisories/trigger
curl -X POST -H "X-Admin-Key: $ADMIN_KEY" http://localhost:8000/api/v1/admin/collectors/nvd/trigger
```

Wait ~30 s, then:

```bash
curl http://localhost:8000/api/v1/sources | jq
curl 'http://localhost:8000/api/v1/indicators?type=cve&value=CVE-2021-44228' | jq
# Pick a threat id from the previous response, then:
curl http://localhost:8000/api/v1/threats/<id>/sources | jq
```

Expected: at least one Log4Shell-class CVE present in 2+ sources, with sources confirming the dedup.

- [ ] **Step 4: Tear down**

```bash
kill %1
docker-compose down
```

- [ ] **Step 5: Push the branch**

Push to a `feat/m3a-multi-source-dedup` branch and open a PR against `dev`.

```bash
git push -u origin feat/m3a-multi-source-dedup
gh pr create --base dev --title "M3a: CISA KEV + GitHub Advisories + cross-source dedup" --body "$(cat <<'EOF'
## Summary
- Adds CISA KEV and GitHub Security Advisories collectors (3 sources total)
- Refactors collector hierarchy: `BaseCollector` → `APIRestCollector` / `APIGraphQLCollector`
- Cross-source deduplication via `threat_indicators (type, value)` lookup; one Threat per CVE-ID, multiple `ThreatSource` rows
- Adds `recompute_canonical()` for deterministic field-level priority (NVD → GHSA → KEV)
- Extends the sectoral scoring with KEV / actively-exploited / multi-source / package-match signals
- Adds `/sources`, `/indicators`, `/threats/{id}/sources`, admin `/collectors/{name}/{trigger,enable,disable}`
- Backoff per collector, isolated dispatch, `CollectorRun` history
- Migration `0003` migrates NVD-only data to the new schema in place

## Test plan
- [ ] Unit + integration tests pass (`pytest -q`)
- [ ] Coverage ≥ 85% on new code
- [ ] mypy --strict clean
- [ ] Local smoke run with Postgres confirms 3 sources ingest and dedup
- [ ] Production-like deploy to Railway succeeds (CI gate)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-review checklist (run inline before handing off)

- **Spec coverage:** every section in the spec is implemented in a task. Section 4.5 `partial` status → Task 10 step 3. Section 5.3 sanitization → Task 8 (`bleach.clean`). Section 8 scoring criteria → Task 9 with one constant per criterion. Section 9 endpoints → Task 11. Section 11 critical tests → Tasks 6, 7, 8, 10, 11.
- **Placeholder scan:** no "TBD" / "implement later" / "similar to". Task 10 Step 3 deliberately leaves the `IngestionService.run` body to the engineer because it is large and would obscure the plan; the rules to apply are spelled out concretely (states, counters, backoff math). Acceptable.
- **Type consistency:** `CollectedEvent`, `CollectedIndicator`, `IngestService.process`, `recompute_canonical`, `IndicatorType`, `CollectorRunStatus` all referenced consistently. The deletion of `analyzers/dedup.py` (Task 6 Step 9) means callers must be updated — Task 6 Step 10 handles `services/ingestion.py`. Worth grepping at Step 9 to catch any other call site.
