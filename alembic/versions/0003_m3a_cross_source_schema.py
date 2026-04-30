"""M3a cross-source schema: threat_source, threat_indicator, collector_run, source extensions

Revision ID: 0003_m3a_cross_source_schema
Revises: 994ed3da0eaa
Create Date: 2026-04-29

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

import threat_intel.models.base

# revision identifiers, used by Alembic.
revision: str = "0003_m3a_cross_source_schema"
down_revision: Union[str, Sequence[str], None] = "994ed3da0eaa"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _json_dump(v, default=None):
    import json
    if v is None:
        return json.dumps(default if default is not None else [])
    return json.dumps(v)


def _extract_cpes(raw_data) -> list:
    import json
    if isinstance(raw_data, str):
        try:
            raw_data = json.loads(raw_data)
        except (TypeError, ValueError):
            return []
    if not isinstance(raw_data, dict):
        return []
    cve = raw_data.get("cve") or raw_data
    cpes: list = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                c = match.get("criteria")
                if c and c not in cpes:
                    cpes.append(c)
    return cpes


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
                "raw": raw_data if isinstance(raw_data, str) else _json_dump(raw_data, default={}),
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
            "TRUE, 360, 360, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) "
            "ON CONFLICT (name) DO NOTHING"
        )
    )
    bind.execute(
        sa.text(
            "INSERT INTO source (name, kind, url, enabled, base_interval_minutes, "
            "current_interval_minutes, consecutive_failures, created_at, updated_at) "
            "VALUES ('github_advisories', 'advisory', "
            "'https://api.github.com/graphql', "
            "TRUE, 120, 120, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) "
            "ON CONFLICT (name) DO NOTHING"
        )
    )


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
        sa.Column(
            "raw_data",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=False,
            server_default="{}",
        ),
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
        batch.drop_index("ix_threat_source_id")
        batch.drop_column("source_id")
        batch.drop_column("external_id")
        batch.drop_column("description")
        batch.drop_column("affected_products")
        batch.drop_column("references_json")
        batch.drop_column("raw_data")
    op.create_index("ix_threat_threat_type", "threat", ["threat_type"])


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
        batch.create_unique_constraint("uq_threat_source_external", ["source_id", "external_id"])
        batch.create_index("ix_threat_source_id", ["source_id"])

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
