import json
import os
import uuid

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text


@pytest.fixture
def alembic_cfg(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    # env.py uses async_engine_from_config — must use the async aiosqlite driver.
    async_url = f"sqlite+aiosqlite:///{db_path}"
    # env.py calls get_settings().database_url which reads DATABASE_URL from env.
    # Override it so the migration runs against the temp SQLite file, not prod.
    monkeypatch.setenv("DATABASE_URL", async_url)
    # get_settings() is @lru_cache — clear it so the new DATABASE_URL is picked up.
    from threat_intel.core.config import get_settings
    get_settings.cache_clear()
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", async_url)
    yield cfg, db_path
    # Restore after test: clear cache again so next test re-reads its env
    get_settings.cache_clear()


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
