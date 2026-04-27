from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select

from threat_intel.core.db import build_engine, session_factory
from threat_intel.models.base import Base
from threat_intel.models.sector_profile import SectorProfile
from threat_intel.services.profile_loader import SectorProfileLoader

VALID_FINANCE = """
id: finance
name: Finance
sector: banking
keywords: [payment, swift]
technologies: [Java, PostgreSQL]
cwe_priorities: [CWE-79, CWE-89]
excluded_keywords: [minecraft]
compliance: [PCI-DSS]
priority_boost_keywords: [wire transfer]
cvss_threshold: 7.5
"""

VALID_HEALTHCARE = """
id: healthcare
name: Healthcare
sector: medical
keywords: [hospital, ehr]
technologies: [HL7]
cwe_priorities: [CWE-732]
excluded_keywords: []
compliance: [HIPAA]
priority_boost_keywords: []
cvss_threshold: 6.5
"""

VALID_CORP = """
id: corp
name: Corp
sector: enterprise
visibility: private
"""

INVALID_BAD_YAML = "id: finance\nname: [unclosed"

INVALID_BAD_SCHEMA = """
id: BAD ID WITH SPACES
name: x
sector: y
"""

INVALID_BAD_CWE = """
id: bad-cwe
name: x
sector: y
cwe_priorities: [not-a-cwe]
"""


@pytest.fixture
async def factory():
    engine = build_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield session_factory(engine)
    await engine.dispose()


def _write_profiles(tmp_path: Path, files: dict[str, str]) -> Path:
    """files keys are like 'public/finance.yaml' or 'private/corp.yaml'."""
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp_path


@pytest.mark.asyncio
async def test_load_public_only_when_private_dir_missing(factory, tmp_path):
    root = _write_profiles(tmp_path, {"public/finance.yaml": VALID_FINANCE})
    loader = SectorProfileLoader(factory, root)
    result = await loader.load_all()
    assert result.public_count == 1
    assert result.private_count == 0
    assert result.added == ["finance"]
    assert result.errors == []


@pytest.mark.asyncio
async def test_load_both_visibilities(factory, tmp_path):
    root = _write_profiles(
        tmp_path,
        {
            "public/finance.yaml": VALID_FINANCE,
            "public/healthcare.yaml": VALID_HEALTHCARE,
            "private/corp.yaml": VALID_CORP,
        },
    )
    loader = SectorProfileLoader(factory, root)
    result = await loader.load_all()
    assert result.public_count == 2
    assert result.private_count == 1
    assert sorted(result.added) == ["corp", "finance", "healthcare"]
    async with factory() as s:
        rows = (await s.execute(select(SectorProfile))).scalars().all()
        by_id = {p.id: p for p in rows}
        assert by_id["finance"].visibility == "public"
        assert by_id["corp"].visibility == "private"
        assert by_id["finance"].source_file.endswith("finance.yaml")
        assert by_id["finance"].cvss_threshold == 7.5


@pytest.mark.asyncio
async def test_malformed_yaml_skipped_others_loaded(factory, tmp_path):
    root = _write_profiles(
        tmp_path,
        {
            "public/finance.yaml": VALID_FINANCE,
            "public/broken.yaml": INVALID_BAD_YAML,
        },
    )
    loader = SectorProfileLoader(factory, root)
    result = await loader.load_all()
    assert result.added == ["finance"]
    assert len(result.errors) == 1
    assert "broken.yaml" in result.errors[0][0]


@pytest.mark.asyncio
async def test_schema_invalid_skipped(factory, tmp_path):
    root = _write_profiles(
        tmp_path,
        {
            "public/finance.yaml": VALID_FINANCE,
            "public/bad_id.yaml": INVALID_BAD_SCHEMA,
            "public/bad_cwe.yaml": INVALID_BAD_CWE,
        },
    )
    loader = SectorProfileLoader(factory, root)
    result = await loader.load_all()
    assert result.added == ["finance"]
    assert len(result.errors) == 2


@pytest.mark.asyncio
async def test_visibility_mismatch_rejected(factory, tmp_path):
    root = _write_profiles(
        tmp_path,
        {"public/corp.yaml": VALID_CORP},  # YAML says private, folder is public
    )
    loader = SectorProfileLoader(factory, root)
    result = await loader.load_all()
    assert result.added == []
    assert len(result.errors) == 1
    assert "visibility mismatch" in result.errors[0][1]


@pytest.mark.asyncio
async def test_duplicate_id_across_files_second_wins_logged(factory, tmp_path):
    root = _write_profiles(
        tmp_path,
        {
            "public/finance_a.yaml": VALID_FINANCE,
            "public/finance_b.yaml": VALID_FINANCE,  # same id
        },
    )
    loader = SectorProfileLoader(factory, root)
    result = await loader.load_all()
    assert result.added == ["finance"]  # only first file accepted
    assert len(result.errors) == 1
    assert "duplicate" in result.errors[0][1].lower()


@pytest.mark.asyncio
async def test_upsert_updates_existing_row(factory, tmp_path):
    root = _write_profiles(tmp_path, {"public/finance.yaml": VALID_FINANCE})
    loader = SectorProfileLoader(factory, root)
    await loader.load_all()

    # Modify the file and reload
    modified = VALID_FINANCE.replace("cvss_threshold: 7.5", "cvss_threshold: 9.0")
    (root / "public" / "finance.yaml").write_text(modified)
    result = await loader.load_all()
    assert result.added == []
    assert result.updated == ["finance"]

    async with factory() as s:
        row = (
            await s.execute(select(SectorProfile).where(SectorProfile.id == "finance"))
        ).scalar_one()
        assert row.cvss_threshold == 9.0


@pytest.mark.asyncio
async def test_remove_missing_only_deletes_disk_sourced(factory, tmp_path):
    root = _write_profiles(
        tmp_path,
        {
            "public/finance.yaml": VALID_FINANCE,
            "public/healthcare.yaml": VALID_HEALTHCARE,
        },
    )
    loader = SectorProfileLoader(factory, root)
    await loader.load_all()

    # Add a profile NOT from disk (source_file is None) — must survive removal
    async with factory() as s:
        s.add(
            SectorProfile(
                id="manual",
                name="Manual",
                sector="custom",
                source_file=None,
                loaded_at=datetime.now(UTC),
            )
        )
        await s.commit()

    # Delete healthcare.yaml from disk and reload with remove_missing=True
    (root / "public" / "healthcare.yaml").unlink()
    result = await loader.load_all(remove_missing=True)
    assert "healthcare" in result.removed
    assert "manual" not in result.removed

    async with factory() as s:
        ids = {r[0] for r in (await s.execute(select(SectorProfile.id))).all()}
        assert ids == {"finance", "manual"}


@pytest.mark.asyncio
async def test_root_dir_missing_returns_empty_result(factory, tmp_path):
    loader = SectorProfileLoader(factory, tmp_path / "does-not-exist")
    result = await loader.load_all()
    assert result.public_count == 0
    assert result.private_count == 0
    assert result.errors == []
