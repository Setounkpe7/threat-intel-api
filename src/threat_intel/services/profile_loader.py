"""SectorProfileLoader — read YAML files under profiles/{public,private}/ and upsert (M2)."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import structlog
import yaml
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threat_intel.models.sector_profile import SectorProfile
from threat_intel.schemas.sector_profile import SectorProfileSchema

logger = structlog.get_logger(__name__)


@dataclass
class LoadResult:
    public_count: int = 0
    private_count: int = 0
    added: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)  # (file_path, message)

    def __str__(self) -> str:
        return (
            f"public={self.public_count} private={self.private_count} "
            f"added={len(self.added)} updated={len(self.updated)} "
            f"removed={len(self.removed)} errors={len(self.errors)}"
        )


class SectorProfileLoader:
    """Loads `profiles/<visibility>/*.yaml` into the `sector_profile` table.

    - Both `public/` and `private/` are scanned recursively. Either may be absent.
    - Each YAML is validated against `SectorProfileSchema`. On failure, a warning
      is logged and the file is skipped — other files still load.
    - Visibility is inferred from the parent folder. If the YAML declares a
      `visibility` that conflicts, the file is rejected.
    - Duplicate ids across files are an error on the *second* occurrence (first
      one wins, second is logged and skipped).
    """

    PUBLIC_DIR = "public"
    PRIVATE_DIR = "private"

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        profiles_root: Path,
    ) -> None:
        self._sf = session_factory
        self._root = profiles_root

    async def load_all(self, *, remove_missing: bool = False) -> LoadResult:
        """Scan disk, upsert profiles, return a summary.

        If `remove_missing=True`, profiles previously loaded from disk
        (i.e. `source_file is not None`) but no longer present are deleted.
        Profiles created via other means (source_file is None) are never deleted.
        """
        result = LoadResult()
        seen_ids: set[str] = set()
        parsed: list[tuple[SectorProfileSchema, Path]] = []

        for visibility, subdir in (
            ("public", self.PUBLIC_DIR),
            ("private", self.PRIVATE_DIR),
        ):
            folder = self._root / subdir
            if not folder.is_dir():
                logger.info("profile_folder_missing", path=str(folder), visibility=visibility)
                continue
            files = sorted(folder.rglob("*.yaml")) + sorted(folder.rglob("*.yml"))
            for path in files:
                profile = self._parse_one(path, visibility, seen_ids, result)
                if profile is None:
                    continue
                seen_ids.add(profile.id)
                parsed.append((profile, path))
                if visibility == "public":
                    result.public_count += 1
                else:
                    result.private_count += 1

        await self._upsert_many(parsed, result)

        if remove_missing:
            await self._remove_stale(seen_ids, result)

        logger.info("sector_profiles_loaded", summary=str(result))
        return result

    def _parse_one(
        self,
        path: Path,
        visibility: str,
        seen_ids: set[str],
        result: LoadResult,
    ) -> SectorProfileSchema | None:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            msg = f"YAML parse error: {e}"
            logger.warning("profile_yaml_invalid", path=str(path), error=msg)
            result.errors.append((str(path), msg))
            return None
        except OSError as e:
            msg = f"I/O error: {e}"
            logger.warning("profile_read_failed", path=str(path), error=msg)
            result.errors.append((str(path), msg))
            return None

        if not isinstance(raw, dict):
            msg = "YAML root must be a mapping"
            logger.warning("profile_yaml_not_mapping", path=str(path))
            result.errors.append((str(path), msg))
            return None

        try:
            profile = SectorProfileSchema.model_validate(raw)
        except ValidationError as e:
            msg = f"schema validation failed: {e.errors()}"
            logger.warning("profile_schema_invalid", path=str(path), errors=e.errors())
            result.errors.append((str(path), msg))
            return None

        if profile.visibility is not None and profile.visibility != visibility:
            msg = (
                f"visibility mismatch: file in '{visibility}/' declares "
                f"visibility={profile.visibility!r}"
            )
            logger.warning(
                "profile_visibility_mismatch",
                path=str(path),
                folder_visibility=visibility,
                yaml_visibility=profile.visibility,
            )
            result.errors.append((str(path), msg))
            return None

        if profile.id in seen_ids:
            msg = f"duplicate profile id {profile.id!r} (already loaded from another file)"
            logger.warning("profile_duplicate_id", path=str(path), id=profile.id)
            result.errors.append((str(path), msg))
            return None

        # Inject the inferred visibility so the upsert stage doesn't have to know about folders.
        return profile.model_copy(update={"visibility": visibility})

    async def _upsert_many(
        self,
        parsed: list[tuple[SectorProfileSchema, Path]],
        result: LoadResult,
    ) -> None:
        if not parsed:
            return
        now = datetime.now(UTC)
        async with self._sf() as session:
            existing_ids = await self._existing_ids(session, [p.id for p, _ in parsed])
            for profile, path in parsed:
                values = {
                    "id": profile.id,
                    "name": profile.name,
                    "sector": profile.sector,
                    "description": profile.description,
                    "keywords": profile.keywords,
                    "technologies": profile.technologies,
                    "cwe_priorities": profile.cwe_priorities,
                    "excluded_keywords": profile.excluded_keywords,
                    "compliance": profile.compliance,
                    "priority_boost_keywords": profile.priority_boost_keywords,
                    "cvss_threshold": profile.cvss_threshold,
                    "visibility": profile.visibility or "public",
                    "source_file": str(path),
                    "loaded_at": now,
                }
                if profile.id in existing_ids:
                    row = await session.get(SectorProfile, profile.id)
                    assert row is not None
                    for k, v in values.items():
                        setattr(row, k, v)
                    result.updated.append(profile.id)
                else:
                    session.add(SectorProfile(**values))
                    result.added.append(profile.id)
            await session.commit()

    @staticmethod
    async def _existing_ids(session: AsyncSession, ids: list[str]) -> set[str]:
        if not ids:
            return set()
        rows = await session.execute(
            select(SectorProfile.id).where(SectorProfile.id.in_(ids))
        )
        return {r[0] for r in rows.all()}

    async def _remove_stale(self, kept_ids: set[str], result: LoadResult) -> None:
        async with self._sf() as session:
            rows = await session.execute(
                select(SectorProfile).where(SectorProfile.source_file.is_not(None))
            )
            stale = [p for p in rows.scalars().all() if p.id not in kept_ids]
            for p in stale:
                await session.delete(p)
                result.removed.append(p.id)
            if stale:
                await session.commit()


__all__ = ["SectorProfileLoader", "LoadResult"]
