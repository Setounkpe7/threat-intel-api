from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


def _strip_inline_comment(value: str) -> str:
    """Strip leading/trailing whitespace AND inline ' # ...' or '\\t# ...' suffix.

    Workaround for python-dotenv / docker-compose env_file not stripping inline
    comments on unquoted values. Also treats values consisting only of leading
    whitespace followed by '#...' as fully-commented (returns empty string).
    """
    # Detect "whitespace-only prefix + # comment" forms by checking the original
    # string before we strip — if the first non-space character is '#', the entire
    # value is effectively a comment.
    lstripped = value.lstrip()
    if lstripped.startswith("#"):
        return ""
    s = value.strip()
    for sep in (" #", "\t#"):
        if sep in s:
            s = s.split(sep, 1)[0].rstrip()
            break
    return s


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "threat-intel-api"
    app_env: Literal["dev", "prod"] = "dev"
    log_level: str = "INFO"

    # Optional rotating-file sink (10 MB × 5 by default). Leave unset to keep
    # logs on stdout only — recommended in containers where the orchestrator
    # collects stdout.
    log_file: Path | None = None
    log_file_max_bytes: int = 10 * 1024 * 1024
    log_file_backup_count: int = 5

    database_url: str

    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str | None = None
    nvd_fetch_interval_minutes: int = 60

    profiles_path: Path = Path("profiles")

    # Admin API key required for /api/v1/admin/* and ?visibility=all.
    # Generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"
    admin_api_key: str | None = None

    # Public-endpoint rate limit (slowapi format).
    rate_limit_default: str = "100/minute"
    rate_limit_enabled: bool = True

    # Sentry error tracking. Leave SENTRY_DSN blank to disable.
    sentry_dsn: str | None = None
    sentry_environment: str = "prod"

    @field_validator(
        "app_name",
        "app_env",
        "log_level",
        "database_url",
        "nvd_base_url",
        "sentry_environment",
        mode="before",
    )
    @classmethod
    def _strip_required_string(cls, v: object) -> object:
        if isinstance(v, str):
            return _strip_inline_comment(v)
        return v

    @field_validator("nvd_api_key", "admin_api_key", "sentry_dsn", mode="before")
    @classmethod
    def _strip_optional_string(cls, v: object) -> object:
        if isinstance(v, str):
            cleaned = _strip_inline_comment(v)
            return cleaned or None
        return v

    @field_validator("database_url", mode="after")
    @classmethod
    def _normalize_postgres_scheme(cls, v: str) -> str:
        """Rewrite synchronous 'postgresql://' to 'postgresql+asyncpg://'.

        Railway's managed Postgres exposes DATABASE_URL with the synchronous
        scheme by default. The runtime uses asyncpg and requires the
        '+asyncpg' driver suffix. Other schemes (sqlite+aiosqlite,
        postgresql+psycopg, postgresql+asyncpg) are left untouched.
        """
        if v.startswith("postgresql://"):
            return "postgresql+asyncpg://" + v.removeprefix("postgresql://")
        return v

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_cors(cls, v: object) -> object:
        if isinstance(v, str):
            cleaned = _strip_inline_comment(v)
            return [item.strip() for item in cleaned.split(",") if item.strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
