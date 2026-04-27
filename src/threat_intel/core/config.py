from functools import lru_cache
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

    database_url: str

    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: str | None = None
    nvd_fetch_interval_minutes: int = 60

    @field_validator(
        "app_name", "app_env", "log_level", "database_url", "nvd_base_url",
        mode="before",
    )
    @classmethod
    def _strip_required_string(cls, v: object) -> object:
        if isinstance(v, str):
            return _strip_inline_comment(v)
        return v

    @field_validator("nvd_api_key", mode="before")
    @classmethod
    def _strip_optional_string(cls, v: object) -> object:
        if isinstance(v, str):
            cleaned = _strip_inline_comment(v)
            return cleaned or None
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
