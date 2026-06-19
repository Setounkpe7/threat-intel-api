from threat_intel.core.config import Settings


def test_settings_loads_from_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@h:5432/db")
    monkeypatch.setenv("CORS_ORIGINS", "https://a.com,https://b.com")
    monkeypatch.setenv("NVD_FETCH_INTERVAL_MINUTES", "30")

    s = Settings()

    assert s.database_url == "postgresql+asyncpg://u:p@h:5432/db"
    assert s.cors_origins == ["https://a.com", "https://b.com"]
    assert s.nvd_fetch_interval_minutes == 30
    assert s.app_env == "dev"  # default


def test_settings_cors_empty_string_yields_empty_list(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("CORS_ORIGINS", "")
    s = Settings()
    assert s.cors_origins == []


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


def test_feeds_path_defaults_to_feeds_dir(monkeypatch):
    from pathlib import Path

    monkeypatch.delenv("FEEDS_PATH", raising=False)
    from threat_intel.core.config import Settings

    settings = Settings(database_url="sqlite+aiosqlite:///:memory:")  # type: ignore[call-arg]
    assert settings.feeds_path == Path("feeds")


def test_dependencies_importable():
    import defusedxml.ElementTree  # noqa: F401

    import feedparser  # noqa: F401
