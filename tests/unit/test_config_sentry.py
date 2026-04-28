from threat_intel.core.config import Settings


def test_sentry_dsn_defaults_to_none(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    s = Settings()
    assert s.sentry_dsn is None


def test_sentry_dsn_loaded_from_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("SENTRY_DSN", "https://abc@sentry.io/123")
    s = Settings()
    assert s.sentry_dsn == "https://abc@sentry.io/123"


def test_sentry_dsn_blank_string_yields_none(monkeypatch):
    """Blank value is the standard 'feature off' signal in this codebase."""
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("SENTRY_DSN", "")
    s = Settings()
    assert s.sentry_dsn is None


def test_sentry_environment_defaults_to_prod(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.delenv("SENTRY_ENVIRONMENT", raising=False)
    s = Settings()
    assert s.sentry_environment == "prod"


def test_sentry_environment_overridable(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("SENTRY_ENVIRONMENT", "staging")
    s = Settings()
    assert s.sentry_environment == "staging"
