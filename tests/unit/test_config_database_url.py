from threat_intel.core.config import Settings


def test_database_url_postgresql_scheme_normalized_to_asyncpg(monkeypatch):
    """Railway exposes DATABASE_URL with the synchronous 'postgresql://' scheme.
    The app uses asyncpg, which requires 'postgresql+asyncpg://'."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@host:5432/db")
    s = Settings()
    assert s.database_url == "postgresql+asyncpg://u:p@host:5432/db"


def test_database_url_already_async_unchanged(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@host:5432/db")
    s = Settings()
    assert s.database_url == "postgresql+asyncpg://u:p@host:5432/db"


def test_database_url_sqlite_unchanged(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    s = Settings()
    assert s.database_url == "sqlite+aiosqlite:///:memory:"


def test_database_url_other_postgres_drivers_unchanged(monkeypatch):
    """Don't rewrite if the user explicitly chose another driver."""
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@host:5432/db")
    s = Settings()
    assert s.database_url == "postgresql+psycopg://u:p@host:5432/db"


def test_database_url_with_inline_comment_normalized(monkeypatch):
    """Composes with the existing inline-comment stripping validator."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@host/db # railway managed")
    s = Settings()
    assert s.database_url == "postgresql+asyncpg://u:p@host/db"
