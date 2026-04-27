from threat_intel.core.config import Settings


def test_inline_comments_stripped_from_string_fields(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("APP_ENV", "dev                    # dev | prod")
    monkeypatch.setenv("NVD_BASE_URL", "https://x.test  # base")
    s = Settings()
    assert s.app_env == "dev"
    assert s.nvd_base_url == "https://x.test"


def test_nvd_api_key_inline_comment_yields_none(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("NVD_API_KEY", "                   # optional, leave empty")
    s = Settings()
    assert s.nvd_api_key is None


def test_nvd_api_key_real_value_preserved(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("NVD_API_KEY", "abcd-1234-real-key")
    s = Settings()
    assert s.nvd_api_key == "abcd-1234-real-key"


def test_cors_origins_inline_comment_stripped(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("CORS_ORIGINS", "https://a.com,https://b.com  # whitelist")
    s = Settings()
    assert s.cors_origins == ["https://a.com", "https://b.com"]


def test_whitespace_only_value_handled(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("NVD_API_KEY", "                   ")
    s = Settings()
    assert s.nvd_api_key is None
