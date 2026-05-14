from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _normalize_db_url(url: str) -> str:
    """Render/Heroku inject `postgres://...` or `postgresql://...` with no
    driver. SQLAlchemy defaults to psycopg2 (sync) for those, which breaks
    `create_async_engine`. Force the asyncpg driver here; the sync version
    for Alembic is derived from this by stripping the +asyncpg suffix."""
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        url = "postgresql+asyncpg://" + url[len("postgresql://") :]
    if url.startswith("sqlite://") and not url.startswith("sqlite+"):
        url = "sqlite+aiosqlite://" + url[len("sqlite://") :]
    return url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = Field(default="sqlite+aiosqlite:///./vault.db", alias="DATABASE_URL")
    app_pepper: str = Field(alias="APP_PEPPER")

    at_username: str = Field(default="sandbox", alias="AT_USERNAME")
    at_api_key: str = Field(default="", alias="AT_API_KEY")
    at_shortcode: str = Field(default="*384*0#", alias="AT_SHORTCODE")

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    @field_validator("database_url", mode="after")
    @classmethod
    def _normalize(cls, v: str) -> str:
        return _normalize_db_url(v)

    @property
    def pepper_bytes(self) -> bytes:
        # Stored as hex; if a non-hex value sneaks in we still get deterministic bytes
        # by treating it as UTF-8. Production must use hex.
        try:
            return bytes.fromhex(self.app_pepper)
        except ValueError:
            return self.app_pepper.encode("utf-8")

    @property
    def database_url_sync(self) -> str:
        """Sync URL for Alembic (which uses sync drivers)."""
        return (
            self.database_url
            .replace("+asyncpg", "")
            .replace("+aiosqlite", "")
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
