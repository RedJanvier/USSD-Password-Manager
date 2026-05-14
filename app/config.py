from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = Field(default="sqlite+aiosqlite:///./vault.db", alias="DATABASE_URL")
    app_pepper: str = Field(alias="APP_PEPPER")

    at_username: str = Field(default="sandbox", alias="AT_USERNAME")
    at_api_key: str = Field(default="", alias="AT_API_KEY")
    at_shortcode: str = Field(default="*384*0#", alias="AT_SHORTCODE")

    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

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
