"""Application configuration loaded from environment variables and .env file.

Uses pydantic-settings to provide typed, validated configuration with sensible
defaults for local development.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration for the SentinelAI backend.

    Values are loaded (in priority order) from:
      1. Environment variables
      2. A ``.env`` file in the project root
      3. Defaults defined below
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── AI Provider ──────────────────────────────────────────────────────
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    AI_PROVIDER: str = "mock"  # "openai" | "claude" | "mock"
    OPENAI_MODEL: str = "gpt-4o-mini"
    CLAUDE_MODEL: str = "claude-sonnet-4-20250514"

    # ── Database ─────────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite:///./sentinelai.db"

    # ── Server ───────────────────────────────────────────────────────────
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000

    # ── CORS ─────────────────────────────────────────────────────────────
    CORS_ORIGINS: str = "http://localhost:5173"

    @property
    def cors_origin_list(self) -> list[str]:
        """Parse the comma-separated CORS_ORIGINS string into a list."""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def db_path(self) -> str:
        """Extract the raw file path from the sqlite URL."""
        return self.DATABASE_URL.replace("sqlite:///", "")


settings = Settings()
