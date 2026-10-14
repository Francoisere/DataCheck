"""
Configuración centralizada de la aplicación usando Pydantic Settings.
Soporta variables de entorno y valores por defecto para desarrollo y producción.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    PORT: int = 8000
    SCAN_TIMEOUT_SECONDS: float = 25.0
    SCAN_PAGE_TIMEOUT_MS: int = 15000
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres_pass@localhost:5432/privacy_audit"
    
    # Restricciones operativas (Privacy by Design DA-04)
    MAX_SNIPPET_LENGTH: int = 300

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
