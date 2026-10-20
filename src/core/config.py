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

    # Configuración de Servidor de Correo (SMTP)
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 1025
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = "alertas@datacheck.cl"
    SMTP_TLS: bool = False

    # Intervalo de sondeo del scheduler en segundos (default: cada 30 segundos)
    SCHEDULER_CHECK_INTERVAL_SECONDS: int = 30

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
