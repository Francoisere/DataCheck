"""
Gestión de sesión asíncrona de base de datos con SQLAlchemy 2.0 y asyncpg.
"""

from typing import AsyncGenerator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase

from src.core.config import settings


class Base(DeclarativeBase):
    """Clase base declarativa para todos los modelos ORM."""
    pass


# Crear motor asíncrono
# Si no hay PostgreSQL disponible (ej: pruebas unitarias locales sin docker),
# se puede utilizar sqlite+aiosqlite o manejar degradación elegante.
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=True
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependencia FastAPI para inyectar sesiones de base de datos."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Crea las tablas en la base de datos si no existen y sincroniza columnas/índices incrementales."""
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            if conn.dialect.name == "postgresql":
                migration_statements = [
                    "ALTER TABLE hallazgos ADD COLUMN IF NOT EXISTS auditoria_id UUID REFERENCES auditorias(id) ON DELETE CASCADE",
                    "ALTER TABLE hallazgos ADD COLUMN IF NOT EXISTS pilar VARCHAR(50)",
                    "ALTER TABLE hallazgos ALTER COLUMN resultado_pilar_id DROP NOT NULL",
                    "ALTER TABLE auditorias ALTER COLUMN score DROP NOT NULL",
                    "CREATE INDEX IF NOT EXISTS ix_hallazgos_auditoria_id ON hallazgos (auditoria_id)",
                    "CREATE INDEX IF NOT EXISTS ix_auditorias_sitio_fecha ON auditorias (sitio_id, ejecutada_en)",
                    "CREATE INDEX IF NOT EXISTS idx_auditorias_sitio_validas_fecha ON auditorias (sitio_id, ejecutada_en) WHERE page_load_status = 1",
                ]
                for stmt in migration_statements:
                    await conn.execute(text(stmt))
    except Exception as e:
        # Registrar advertencia sin detener la API si la DB aún no está lista
        print(f"[WARN] No se pudo conectar a la base de datos para init_db: {e}")
