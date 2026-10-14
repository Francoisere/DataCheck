"""
Gestión de sesión asíncrona de base de datos con SQLAlchemy 2.0 y asyncpg.
"""

from typing import AsyncGenerator
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
    """Crea las tablas en la base de datos si no existen."""
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as e:
        # Registrar advertencia sin detener la API si la DB aún no está lista
        print(f"[WARN] No se pudo conectar a la base de datos para init_db: {e}")
