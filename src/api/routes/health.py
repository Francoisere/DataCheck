"""
Endpoint de monitoreo y verificación de salud de DataCheck.cl (C-03).
"""

from fastapi import APIRouter
from sqlalchemy import text
from src.db.session import engine

router = APIRouter(prefix="/api/v1", tags=["Salud del Sistema"])


@router.get("/health", summary="Verificar estado operativo del microservicio")
async def health_check():
    """
    Verifica la disponibilidad del microservicio y la conexión con PostgreSQL.
    """
    db_status = "connected"
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unreachable ({type(e).__name__})"

    return {
        "status": "ok",
        "service": "DataCheck.cl Audit Scanner",
        "version": "2.0.0",
        "database": db_status
    }
