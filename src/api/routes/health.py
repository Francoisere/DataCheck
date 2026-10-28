"""
Endpoint de monitoreo y verificación de salud de DataCheck.cl (C-03).
Soporta tanto /healthcheck como /api/v1/health.
Retorna HTTP 200 con 'connected' si la BD responde, o HTTP 503 con 'unreachable' si falla.
"""

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text
from src.db.session import engine

router = APIRouter(tags=["Salud del Sistema"])


async def check_system_health():
    """
    Verifica la disponibilidad del microservicio y la conexión activa con la base de datos.
    """
    db_status = "connected"
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as e:
        try:
            await engine.dispose()
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        except Exception as e2:
            db_status = f"unreachable ({type(e2).__name__})"

    payload = {
        "status": "ok" if db_status == "connected" else "unhealthy",
        "service": "DataCheck.cl Audit Scanner",
        "version": "2.0.0",
        "database": db_status
    }

    if db_status != "connected":
        return JSONResponse(status_code=503, content=payload)
    return payload


@router.get("/healthcheck", summary="Verificar estado operativo del sistema (raíz)")
async def healthcheck_root():
    return await check_system_health()


@router.get("/api/v1/health", summary="Verificar estado operativo del microservicio (/api/v1)")
async def healthcheck_api_v1():
    return await check_system_health()
