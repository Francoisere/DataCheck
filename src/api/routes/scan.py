"""
Endpoints de escaneo pasivo y auditoría (C-01 / C-02).
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from src.api.schemas import ScanRequest, ScanResponse
from src.services.audit_service import AuditService
from src.db.session import get_db_session

router = APIRouter(prefix="/api/v1", tags=["Auditoría de Cumplimiento"])
audit_service = AuditService()


@router.post("/scan", response_model=ScanResponse, summary="Auditar sitio web (POST)")
async def run_scan_post(
    request: ScanRequest,
    db: Optional[AsyncSession] = Depends(get_db_session)
):
    """
    Ejecuta una auditoría pasiva completa:
    1. Sanitiza y normaliza la URL eliminando credenciales o tokens.
    2. Inspecciona el sitio pasivamente con Playwright (timeout 25s).
    3. Evalúa el cumplimiento normativo (Ley N° 19.628) y genera tickets técnicos de remediación.
    4. Persiste los resultados inmutables en base de datos PostgreSQL.
    """
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="La URL provista no puede estar vacía.")

    try:
        return await audit_service.execute_audit(raw_url=url, db_session=db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error durante el escaneo: {str(e)}")


@router.get("/scan", response_model=ScanResponse, summary="Auditar sitio web (GET para Bookmarklet)")
async def run_scan_get(
    url: str = Query(..., description="URL a auditar vía GET (útil para Bookmarklets)"),
    db: Optional[AsyncSession] = Depends(get_db_session)
):
    """
    Endpoint GET para ejecutar auditorías directas desde la barra de marcadores del navegador.
    """
    cleaned_url = url.strip()
    if not cleaned_url:
        raise HTTPException(status_code=400, detail="El parámetro 'url' es requerido.")

    try:
        return await audit_service.execute_audit(raw_url=cleaned_url, db_session=db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error durante el escaneo: {str(e)}")
