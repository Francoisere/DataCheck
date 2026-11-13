"""
Endpoints REST de Historial Evolutivo por Dominio y Comparador de Regresiones ("Antes vs. Después").
Cumple con RF-HIST-01, RF-HIST-02, RF-HIST-03 y RNF-PERF-01:
- GET /api/v1/sites/{domain}/history
- GET /api/v1/audits/{audit_id}/diff
"""

import uuid
from urllib.parse import urlsplit
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.schemas import AuditDiffResponse, SiteHistoryResponse
from src.db.repositories.audit_repository import AuditRepository
from src.db.session import get_db_session
from src.services.comparison_service import ComparisonService

router = APIRouter(prefix="/api/v1", tags=["Historial y Comparador Evolutivo"])


def normalize_domain_param(raw_domain: str) -> str:
    """
    Normaliza el parámetro de dominio removiendo esquemas (http/https),
    credenciales, puertos, rutas y fragmentos.
    """
    cleaned = (raw_domain or "").strip().lower()
    if not cleaned:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El dominio consultado no puede estar vacío.",
        )
    if "://" not in cleaned:
        cleaned = "https://" + cleaned
    parsed = urlsplit(cleaned)
    host = parsed.hostname or ""
    if not host:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Formato de dominio inválido.",
        )
    return host.lower()


@router.get(
    "/sites/{domain:path}/history",
    response_model=SiteHistoryResponse,
    summary="Obtener historial cronológico y tendencia evolutiva de un dominio (RF-HIST-01)",
)
async def get_site_history(
    domain: str,
    limit: int = Query(10, ge=1, le=100, description="Cantidad máxima de auditorías en la línea de tiempo"),
    db: AsyncSession = Depends(get_db_session),
):
    """
    Retorna todas las auditorías ejecutadas sobre un dominio ordenadas descendentemente
    por fecha junto con el delta de puntaje acumulado.
    """
    clean_domain = normalize_domain_param(domain)
    audits = await AuditRepository.get_audits_by_domain(db, clean_domain)
    if not audits:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"El dominio '{clean_domain}' nunca ha sido auditado en la plataforma.",
        )

    return ComparisonService.build_domain_history(
        domain=clean_domain,
        audits_desc=audits,
        limit=limit,
    )


@router.get(
    "/audits/{audit_id}/diff",
    response_model=AuditDiffResponse,
    response_model_by_alias=True,
    summary="Obtener comparativa detallada 'Antes vs. Después' de una auditoría (RF-HIST-02 / RF-HIST-03)",
)
async def get_audit_diff(
    audit_id: str,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Compara la auditoría indicada contra la auditoría válida (page_load_status == 1)
    inmediatamente anterior del mismo sitio web, clasificando rastreadores en
    REMEDIATED, PERSISTENT y REGRESSION.
    """
    try:
        val_uuid = uuid.UUID(audit_id)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El identificador de auditoría provisto no tiene un formato UUID válido.",
        )

    current_audit = await AuditRepository.get_audit_with_details(db, val_uuid)
    if not current_audit:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No se encontró ninguna auditoría con ID: {audit_id}",
        )

    previous_audit = await AuditRepository.get_previous_valid_audit(
        db=db,
        sitio_id=current_audit.sitio_id,
        current_executed_at=current_audit.ejecutada_en,
        current_audit_id=current_audit.id,
    )

    return ComparisonService.compare_audits(
        current_audit=current_audit,
        previous_audit=previous_audit,
    )
