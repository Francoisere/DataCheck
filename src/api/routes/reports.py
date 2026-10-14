"""
Endpoints de Reportabilidad PDF (DataCheck.cl).
Cumple con AC-REP-01 y AC-REP-02:
- GET /api/v1/audits/{audit_id}/pdf
  Genera y transmite en streaming el informe formal en formato application/pdf desde PostgreSQL.
- POST /api/v1/audits/generate-pdf
  Genera el informe PDF al vuelo recibiendo el payload completo de la auditoría actual (fallback instantáneo si DB no está conectada).
"""

import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from typing import Dict, Any

from src.db.session import get_db_session
from src.db.models import Auditoria, SitioAnalizado
from src.services.pdf_report_service import PdfReportService

router = APIRouter(prefix="/api/v1/audits", tags=["Reportes de Auditoría"])


@router.post(
    "/generate-pdf",
    summary="Generar informe técnico y legal en formato PDF al vuelo",
    response_class=StreamingResponse
)
async def generate_pdf_from_payload(payload: Dict[str, Any]):
    """
    Genera el informe PDF a partir del payload actual del escaneo.
    Garantiza disponibilidad del PDF tanto en modo persistido como en modo sin base de datos.
    """
    if not payload or not payload.get("target_url"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload de auditoría inválido o vacío."
        )

    dominio = payload.get("target_url", "").replace("https://", "").replace("http://", "").split("/")[0] or "sitio"
    pdf_buffer = PdfReportService.generate_pdf_report(payload)
    filename = f"DataCheck_Auditoria_{dominio}.pdf"

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )


@router.get(
    "/{audit_id}/pdf",
    summary="Descargar informe técnico y legal en formato PDF",
    response_class=StreamingResponse
)
async def download_audit_pdf(
    audit_id: str,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Exporta el reporte formal de diagnóstico de conformidad en PDF.
    - Valida existencia (404 si no existe).
    - Valida que la auditoría haya completado su análisis (400 si page_load_status == 0).
    - Compila en memoria y retorna el archivo binario con cabeceras de descarga.
    """
    try:
        val_uuid = uuid.UUID(audit_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El identificador de auditoría provisto no tiene un formato UUID válido."
        )

    # Consultar auditoría con sus relaciones
    stmt = (
        select(Auditoria)
        .options(
            selectinload(Auditoria.sitio),
            selectinload(Auditoria.resultados_pilares),
            selectinload(Auditoria.evidencias_rastreadores)
        )
        .where(Auditoria.id == val_uuid)
    )
    res = await db.execute(stmt)
    auditoria = res.scalar_one_or_none()

    if not auditoria:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No se encontró ninguna auditoría con ID: {audit_id}"
        )

    # Validar precondición AC-REP-02: rechazar auditorías sin resultados ni pilares
    if not auditoria.resultados_pilares and auditoria.page_load_status == 0 and not auditoria.resumen:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se puede generar el informe PDF porque la auditoría está vacía o corrupta."
        )

    # Reconstruir estructura de datos para el compilador PDF
    sitio_url = auditoria.sitio.url_normalizada if auditoria.sitio else "https://desconocido.cl"
    dominio = auditoria.sitio.dominio if auditoria.sitio else "sitio"

    pilares_dict = {}
    findings_list = []

    for rp in auditoria.resultados_pilares:
        p_key = rp.pilar.lower()
        pilares_dict[p_key] = {
            "status": rp.estado,
            "score": rp.puntaje,
            "max_score": rp.puntaje_max
        }
        from src.db.models import Hallazgo
        h_stmt = select(Hallazgo).where(Hallazgo.resultado_pilar_id == rp.id)
        h_res = await db.execute(h_stmt)
        for h in h_res.scalars().all():
            findings_list.append({
                "pilar": rp.pilar,
                "status": h.severidad,
                "title": h.titulo,
                "detail": h.detalle,
                "technical_raw": h.technical_raw,
                "remediation_ticket": h.recomendacion
            })

    audit_payload = {
        "target_url": sitio_url,
        "page_load_status": auditoria.page_load_status,
        "verdict": auditoria.verdict,
        "score": auditoria.score,
        "verdict_summary": auditoria.resumen,
        "pilares": pilares_dict,
        "findings": findings_list
    }

    pdf_buffer = PdfReportService.generate_pdf_report(audit_payload)
    filename = f"DataCheck_Auditoria_{dominio}_{auditoria.id.hex[:8]}.pdf"

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )
