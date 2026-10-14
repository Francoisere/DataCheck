"""
Esquemas de datos Pydantic V2 para la API de DataCheck.cl.
Alineados estrictamente con el contrato OpenAPI C-01 / C-04 del Incremento 2.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    url: str = Field(
        ...,
        examples=["https://tienda-ejemplo.cl"],
        description="URL del sitio web a auditar"
    )


class PilarScore(BaseModel):
    status: str = Field(..., description="Estado del pilar: CUMPLE | OBSERVACION | FALLA")
    score: int = Field(..., description="Puntaje obtenido en el pilar")
    max_score: int = Field(..., description="Puntaje máximo asignable al pilar")


class RemediationFinding(BaseModel):
    pilar: str = Field(..., description="Pilar evaluado (POLITICA_PRIVACIDAD, CANALES_ARCO, CONSENTIMIENTO_COOKIES)")
    status: str = Field(..., description="Severidad del hallazgo: OK | WARNING | FAIL")
    title: str = Field(..., description="Título técnico descriptivo")
    detail: str = Field(..., description="Detalle técnico del hallazgo (máx. 300 caracteres)")
    technical_raw: Optional[str] = Field(None, description="Dato técnico crudo (dominio, cookie, código HTTP)")
    remediation_ticket: str = Field(..., description="Ticket técnico con recomendación accionable para desarrolladores")
    # Sustento normativo Ley 21.719
    articulo_ley: Optional[str] = Field(None, description="Artículo legal vulnerado o conforme (Ley 21.719)")
    principio_vulnerado: Optional[str] = Field(None, description="Principio legal afectado")
    sancion_estimada: Optional[str] = Field(None, description="Rango sancionatorio potencial ante la APDP")


class ScanResponse(BaseModel):
    audit_id: Optional[str] = Field(None, description="Identificador único UUID de la auditoría en PostgreSQL")
    target_url: str = Field(..., description="URL normalizada y auditada")
    page_load_status: int = Field(..., description="1 si cargó correctamente, 0 en caso de error/bloqueo")
    verdict: str = Field(..., description="Dictamen: APROBADO | CON_OBSERVACIONES | RECHAZADO")
    score: int = Field(..., ge=0, le=100, description="Puntaje global consolidado de 0 a 100")
    verdict_summary: str = Field(..., description="Resumen ejecutivo del dictamen")
    pilares: Dict[str, PilarScore] = Field(..., description="Desglose por los 3 pilares legales auditables")
    findings: List[RemediationFinding] = Field(..., description="Lista de evidencias técnicas y tickets de remediación")
    technical_raw: Optional[Dict[str, Any]] = Field(None, description="Metadatos técnicos complementarios")
    legal_disclaimer: str = Field(..., description="Aviso legal de descargo de responsabilidad académica")
    pdf_report_url: Optional[str] = Field(None, description="Enlace para descargar el informe oficial en PDF")

