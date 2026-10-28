"""
Esquemas de datos Pydantic V2 para la API de DataCheck.cl.
Alineados estrictamente con el contrato OpenAPI C-01 / C-04 del Incremento 2.
"""

from typing import List, Dict, Any, Optional, Union
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


class ConsentBannerAudit(BaseModel):
    banner_detected: bool = Field(..., description="Si se detectó un banner/modal de consentimiento de cookies")
    cmp_provider: Optional[str] = Field(None, description="Proveedor CMP identificado (cookiebot, onetrust, didomi, etc.)")
    has_reject_option: bool = Field(False, description="Si el banner ofrece opción real de rechazo")
    has_accept_option: bool = Field(False, description="Si el banner ofrece botón de aceptar")
    has_settings_option: bool = Field(False, description="Si el banner ofrece opción de configurar/personalizar")
    detected_buttons: List[str] = Field(default_factory=list, description="Textos de botones detectados en el banner")
    banner_source_frame: Optional[str] = Field(None, description="URL del frame donde se detectó el banner")
    buttons_verifiable: bool = Field(True, description="Si los controles del banner fueron verificables (False en Shadow DOM cerrado)")
    blocks_prior_to_consent: Optional[bool] = Field(None, description="True si bloquea trackers pre-consentimiento, False si no bloquea, None si no hay banner")


class FrameInfo(BaseModel):
    url: str = Field(..., description="URL o src del frame")
    origin: str = Field(..., description="Origen del frame (scheme + host + port)")
    is_third_party: bool = Field(False, description="Si el frame es de un origen de terceros")
    is_cmp_frame: bool = Field(False, description="Si el frame pertenece a un CMP conocido")
    detected_cmp: Optional[str] = Field(None, description="Nombre del CMP si fue identificado")


class FramesAudit(BaseModel):
    total_frames: int = Field(0, description="Número total de frames detectados")
    third_party_frames: Union[int, List[FrameInfo]] = Field(0, description="Cantidad o lista de frames de terceros")
    cmp_frames: Union[int, List[FrameInfo]] = Field(0, description="Cantidad o lista de frames de CMPs de consentimiento")
    frames: List[FrameInfo] = Field(default_factory=list, description="Lista detallada de frames detectados")


# --- Esquemas para Auditoría de Flujo Multietapa (C-05) ---

class FlowScanRequest(BaseModel):
    """Solicitud de auditoría de flujo de compra/registro."""
    url: str = Field(
        ...,
        examples=["https://tienda-ejemplo.cl"],
        description="URL del sitio web cuyo flujo de compra/registro se auditará"
    )


class FlowStageFinding(BaseModel):
    """Hallazgo específico de una etapa del flujo."""
    stage: str = Field(..., description="Nombre de la etapa (inicio, catalogo, registro, carrito)")
    stage_label: str = Field(..., description="Etiqueta legible de la etapa")
    status: str = Field(..., description="Severidad: OK | WARNING | FAIL")
    title: str = Field(..., description="Título del hallazgo")
    detail: str = Field(..., description="Detalle técnico (máx. 300 caracteres)")
    technical_raw: Optional[str] = Field(None, description="Dato técnico crudo")
    remediation_ticket: str = Field(..., description="Recomendación accionable")


class FlowStageResult(BaseModel):
    """Resultado evaluado de una etapa individual del flujo."""
    stage_name: str = Field(..., description="Nombre de la etapa")
    stage_label: str = Field(..., description="Etiqueta legible")
    url: str = Field(..., description="URL visitada en la etapa")
    verdict: str = Field(..., description="CUMPLE | NO_CUMPLE | NO_VERIFICABLE | NO_ALCANZADA")
    new_tracker_domains: List[str] = Field(default_factory=list, description="Dominios de rastreo nuevos en esta etapa")
    new_tracker_cookies: List[str] = Field(default_factory=list, description="Cookies de rastreo nuevas en esta etapa")


class FlowAuditResponse(BaseModel):
    """Respuesta de auditoría de flujo multietapa (C-05)."""
    target_url: str = Field(..., description="URL auditada")
    flow_detected: bool = Field(..., description="Si se detectó un flujo de compra/registro")
    flow_not_detected_reason: Optional[str] = Field(None, description="Razón si no se detectó flujo")
    flow_verdict: str = Field(..., description="CUMPLE | NO_CUMPLE | NO_VERIFICABLE | NO_APLICABLE")
    flow_verdict_summary: str = Field(..., description="Resumen ejecutivo del dictamen del flujo")
    total_stages_evaluated: int = Field(0, description="Número de etapas evaluadas")
    stages_evaluated: List[FlowStageResult] = Field(default_factory=list, description="Resultados por etapa")
    flow_findings: List[FlowStageFinding] = Field(default_factory=list, description="Hallazgos del flujo")
    limitations: List[str] = Field(default_factory=list, description="Limitaciones declaradas de la inspección")
    legal_disclaimer: str = Field(..., description="Descargo de responsabilidad")


class ResponsiblePartyAudit(BaseModel):
    """Auditoría de transparencia del responsable (Art. 14 ter b y c Ley 21.719)."""
    identified: bool = Field(..., description="Indica si se identificó razón social, RUT o titular de la entidad")
    representative_found: bool = Field(..., description="Si se menciona representante legal")
    dpo_found: bool = Field(..., description="Si se menciona encargado de prevención o DPO (Art. 49/50)")
    contact_channels_found: List[str] = Field(default_factory=list, description="Canales identificados (email, formulario, domicilio)")
    verdict: str = Field(..., description="CUMPLE | OBSERVACION | NO_VERIFICABLE")
    notes: str = Field(..., description="Resumen o justificación técnica de la evaluación")
    corporate_name: Optional[str] = Field(None, description="Razón Social o nombre de la entidad identificada")
    detected_rut: Optional[str] = Field(None, description="RUT de la empresa/responsable identificado")
    contact_email: Optional[str] = Field(None, description="Correo electrónico formal de contacto o notificación")
    postal_address: Optional[str] = Field(None, description="Domicilio postal o dirección detectada")
    dpo_email: Optional[str] = Field(None, description="Correo electrónico específico del Delegado de Protección de Datos (DPO)")


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
    consent_banner_audit: Optional[ConsentBannerAudit] = Field(None, description="Resultado de la detección de banner de consentimiento")
    frames_audit: Optional[FramesAudit] = Field(None, description="Resultado del análisis de frames e iframes")
    responsible_party_audit: Optional[ResponsiblePartyAudit] = Field(None, description="Resultado de la auditoría de deberes del responsable (Art. 14 ter b y c Ley 21.719)")
    legal_disclaimer: str = Field(..., description="Aviso legal de descargo de responsabilidad académica")
    pdf_report_url: Optional[str] = Field(None, description="Enlace para descargar el informe oficial en PDF")


class ScheduleCreateRequest(BaseModel):
    audit_id: str = Field(..., description="UUID de la auditoría reprobada previa")
    email: str = Field(..., description="Correo electrónico para recibir los resultados")
    interval_mode: str = Field(
        default="DEMO_2_MIN",
        description="Modo de intervalo: 'DEMO_2_MIN' (2 minutos para demostración) o 'PROD_15_DAYS' (15 días)"
    )


class ScheduleResponse(BaseModel):
    schedule_id: str = Field(..., description="UUID de la tarea programada")
    target_url: str = Field(..., description="URL que será re-auditada")
    email: str = Field(..., description="Correo destinatario")
    scheduled_at: str = Field(..., description="Fecha y hora ISO de próxima ejecución")
    status: str = Field(..., description="Estado de la tarea (PENDIENTE, etc.)")
    message: str = Field(..., description="Mensaje informativo para el usuario")
    executed_at: Optional[str] = Field(None, description="Fecha y hora ISO de ejecución")
    nueva_auditoria_id: Optional[str] = Field(None, description="UUID de la nueva auditoría ejecutada")
