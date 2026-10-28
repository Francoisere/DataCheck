"""
Servicio Orquestador de Auditorías (DataCheck.cl).
Flujo F-01:
Normalización URL -> Inspección Pasiva (Playwright) -> Motor de Reglas -> Persistencia Relacional.
"""

import time
import asyncio
import logging
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from src.core.sanitizer import sanitize_url
from src.scanner.inspector import WebInspector
from src.scanner.rules_engine import RulesEngine
from src.scanner.trackers_db import get_tracker_category
from src.core.config import settings
from src.db.models import (
    SitioAnalizado,
    Auditoria,
    ResultadoPilar,
    Hallazgo,
    EvidenciaRastreador
)

logger = logging.getLogger(__name__)


class AuditService:
    def __init__(self, inspector: Optional[WebInspector] = None):
        self.inspector = inspector or WebInspector()

    async def execute_audit(
        self,
        raw_url: str,
        db_session: Optional[AsyncSession] = None
    ) -> Dict[str, Any]:
        """
        Orquesta el ciclo completo de auditoría técnica.
        1. Normaliza y sanitiza la URL (excluyendo tokens/credenciales).
        2. Ejecuta el escaneo pasivo con Playwright y timeout forzado de 25s.
        3. Evalúa con el motor determinista de reglas generando tickets de remediación.
        4. Si hay sesión de base de datos activa, persiste los resultados inmutables.
        """
        start_time = time.perf_counter()

        # 1. Normalización
        normalized_url, domain = sanitize_url(raw_url)

        # 2. Inspección pasiva con límite asíncrono estricto (FB-03)
        try:
            scan_raw = await asyncio.wait_for(
                self.inspector.scan_url(normalized_url),
                timeout=settings.SCAN_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            logger.warning(f"Timeout global excedido (25s) escaneando {normalized_url}")
            await self.inspector.force_close()
            scan_raw = self.inspector._build_timeout_fallback(normalized_url)

        # 3. Motor de reglas y dictamen
        audit_result = RulesEngine.evaluate(scan_raw)
        duracion_ms = int((time.perf_counter() - start_time) * 1000)

        # Enriquecer cada hallazgo con sustento normativo (Ley 21.719)
        from src.core.legal_catalog import get_legal_basis
        for f in audit_result.get("findings", []):
            citation = get_legal_basis(f.get("pilar", ""), f.get("status", ""), f.get("legal_basis_key"))
            f["articulo_ley"] = citation.articulo_ley
            f["principio_vulnerado"] = citation.principio_vulnerado
            f["sancion_estimada"] = citation.sancion_estimada

        # 4. Persistencia relacional (si la sesión está disponible)
        if db_session:
            try:
                saved_audit_id = await self._persist_audit_result(
                    db=db_session,
                    normalized_url=normalized_url,
                    domain=domain,
                    audit_result=audit_result,
                    scan_raw=scan_raw,
                    duracion_ms=duracion_ms
                )
                if saved_audit_id:
                    audit_result["audit_id"] = str(saved_audit_id)
                    audit_result["pdf_report_url"] = f"/api/v1/audits/{saved_audit_id}/pdf"
            except Exception as e:
                logger.warning(f"No se pudo persistir la auditoría en PostgreSQL: {e}")

        return audit_result

    async def _persist_audit_result(
        self,
        db: AsyncSession,
        normalized_url: str,
        domain: str,
        audit_result: Dict[str, Any],
        scan_raw: Dict[str, Any],
        duracion_ms: int
    ) -> None:
        """
        Almacena el registro de auditoría y sus evidencias en las tablas relacionales.
        """
        # Buscar o crear SitioAnalizado
        stmt = select(SitioAnalizado).where(SitioAnalizado.url_normalizada == normalized_url)
        res = await db.execute(stmt)
        sitio = res.scalar_one_or_none()

        if not sitio:
            sitio = SitioAnalizado(
                url_normalizada=normalized_url,
                dominio=domain
            )
            db.add(sitio)
            await db.flush()

        # Crear Auditoría inmutable
        auditoria = Auditoria(
            sitio_id=sitio.id,
            page_load_status=audit_result.get("page_load_status", 1),
            verdict=audit_result.get("verdict", "RECHAZADO"),
            score=audit_result.get("score", 0),
            duracion_ms=duracion_ms,
            resumen=audit_result.get("verdict_summary", "")
        )
        db.add(auditoria)
        await db.flush()

        is_inaccessible = audit_result.get("verdict") == "NO_ACCESIBLE"

        # Crear Resultados de Pilares y Hallazgos
        pilares_dict = audit_result.get("pilares", {})
        pilar_mapping = {
            "politica_privacidad": "POLITICA_PRIVACIDAD",
            "canales_arco": "CANALES_ARCO",
            "consentimiento_cookies": "CONSENTIMIENTO_COOKIES"
        }

        pilar_records: Dict[str, ResultadoPilar] = {}
        for key, pilar_enum in pilar_mapping.items():
            data = pilares_dict.get(key, {})
            # Ante bloqueo WAF o timeout, no sancionar falsamente con FALLA: estado neutro NO_EVALUADO
            estado_pilar = "NO_EVALUADO" if is_inaccessible else data.get("status", "FALLA")
            record = ResultadoPilar(
                auditoria_id=auditoria.id,
                pilar=pilar_enum,
                estado=estado_pilar,
                puntaje=data.get("score", 0),
                puntaje_max=data.get("max_score", 35)
            )
            db.add(record)
            pilar_records[pilar_enum] = record

        await db.flush()

        # Guardar Hallazgos
        for finding in audit_result.get("findings", []):
            pilar_key = finding.get("pilar", "")
            pilar_record = pilar_records.get(pilar_key)
            # Para hallazgos perimetrales (WAF/Timeout), resultado_pilar_id queda None
            # y se vincula directamente a auditoria_id sin contaminar el pilar de Política
            h = Hallazgo(
                auditoria_id=auditoria.id,
                resultado_pilar_id=pilar_record.id if pilar_record else None,
                pilar=pilar_key or None,
                severidad=finding.get("status", "OK"),
                titulo=finding.get("title", "")[:255],
                detalle=finding.get("detail", "")[:300],
                technical_raw=finding.get("technical_raw", "")[:500] if finding.get("technical_raw") else None,
                recomendacion=finding.get("remediation_ticket", "")
            )
            db.add(h)

        # Guardar Evidencias de Rastreadores (sin duplicados conforme a UNIQUE constraint)
        tracker_audit = scan_raw.get("tracker_audit", {})
        seen_evidence = set()
        for domain_name in tracker_audit.get("detected_tracker_domains", []):
            key = ("DOMINIO", domain_name[:255])
            if key not in seen_evidence:
                seen_evidence.add(key)
                db.add(EvidenciaRastreador(
                    auditoria_id=auditoria.id,
                    tipo="DOMINIO",
                    valor=domain_name[:255],
                    categoria=get_tracker_category(domain_name)
                ))

        for cookie_name in tracker_audit.get("detected_tracker_cookies", []):
            key = ("COOKIE", cookie_name[:255])
            if key not in seen_evidence:
                seen_evidence.add(key)
                db.add(EvidenciaRastreador(
                    auditoria_id=auditoria.id,
                    tipo="COOKIE",
                    valor=cookie_name[:255],
                    categoria=get_tracker_category(cookie_name)
                ))

        return auditoria.id
