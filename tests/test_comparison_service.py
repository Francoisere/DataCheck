"""
Pruebas Unitarias y de Integración para el Comparador de Regresiones e Historial Evolutivo ("Antes vs. Después").
Cubre RF-HIST-01, RF-HIST-02, RF-HIST-03, RF-HIST-04 y RNF-PERF-01.
"""

import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from src.api.main import app
from src.db.models import (
    Auditoria,
    Base,
    EvidenciaRastreador,
    ResultadoPilar,
    SitioAnalizado,
)
from src.db.repositories.audit_repository import AuditRepository
from src.db.session import get_db_session
from src.services.comparison_service import ComparisonService
from src.services.email_service import EmailService
from src.services.pdf_report_service import PdfReportService


# ==============================================================================
# Pruebas Unitarias Puras de ComparisonService (Casos 1, 2 y 3)
# ==============================================================================

def test_case_1_first_scan_has_no_previous():
    """Caso 1 (Primer escaneo): Verificar que has_previous sea False y verdict_transition sea None sin lanzar excepción."""
    audit_t1 = {
        "id": str(uuid.uuid4()),
        "ejecutada_en": datetime(2026, 11, 10, 15, 30, tzinfo=timezone.utc),
        "verdict": "RECHAZADO",
        "score": 65,
        "page_load_status": 1,
        "resultados_pilares": [
            {"pilar": "POLITICA_PRIVACIDAD", "estado": "CUMPLE", "puntaje": 35},
            {"pilar": "CANALES_ARCO", "estado": "CUMPLE", "puntaje": 30},
            {"pilar": "CONSENTIMIENTO_COOKIES", "estado": "FALLA", "puntaje": 0},
        ],
        "evidencias_rastreadores": [
            {"tipo": "COOKIE", "valor": "_ga", "categoria": "Analítica"},
        ],
    }

    diff = ComparisonService.compare_audits(current_audit=audit_t1, previous_audit=None)
    assert diff["has_previous"] is False
    assert diff["previous_audit_id"] is None
    assert diff["verdict_transition"] is None
    assert diff["score_comparison"] is None
    assert diff["pilares_delta"] == []
    assert diff["trackers_diff"] == {"remediated": [], "persistent": [], "regressions": []}


def test_case_2_successful_remediation_improved():
    """
    Caso 2 (Remediación exitosa):
    Auditoría 1 (RECHAZADO, 65 pts, _ga y _fbp) -> Auditoría 2 (APROBADO, 100 pts, 0 trackers).
    Valida delta: +35, status: IMPROVED y 2 items en remediated.
    """
    t1_time = datetime(2026, 11, 10, 15, 30, tzinfo=timezone.utc)
    t2_time = t1_time + timedelta(hours=78, minutes=30)

    audit_t1 = {
        "id": "9b1deb4d-0000-0000-0000-000000000001",
        "ejecutada_en": t1_time,
        "verdict": "RECHAZADO",
        "score": 65,
        "page_load_status": 1,
        "resultados_pilares": [
            {"pilar": "POLITICA_PRIVACIDAD", "estado": "CUMPLE", "puntaje": 35},
            {"pilar": "CANALES_ARCO", "estado": "CUMPLE", "puntaje": 30},
            {"pilar": "CONSENTIMIENTO_COOKIES", "estado": "FALLA", "puntaje": 0},
        ],
        "evidencias_rastreadores": [
            {"tipo": "COOKIE", "valor": "_ga", "categoria": "Analítica"},
            {"tipo": "COOKIE", "valor": "_fbp", "categoria": "Publicidad"},
        ],
    }

    audit_t2 = {
        "id": "a1b2c3d4-0000-0000-0000-000000000002",
        "ejecutada_en": t2_time,
        "verdict": "APROBADO",
        "score": 100,
        "page_load_status": 1,
        "resultados_pilares": [
            {"pilar": "POLITICA_PRIVACIDAD", "estado": "CUMPLE", "puntaje": 35},
            {"pilar": "CANALES_ARCO", "estado": "CUMPLE", "puntaje": 30},
            {"pilar": "CONSENTIMIENTO_COOKIES", "estado": "CUMPLE", "puntaje": 35},
        ],
        "evidencias_rastreadores": [],
    }

    diff = ComparisonService.compare_audits(current_audit=audit_t2, previous_audit=audit_t1)

    assert diff["has_previous"] is True
    assert diff["time_elapsed_hours"] == 78.5
    assert diff["verdict_transition"] == {
        "from": "RECHAZADO",
        "to": "APROBADO",
        "status": "IMPROVED",
    }
    assert diff["score_comparison"] == {
        "previous_score": 65,
        "current_score": 100,
        "delta": 35,
    }
    assert len(diff["trackers_diff"]["remediated"]) == 2
    remediated_values = {item["valor"] for item in diff["trackers_diff"]["remediated"]}
    assert remediated_values == {"_ga", "_fbp"}
    assert diff["trackers_diff"]["persistent"] == []
    assert diff["trackers_diff"]["regressions"] == []

    cookies_pillar = next(p for p in diff["pilares_delta"] if p["pilar"] == "CONSENTIMIENTO_COOKIES")
    assert cookies_pillar["previous_status"] == "FALLA"
    assert cookies_pillar["current_status"] == "CUMPLE"
    assert cookies_pillar["delta"] == 35


def test_case_3_regression_by_new_tracker_script():
    """
    Caso 3 (Regresión por nuevo script):
    Auditoría limpia (APROBADO, 100 pts) seguida de inyección de hotjar.com ->
    valida status: REGRESSED y detección en regressions.
    """
    t1_time = datetime(2026, 11, 11, 10, 0, tzinfo=timezone.utc)
    t2_time = t1_time + timedelta(hours=24)

    audit_clean = {
        "id": str(uuid.uuid4()),
        "ejecutada_en": t1_time,
        "verdict": "APROBADO",
        "score": 100,
        "page_load_status": 1,
        "resultados_pilares": [
            {"pilar": "CONSENTIMIENTO_COOKIES", "estado": "CUMPLE", "puntaje": 35},
        ],
        "evidencias_rastreadores": [],
    }

    audit_regressed = {
        "id": str(uuid.uuid4()),
        "ejecutada_en": t2_time,
        "verdict": "RECHAZADO",
        "score": 65,
        "page_load_status": 1,
        "resultados_pilares": [
            {"pilar": "CONSENTIMIENTO_COOKIES", "estado": "FALLA", "puntaje": 0},
        ],
        "evidencias_rastreadores": [
            {"tipo": "DOMINIO", "valor": "hotjar.com", "categoria": "Grabación de Sesión"},
        ],
    }

    diff = ComparisonService.compare_audits(current_audit=audit_regressed, previous_audit=audit_clean)

    assert diff["has_previous"] is True
    assert diff["verdict_transition"]["status"] == "REGRESSED"
    assert diff["score_comparison"]["delta"] == -35
    assert len(diff["trackers_diff"]["regressions"]) == 1
    assert diff["trackers_diff"]["regressions"][0]["valor"] == "hotjar.com"


# ==============================================================================
# Pruebas de Integración Relacional y Endpoints REST (Caso 4: Salto de WAF y RNF-PERF-01)
# ==============================================================================

@pytest.mark.asyncio
async def test_case_4_waf_intermediate_failure_skipped_and_rest_endpoints():
    """
    Caso 4 (Salto de fallo WAF) + Integración REST (/history y /diff) + Rendimiento (< 150ms):
    Verifica que una auditoría intermedia con page_load_status = 0 (WAF/Timeout)
    sea ignorada como base de comparación para la siguiente auditoría válida.
    """
    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    TestSession = async_sessionmaker(bind=test_engine, expire_on_commit=False)

    t1 = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
    t2_waf = t1 + timedelta(hours=12)
    t3 = t1 + timedelta(hours=24)

    async with TestSession() as session:
        sitio = SitioAnalizado(
            url_normalizada="https://tienda-ejemplo.cl/",
            dominio="tienda-ejemplo.cl",
        )
        session.add(sitio)
        await session.flush()

        # Auditoría 1: Válida pero RECHAZADO (65 pts, 2 trackers)
        a1 = Auditoria(
            sitio_id=sitio.id,
            ejecutada_en=t1,
            page_load_status=1,
            verdict="RECHAZADO",
            score=65,
            duracion_ms=2100,
            resumen="Incumplimiento por trackers.",
        )
        session.add(a1)
        await session.flush()
        session.add_all([
            ResultadoPilar(auditoria_id=a1.id, pilar="POLITICA_PRIVACIDAD", estado="CUMPLE", puntaje=35, puntaje_max=35),
            ResultadoPilar(auditoria_id=a1.id, pilar="CANALES_ARCO", estado="CUMPLE", puntaje=30, puntaje_max=30),
            ResultadoPilar(auditoria_id=a1.id, pilar="CONSENTIMIENTO_COOKIES", estado="FALLA", puntaje=0, puntaje_max=35),
            EvidenciaRastreador(auditoria_id=a1.id, tipo="COOKIE", valor="_ga", categoria="Analítica"),
            EvidenciaRastreador(auditoria_id=a1.id, tipo="DOMINIO", valor="google-analytics.com", categoria="Analítica"),
        ])

        # Auditoría 2: Intermedia fallida por bloqueo WAF (page_load_status = 0)
        a2_waf = Auditoria(
            sitio_id=sitio.id,
            ejecutada_en=t2_waf,
            page_load_status=0,
            verdict="NO_ACCESIBLE",
            score=0,
            duracion_ms=1500,
            resumen="Bloqueo WAF perimetral.",
        )
        session.add(a2_waf)
        await session.flush()

        # Auditoría 3: Válida y APROBADO (100 pts, 0 trackers)
        a3 = Auditoria(
            sitio_id=sitio.id,
            ejecutada_en=t3,
            page_load_status=1,
            verdict="APROBADO",
            score=100,
            duracion_ms=1900,
            resumen="Sitio conforme.",
        )
        session.add(a3)
        await session.flush()
        session.add_all([
            ResultadoPilar(auditoria_id=a3.id, pilar="POLITICA_PRIVACIDAD", estado="CUMPLE", puntaje=35, puntaje_max=35),
            ResultadoPilar(auditoria_id=a3.id, pilar="CANALES_ARCO", estado="CUMPLE", puntaje=30, puntaje_max=30),
            ResultadoPilar(auditoria_id=a3.id, pilar="CONSENTIMIENTO_COOKIES", estado="CUMPLE", puntaje=35, puntaje_max=35),
        ])
        await session.commit()

        # Verificar a nivel de repositorio que get_previous_valid_audit salta a2_waf y retorna a1
        prev_valid = await AuditRepository.get_previous_valid_audit(
            db=session,
            sitio_id=sitio.id,
            current_executed_at=a3.ejecutada_en,
            current_audit_id=a3.id,
        )
        assert prev_valid is not None
        assert prev_valid.id == a1.id

    async def override_db():
        async with TestSession() as s:
            yield s

    app.dependency_overrides[get_db_session] = override_db
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # 1. Probar GET /api/v1/audits/{audit_id}/diff (RNF-PERF-01 < 150ms)
            t0 = time.perf_counter()
            res_diff = await client.get(f"/api/v1/audits/{a3.id}/diff")
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            assert res_diff.status_code == 200
            assert elapsed_ms < 150.0

            diff_data = res_diff.json()
            assert diff_data["current_audit_id"] == str(a3.id)
            assert diff_data["previous_audit_id"] == str(a1.id)  # Ignoró a2_waf
            assert diff_data["has_previous"] is True
            assert diff_data["verdict_transition"]["from"] == "RECHAZADO"
            assert diff_data["verdict_transition"]["to"] == "APROBADO"
            assert diff_data["verdict_transition"]["status"] == "IMPROVED"
            assert diff_data["score_comparison"]["delta"] == 35
            assert len(diff_data["trackers_diff"]["remediated"]) == 2

            # 2. Probar GET /api/v1/sites/{domain}/history
            t0_hist = time.perf_counter()
            res_hist = await client.get("/api/v1/sites/tienda-ejemplo.cl/history?limit=10")
            elapsed_hist_ms = (time.perf_counter() - t0_hist) * 1000.0
            assert res_hist.status_code == 200
            assert elapsed_hist_ms < 150.0

            hist_data = res_hist.json()
            assert hist_data["domain"] == "tienda-ejemplo.cl"
            assert hist_data["total_audits"] == 3
            assert hist_data["latest_verdict"] == "APROBADO"
            assert hist_data["overall_score_delta"] == 35
            assert len(hist_data["timeline"]) == 3
            # La auditoría más reciente (a3) debe tener delta +35 respecto a a1
            assert hist_data["timeline"][0]["audit_id"] == str(a3.id)
            assert hist_data["timeline"][0]["score_delta_from_previous"] == 35

            # 3. Probar 404 para dominio inexistente
            res_404 = await client.get("/api/v1/sites/dominio-nunca-auditado.cl/history")
            assert res_404.status_code == 404
    finally:
        app.dependency_overrides.pop(get_db_session, None)
        await test_engine.dispose()


def test_email_and_pdf_render_comparison_block():
    """RF-HIST-04: Verifica que EmailService y PdfReportService integren el bloque Antes vs. Después."""
    mock_comparison = {
        "current_audit_id": "a2",
        "previous_audit_id": "a1",
        "has_previous": True,
        "time_elapsed_hours": 48.0,
        "verdict_transition": {"from": "RECHAZADO", "to": "APROBADO", "status": "IMPROVED"},
        "score_comparison": {"previous_score": 65, "current_score": 100, "delta": 35},
        "pilares_delta": [],
        "trackers_diff": {
            "remediated": [{"tipo": "COOKIE", "valor": "_ga", "categoria": "Analítica"}],
            "persistent": [],
            "regressions": [],
        },
    }

    html = EmailService.build_email_content(
        target_url="https://tienda-ejemplo.cl",
        verdict="APROBADO",
        score=100,
        previous_verdict="RECHAZADO",
        previous_score=65,
        verdict_summary="Conforme",
        findings_count=0,
        comparison=mock_comparison,
    )
    assert "+35 pts" in html
    assert "_ga" in html
    assert "IMPROVED" in html

    pdf_buf = PdfReportService.generate_pdf_report({
        "target_url": "https://tienda-ejemplo.cl",
        "verdict": "APROBADO",
        "score": 100,
        "verdict_summary": "Conforme",
        "pilares": {},
        "findings": [],
        "comparison": mock_comparison,
    })
    assert pdf_buf.getvalue().startswith(b"%PDF-")
