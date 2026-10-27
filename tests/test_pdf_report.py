"""
Pruebas del Generador de Reportes PDF Normativos (FB-06 / PBI-06).
Verifica compilación rápida (< 3s), tamaño mayor a 0 KB y renderizado de todos los veredictos (incluido NO_ACCESIBLE).
"""

import pytest
import time
from httpx import AsyncClient, ASGITransport

from src.api.main import app
from src.services.pdf_report_service import PDFReportService


def test_pdf_report_compiles_valid_buffer_under_3_seconds():
    """Caso 1: El servicio de PDF compila el documento en menos de 3.0 segundos y genera > 0 KB."""
    sample_audit = {
        "target_url": "https://tienda-prueba.cl",
        "verdict": "APROBADO",
        "score": 85,
        "verdict_summary": "Cumplimiento normativo integral bajo Ley 21.719.",
        "pilares": {
            "politica_privacidad": {"status": "CUMPLE", "score": 35, "max_score": 35},
            "canales_arco": {"status": "CUMPLE", "score": 25, "max_score": 30},
            "consentimiento_cookies": {"status": "CUMPLE", "score": 25, "max_score": 35}
        },
        "findings": [
            {
                "pilar": "POLITICA_PRIVACIDAD",
                "status": "OK",
                "title": "Política Activa",
                "detail": "URL responde con código HTTP 200.",
                "remediation_ticket": "Mantener enlace persistente en footer institucional.",
                "articulo_ley": "Art. 11 Ley 21.719"
            }
        ]
    }

    t0 = time.perf_counter()
    pdf_bytes = PDFReportService.generate_audit_pdf(sample_audit)
    elapsed = time.perf_counter() - t0

    assert elapsed < 3.0
    assert len(pdf_bytes) > 0
    # Los PDFs siempre comienzan con la cabecera %PDF-
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_report_renders_no_accesible_verdict():
    """Caso 2: Generar PDF para auditoría con veredicto neutro NO_ACCESIBLE sin fallar."""
    no_accesible_audit = {
        "target_url": "https://banco-protegido.cl",
        "verdict": "NO_ACCESIBLE",
        "score": 0,
        "verdict_summary": "Sitio no accesible para análisis técnico pasivo (Bloqueo WAF).",
        "pilares": {
            "politica_privacidad": {"status": "FALLA", "score": 0, "max_score": 35},
            "canales_arco": {"status": "FALLA", "score": 0, "max_score": 30},
            "consentimiento_cookies": {"status": "FALLA", "score": 0, "max_score": 35}
        },
        "findings": [
            {
                "pilar": "ACCESIBILIDAD_PERIMETRAL",
                "status": "WARNING",
                "title": "Inspección Externa Bloqueada",
                "detail": "El sitio cuenta con cortafuegos perimetral WAF.",
                "remediation_ticket": "Permitir cabeceras DataCheck o auditar en staging.",
                "articulo_ley": "Art. 11 Ley 21.719"
            }
        ]
    }
    pdf_bytes = PDFReportService.generate_audit_pdf(no_accesible_audit)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF-")


@pytest.mark.asyncio
async def test_pdf_endpoint_validation_errors():
    """Caso 3: El endpoint /api/v1/audits/{audit_id}/pdf valida UUID y existencia."""
    from unittest.mock import AsyncMock
    from src.db.session import get_db_session

    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(return_value=AsyncMock(scalar_one_or_none=lambda: None))
    app.dependency_overrides[get_db_session] = lambda: mock_db

    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # UUID con formato inválido -> 400
            res_invalid = await client.get("/api/v1/audits/id-no-valido-123/pdf")
            assert res_invalid.status_code == 400

            # UUID sintácticamente válido pero inexistente -> 404
            res_not_found = await client.get("/api/v1/audits/00000000-0000-0000-0000-000000000000/pdf")
            assert res_not_found.status_code == 404
    finally:
        app.dependency_overrides.pop(get_db_session, None)
