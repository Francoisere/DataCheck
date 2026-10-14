import pytest
import io
import time
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch, AsyncMock
import uuid

from src.api.main import app
from src.services.pdf_report_service import PdfReportService


def test_pdf_service_compiles_valid_buffer_under_3_seconds():
    """AC-REP-01: Generación de PDF estructurado en < 3.0 s (> 0 KB)."""
    mock_audit_data = {
        "target_url": "https://tienda-ejemplo.cl/",
        "page_load_status": 1,
        "verdict": "RECHAZADO",
        "score": 45,
        "verdict_summary": "Incumplimiento crítico: Se detectaron rastreadores de terceros activos previo al consentimiento.",
        "pilares": {
            "politica_privacidad": {"status": "CUMPLE", "score": 35, "max_score": 35},
            "canales_arco": {"status": "OBSERVACION", "score": 10, "max_score": 30},
            "consentimiento_cookies": {"status": "FALLA", "score": 0, "max_score": 35}
        },
        "findings": [
            {
                "pilar": "CONSENTIMIENTO_COOKIES",
                "status": "FAIL",
                "title": "Inyección no autorizada de rastreador externo",
                "detail": "Cookie '_ga' y petición saliente a 'google-analytics.com' detectadas al cargar el DOM.",
                "technical_raw": "google-analytics.com",
                "remediation_ticket": "Condicionar la inyección de la etiqueta de Google Analytics en Google Tag Manager (GTM)."
            },
            {
                "pilar": "POLITICA_PRIVACIDAD",
                "status": "OK",
                "title": "Política de Privacidad Accesible",
                "detail": "Enlace a la política detectado en https://tienda-ejemplo.cl/privacidad respondiendo HTTP 200.",
                "technical_raw": "HTTP 200",
                "remediation_ticket": "Mantener la visibilidad y accesibilidad directa del enlace en el footer institucional."
            }
        ]
    }

    start = time.perf_counter()
    pdf_buffer = PdfReportService.generate_pdf_report(mock_audit_data)
    elapsed = time.perf_counter() - start

    assert elapsed < 3.0
    content = pdf_buffer.getvalue()
    assert len(content) > 1000  # PDF binario estructurado > 0 KB (AC-REP-01)
    assert content.startswith(b"%PDF")  # Cabecera estándar de archivo PDF


@pytest.mark.asyncio
async def test_pdf_endpoint_invalid_uuid_returns_400():
    """AC-REP-02: Intento con ID inválido retorna 400 Bad Request."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/audits/invalid-uuid-123/pdf")
        assert res.status_code == 400
        assert "UUID" in res.json()["detail"]


@pytest.mark.asyncio
async def test_pdf_endpoint_nonexistent_audit_returns_404():
    """AC-REP-02: Auditoría no encontrada retorna 404."""
    from src.db.session import get_db_session

    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(return_value=AsyncMock(scalar_one_or_none=lambda: None))

    async def override_db():
        yield mock_db

    app.dependency_overrides[get_db_session] = override_db
    try:
        random_uuid = str(uuid.uuid4())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.get(f"/api/v1/audits/{random_uuid}/pdf")
            assert res.status_code == 404
            assert "No se encontró" in res.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_db_session, None)

