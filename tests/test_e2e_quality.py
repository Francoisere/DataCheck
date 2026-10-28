"""
Pruebas de Calidad E2E y Atributos de Calidad (EC-01 a EC-06) según Informe de Arquitectura (§15):
- EC-01: Rendimiento en carga normal (<15s por escaneo).
- EC-02: Disponibilidad y concurrencia (3 escaneos concurrentes en <30s y resiliencia ante timeout de 25s).
- EC-03: Seguridad e inspección pasiva no intrusiva (solo GET, cero métodos mutacionales hacia el objetivo).
- EC-04: Privacy by Design en base de datos (≥10 auditorías persistidas, 0 credenciales/tokens en BD, snippets <= 300 caracteres).
- EC-05: Precisión funcional y manejo amigable de WAF (HTTP 403/503 devuelve NO_ACCESIBLE sin error 500).
- EC-06: Despliegue y reproducibilidad (sanitización de datos sensibles y cumplimiento de contratos).
"""

import pytest
import asyncio
import time
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select

from src.api.main import app
from src.scanner.inspector import WebInspector, block_non_get_route
from src.core.sanitizer import sanitize_url
from src.services.audit_service import AuditService
from src.db.session import engine, Base, AsyncSessionLocal
from src.db.models import SitioAnalizado, Auditoria, Hallazgo, EvidenciaRastreador


@pytest.mark.asyncio
async def test_ec01_rendimiento_carga_normal():
    """EC-01: Respuesta en < 15 segundos en sitio simulado normal."""
    mock_raw = {
        "target_url": "https://sitio-rapido.cl/",
        "page_load_status": 200,
        "error_message": None,
        "tracker_audit": {
            "detected_tracker_domains": [],
            "detected_tracker_cookies": [],
            "has_unauthorized_trackers": False
        },
        "privacy_policy_audit": {
            "found": True,
            "url": "https://sitio-rapido.cl/privacidad",
            "http_status": 200,
            "has_mandatory_keywords": True,
            "found_keywords": ["titular", "responsable", "derechos", "tratamiento"]
        },
        "arco_channels_audit": {
            "found": True,
            "detected_emails": ["contacto@sitio-rapido.cl"],
            "detected_terms": ["arco"],
            "has_explicit_arco_mention": True
        }
    }

    start = time.perf_counter()
    with patch("src.services.audit_service.WebInspector.scan_url", return_value=mock_raw):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.post("/api/v1/scan", json={"url": "https://sitio-rapido.cl"})
            elapsed = time.perf_counter() - start
            assert res.status_code == 200
            assert elapsed < 15.0


@pytest.mark.asyncio
async def test_ec02_rendimiento_concurrencia_y_resiliencia():
    """EC-02: Concurrencia de 3 escaneos finaliza en < 30s y servidor lento de 40s aborta en límite configurado."""
    mock_raw = {
        "target_url": "https://sitio-concurrente.cl/",
        "page_load_status": 200,
        "error_message": None,
        "tracker_audit": {
            "detected_tracker_domains": [],
            "detected_tracker_cookies": [],
            "has_unauthorized_trackers": False
        },
        "privacy_policy_audit": {
            "found": True,
            "url": "https://sitio-concurrente.cl/privacidad",
            "http_status": 200,
            "has_mandatory_keywords": True,
            "found_keywords": ["titular", "responsable"]
        },
        "arco_channels_audit": {
            "found": True,
            "detected_emails": ["legal@sitio-concurrente.cl"],
            "detected_terms": ["arco"],
            "has_explicit_arco_mention": True
        }
    }

    async def scan_call(client, url):
        return await client.post("/api/v1/scan", json={"url": url})

    start = time.perf_counter()
    with patch("src.services.audit_service.WebInspector.scan_url", return_value=mock_raw):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            tasks = [
                scan_call(client, f"https://sitio-concurrente-{i}.cl")
                for i in range(3)
            ]
            responses = await asyncio.gather(*tasks)
            elapsed = time.perf_counter() - start
            for r in responses:
                assert r.status_code == 200
            assert elapsed < 30.0

    # Resiliencia: servidor lento aborta limpiamente
    inspector = WebInspector(timeout_seconds=1.0)
    async def delay_40s(url):
        await asyncio.sleep(40.0)
        return {}

    with patch.object(inspector, "_execute_scan", side_effect=delay_40s):
        result = await inspector.scan_url("https://servidor-lento-40s.cl")
        assert result["page_load_status"] == 0
        assert "Tiempo límite" in result["error_message"]


@pytest.mark.asyncio
async def test_ec03_seguridad_no_intrusiva_solo_get():
    """EC-03 / DA-01: Cero métodos mutacionales (POST/PUT/DELETE) y ruta aborta peticiones de modificación."""
    inspector = WebInspector()
    assert hasattr(WebInspector, "block_non_get")
    assert not hasattr(inspector, "post_form")
    assert not hasattr(inspector, "submit_form")
    assert not hasattr(inspector, "click_and_fill")

    # Verificar interceptor real con método POST
    mock_post_route = MagicMock()
    mock_post_route.request.method = "POST"
    mock_post_route.request.url = "https://sitio.cl/api/login"
    mock_post_route.abort = AsyncMock()
    await block_non_get_route(mock_post_route)
    mock_post_route.abort.assert_awaited_once_with("blockedbyclient")

    # Verificar interceptor real con método GET legítimo
    mock_get_route = MagicMock()
    mock_get_route.request.method = "GET"
    mock_get_route.request.url = "https://sitio.cl/estilos.css"
    mock_get_route.continue_ = AsyncMock()
    await block_non_get_route(mock_get_route)
    mock_get_route.continue_.assert_awaited_once()


@pytest.mark.asyncio
async def test_ec04_privacy_by_design_db():
    """EC-04 / DA-04: Persistir 10 auditorías y verificar en BD que 0 contraseñas, tokens o fragmentos se almacenen."""
    # Asegurar inicialización del esquema relacional (especialmente en CI con SQLite efímero)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    service = AuditService()
    async with AsyncSessionLocal() as session:
        for i in range(10):
            sensitive_url = f"https://user{i}:secret_token_{i}@tienda-test-{i}.cl/checkout?session_id=abc123_{i}&auth=token456#step2"
            mock_scan = {
                "target_url": f"https://tienda-test-{i}.cl/checkout",
                "page_load_status": 200,
                "error_message": None,
                "tracker_audit": {
                    "detected_tracker_domains": ["google-analytics.com"],
                    "detected_tracker_cookies": ["_ga"],
                    "has_unauthorized_trackers": True
                },
                "privacy_policy_audit": {
                    "found": True,
                    "url": f"https://tienda-test-{i}.cl/privacidad",
                    "http_status": 200,
                    "has_mandatory_keywords": True,
                    "found_keywords": ["titular", "responsable"]
                },
                "arco_channels_audit": {
                    "found": True,
                    "detected_emails": [f"contacto{i}@tienda-test-{i}.cl"],
                    "detected_terms": ["arco"],
                    "has_explicit_arco_mention": True
                }
            }

            with patch.object(service.inspector, "scan_url", return_value=mock_scan):
                await service.execute_audit(sensitive_url, db_session=session)

        # Consultar la base de datos real para verificar que no existan credenciales ni tokens
        sitios = (await session.execute(select(SitioAnalizado))).scalars().all()
        assert len(sitios) >= 10
        for s in sitios:
            assert "secret_token" not in s.url_normalizada
            assert "user" not in s.url_normalizada
            assert "session_id" not in s.url_normalizada
            assert "auth=" not in s.url_normalizada

        auditorias = (await session.execute(select(Auditoria))).scalars().all()
        assert len(auditorias) >= 10
        for a in auditorias:
            assert "secret_token" not in a.resumen
            assert "session_id" not in a.resumen

        # Verificar que todos los snippets en hallazgos sean <= 300 caracteres
        hallazgos = (await session.execute(select(Hallazgo))).scalars().all()
        for h in hallazgos:
            assert len(h.detalle) <= 300


@pytest.mark.asyncio
async def test_ec05_waf_bloqueo_403_sin_error_500():
    """EC-05 / TEST-WAF-03: Sitio protegido con HTTP 403 devuelve page_load_status=0 sin explotar en error 500."""
    mock_waf_raw = {
        "target_url": "https://sitio-protegido-waf.cl/",
        "page_load_status": 403,
        "error_message": "Sitio no accesible para análisis (HTTP 403 - posible bloqueo WAF)",
        "tracker_audit": {
            "detected_tracker_domains": [],
            "detected_tracker_cookies": [],
            "has_unauthorized_trackers": False
        },
        "privacy_policy_audit": {
            "found": False,
            "url": None,
            "http_status": 403,
            "has_mandatory_keywords": False,
            "found_keywords": []
        },
        "arco_channels_audit": {
            "found": False,
            "detected_emails": [],
            "detected_terms": [],
            "has_explicit_arco_mention": False
        }
    }

    with patch("src.services.audit_service.WebInspector.scan_url", return_value=mock_waf_raw):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.post("/api/v1/scan", json={"url": "https://sitio-protegido-waf.cl"})
            assert res.status_code == 200
            data = res.json()
            assert data["page_load_status"] == 0
            assert data["verdict"] == "NO_ACCESIBLE"


@pytest.mark.asyncio
async def test_ec06_sanitizacion_cero_datos_sensibles():
    """EC-06 / TEST-SAN-01: El payload enviado con user:pass@ y query no se propaga a la salida."""
    normalized, domain = sanitize_url("https://admin:supersecret@banco.cl/home?auth=token123#tab")
    assert normalized == "https://banco.cl/home"
    assert "admin" not in normalized
    assert "supersecret" not in normalized
    assert "token123" not in normalized
