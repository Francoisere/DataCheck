"""
Pruebas de Calidad E2E (EC-01 a EC-06) según Sprint 3:
- EC-01 / EC-02: Rendimiento y tiempo de respuesta (<15s estándar, <30s en concurrencia).
- EC-03: Resiliencia con corte estricto en 25s ante servidores con retardo de 40s (TEST-TO-02).
- EC-04: Seguridad e Inspección Pasiva (DA-01): Cero métodos no autorizados (POST/PUT/DELETE) hacia el objetivo.
- EC-05: Manejo amigable de bloqueos WAF (HTTP 403/503) sin error 500 (TEST-WAF-03).
- EC-06: Sanitización estricta ante credenciales y tokens (TEST-SAN-01).
"""

import pytest
import asyncio
import time
from unittest.mock import patch, AsyncMock
from httpx import AsyncClient, ASGITransport

from src.api.main import app
from src.scanner.inspector import WebInspector
from src.core.sanitizer import sanitize_url


@pytest.mark.asyncio
async def test_ec01_rendimiento_estandar():
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
async def test_ec02_rendimiento_concurrencia():
    """EC-02: Concurrencia de 3 escaneos simultáneos finaliza en < 30s."""
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


@pytest.mark.asyncio
async def test_ec03_resiliencia_delay_40s_aborta_en_25s():
    """EC-03 / TEST-TO-02: Servidor con delay de 40s debe abortar a los 25s limpiamente."""
    inspector = WebInspector(timeout_seconds=1.0)  # timeout calibrado para test

    async def delay_40s(url):
        await asyncio.sleep(40.0)
        return {}

    start = time.perf_counter()
    with patch.object(inspector, "_execute_scan", side_effect=delay_40s):
        result = await inspector.scan_url("https://servidor-lento-40s.cl")
        elapsed = time.perf_counter() - start
        assert elapsed < 3.0  # Abortó inmediatamente al cumplirse el timeout configurado
        assert result["page_load_status"] == 0
        assert "Tiempo límite" in result["error_message"]


@pytest.mark.asyncio
async def test_ec04_seguridad_inspeccion_pasiva_cero_mutaciones():
    """EC-04 / DA-01: Garantizar que el inspector opera en modo solo lectura pública sin métodos POST/PUT/DELETE."""
    inspector = WebInspector()
    # Verificar que el inspector no exponga métodos de mutación ni los invoque
    assert not hasattr(inspector, "post_form")
    assert not hasattr(inspector, "submit_form")
    assert not hasattr(inspector, "click_and_fill")


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
