"""
Pruebas de Seguridad y Mitigación de SSRF (FB-01 / FB-06 / PBI-05).
Verifica el bloqueo de IPs privadas, loopback, metadatos cloud y restricción estricta de métodos no-GET.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import MagicMock, AsyncMock

from src.api.main import app
from src.core.sanitizer import sanitize_url, is_ip_private_or_restricted, validate_ssrf


def test_ssrf_blocks_loopback_addresses():
    """Caso 1: Bloqueo de localhost y direcciones loopback IPv4/IPv6."""
    loopback_targets = [
        "http://127.0.0.1/admin",
        "http://127.0.0.2:8080/metrics",
        "http://localhost:3000/api",
        "https://127.0.0.1"
    ]
    for url in loopback_targets:
        with pytest.raises(ValueError, match="SSRF"):
            sanitize_url(url)


def test_ssrf_blocks_private_rfc1918_networks():
    """Caso 2: Bloqueo de segmentos de red privada RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."""
    private_targets = [
        "http://10.0.0.1/internal",
        "http://10.255.255.254/",
        "http://172.16.0.1/status",
        "http://172.31.255.255/db",
        "http://192.168.1.1/router",
        "http://192.168.100.50:9000"
    ]
    for url in private_targets:
        with pytest.raises(ValueError, match="SSRF"):
            sanitize_url(url)


def test_ssrf_blocks_cloud_metadata_services():
    """Caso 3: Bloqueo estricto del servicio de metadatos de proveedores cloud (169.254.169.254)."""
    metadata_targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/computeMetadata/v1/",
        "https://169.254.1.1/secret"
    ]
    for url in metadata_targets:
        with pytest.raises(ValueError, match="SSRF"):
            sanitize_url(url)


@pytest.mark.asyncio
async def test_api_scan_returns_400_on_ssrf_attempt():
    """Caso 4: El endpoint /api/v1/scan responde con código HTTP 400 ante payloads maliciosos de SSRF."""
    malicious_payloads = [
        {"url": "http://127.0.0.1:8000/internal-admin"},
        {"url": "http://169.254.169.254/secret"},
        {"url": "http://192.168.0.1/"}
    ]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for payload in malicious_payloads:
            res = await client.post("/api/v1/scan", json=payload)
            assert res.status_code == 400
            assert "SSRF" in res.json().get("detail", "")


@pytest.mark.asyncio
async def test_playwright_interceptor_aborts_non_get_requests():
    """Caso 5: La rutina de intercepción del código real aborta cualquier método HTTP distinto de GET y valida SSRF."""
    from src.scanner.inspector import block_non_get_route, WebInspector
    assert hasattr(WebInspector, "block_non_get")

    # Simular una petición con método POST
    mock_post_route = MagicMock()
    mock_post_route.request.method = "POST"
    mock_post_route.request.url = "https://sitio.cl/api/login"
    mock_post_route.abort = AsyncMock()

    await block_non_get_route(mock_post_route)
    mock_post_route.abort.assert_awaited_once_with("blockedbyclient")

    # Simular una petición con método GET legítimo
    mock_get_route = MagicMock()
    mock_get_route.request.method = "GET"
    mock_get_route.request.url = "https://sitio.cl/estilos.css"
    mock_get_route.continue_ = AsyncMock()
    await block_non_get_route(mock_get_route)
    mock_get_route.continue_.assert_awaited_once()

    # Simular intento de SSRF a IP interna vía GET en subrecurso
    mock_ssrf_route = MagicMock()
    mock_ssrf_route.request.method = "GET"
    mock_ssrf_route.request.url = "http://169.254.169.254/latest/meta-data/"
    mock_ssrf_route.abort = AsyncMock()
    await block_non_get_route(mock_ssrf_route)
    mock_ssrf_route.abort.assert_awaited_once_with("blockedbyclient")


def test_ssrf_blocks_cgnat_and_ipv6_loopback():
    """Caso 6: Bloqueo de CGNAT (100.64.0.0/10) e IPv6 loopback ([::1])."""
    targets = [
        "http://100.64.0.1/",
        "http://100.127.255.254/status",
        "http://[::1]/admin"
    ]
    for url in targets:
        with pytest.raises(ValueError, match="SSRF"):
            sanitize_url(url)
