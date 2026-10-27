"""
Pruebas de Resiliencia ante Timeouts Lentos (FB-03 / FB-06 / PBI-05).
Verifica que las peticiones se interrumpan estrictamente bajo 25 segundos y se liberen recursos.
"""

import pytest
import asyncio
import time
from unittest.mock import patch, AsyncMock
from httpx import AsyncClient, ASGITransport

from src.api.main import app
from src.scanner.inspector import WebInspector
from src.services.audit_service import AuditService


@pytest.mark.asyncio
async def test_resilience_timeout_aborts_under_configured_limit():
    """Caso 1: Un servidor con retardo indefinido es interrumpido limpiamente por el inspector."""
    inspector = WebInspector(timeout_seconds=1.0)

    async def hanging_scan(url):
        await asyncio.sleep(10.0)
        return {"target_url": url, "page_load_status": 200}

    start = time.perf_counter()
    with patch.object(inspector, "_execute_scan", side_effect=hanging_scan):
        result = await inspector.scan_url("https://servidor-congelado.cl")
    elapsed = time.perf_counter() - start

    assert elapsed < 2.5
    assert result["page_load_status"] == 0
    assert "Tiempo límite" in result.get("error_message", "") or "TIMEOUT" in result.get("error_message", "")


@pytest.mark.asyncio
async def test_resilience_force_close_terminates_browser_resources():
    """Caso 2: Invocación de force_close() cierra el browser y contexto activo sin dejar procesos huérfanos."""
    inspector = WebInspector()

    mock_browser = AsyncMock()
    mock_context = AsyncMock()
    inspector._active_browser = mock_browser
    inspector._active_context = mock_context

    await inspector.force_close()

    mock_context.close.assert_awaited_once()
    mock_browser.close.assert_awaited_once()
    assert inspector._active_context is None
    assert inspector._active_browser is None
