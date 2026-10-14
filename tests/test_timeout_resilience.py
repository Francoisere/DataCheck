import pytest
import asyncio
from unittest.mock import patch
from src.scanner.inspector import WebInspector


@pytest.mark.asyncio
async def test_inspector_enforces_timeout_safely():
    """
    Verifica TEST-TO-02:
    Si una navegación tarda más de lo configurado (simulado con sleep de 30s),
    el método scan_url aborta limpiamente sin lanzar excepciones no controladas.
    """
    inspector = WebInspector(timeout_seconds=0.5, page_timeout_ms=500)

    async def mock_slow_scan(url: str):
        await asyncio.sleep(5.0)
        return {"should": "not reach"}

    with patch.object(inspector, "_execute_scan", side_effect=mock_slow_scan):
        result = await inspector.scan_url("https://sitio-lento.cl")
        assert result["page_load_status"] == 0
        assert "Tiempo límite" in result["error_message"] or "25 segundos" in result["error_message"]
        assert result["privacy_policy_audit"]["found"] is False
        assert result["tracker_audit"]["has_unauthorized_trackers"] is False
