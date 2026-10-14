import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch

from src.api.main import app


@pytest.mark.asyncio
async def test_health_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "DataCheck.cl" in data["service"]


@pytest.mark.asyncio
async def test_scan_endpoint_post_contract():
    mock_scan_raw = {
        "target_url": "https://sitio-test.cl/",
        "page_load_status": 200,
        "error_message": None,
        "tracker_audit": {
            "detected_tracker_domains": ["google-analytics.com"],
            "detected_tracker_cookies": ["_ga"],
            "total_cookies": 1,
            "raw_cookies": ["_ga"],
            "local_storage_keys_count": 0,
            "has_unauthorized_trackers": True
        },
        "privacy_policy_audit": {
            "found": True,
            "url": "https://sitio-test.cl/privacidad",
            "http_status": 200,
            "has_mandatory_keywords": True,
            "found_keywords": ["titular", "responsable", "derechos", "tratamiento"]
        },
        "arco_channels_audit": {
            "found": True,
            "detected_emails": ["contacto@sitio-test.cl"],
            "detected_terms": ["arco"],
            "has_explicit_arco_mention": True
        }
    }

    with patch("src.services.audit_service.WebInspector.scan_url", return_value=mock_scan_raw):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/api/v1/scan",
                json={"url": "https://user:pass@sitio-test.cl/?utm=123"}
            )
            assert response.status_code == 200
            data = response.json()
            assert data["target_url"] == "https://sitio-test.cl/"
            assert data["verdict"] == "RECHAZADO"
            assert "findings" in data
            assert len(data["findings"]) > 0
            # Validar que cada finding cuenta con ticket técnico de remediación
            for finding in data["findings"]:
                assert "remediation_ticket" in finding


@pytest.mark.asyncio
async def test_scan_endpoint_get_bookmarklet_contract():
    mock_scan_raw = {
        "target_url": "https://sitio-test.cl/",
        "page_load_status": 200,
        "error_message": None,
        "tracker_audit": {
            "detected_tracker_domains": [],
            "detected_tracker_cookies": [],
            "total_cookies": 0,
            "raw_cookies": [],
            "local_storage_keys_count": 0,
            "has_unauthorized_trackers": False
        },
        "privacy_policy_audit": {
            "found": True,
            "url": "https://sitio-test.cl/privacidad",
            "http_status": 200,
            "has_mandatory_keywords": True,
            "found_keywords": ["titular", "responsable", "derechos", "tratamiento", "finalidad"]
        },
        "arco_channels_audit": {
            "found": True,
            "detected_emails": ["contacto@sitio-test.cl"],
            "detected_terms": ["arco"],
            "has_explicit_arco_mention": True
        }
    }

    with patch("src.services.audit_service.WebInspector.scan_url", return_value=mock_scan_raw):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/scan?url=https://sitio-test.cl")
            assert response.status_code == 200
            data = response.json()
            assert data["verdict"] == "APROBADO"
            assert data["score"] >= 80
