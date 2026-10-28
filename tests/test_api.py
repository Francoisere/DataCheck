import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch

from src.api.main import app


@pytest.mark.asyncio
async def test_health_endpoint():
    """C-03: Verifica /healthcheck y /api/v1/health devolviendo estado ok y conexión a BD."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Probar ruta canónica /api/v1/health
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "DataCheck.cl" in data["service"]
        assert "database" in data

        # 2. Probar ruta raíz /healthcheck
        res_root = await client.get("/healthcheck")
        assert res_root.status_code == 200
        assert res_root.json()["status"] == "ok"

        # 3. Simular caída de base de datos -> debe retornar HTTP 503
        with patch("src.api.routes.health.engine") as mock_eng:
            mock_eng.connect.side_effect = Exception("DB Connection Refused")
            res_down = await client.get("/healthcheck")
            assert res_down.status_code == 503
            assert res_down.json()["status"] == "unhealthy"
            assert "unreachable" in res_down.json()["database"]


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
        },
        "consent_banner_audit": {
            "banner_detected": True,
            "cmp_provider": "cookiebot",
            "has_reject_option": False,
            "has_accept_option": True,
            "has_settings_option": False,
            "detected_buttons": ["Aceptar"],
            "banner_source_frame": "https://consentcdn.cookiebot.com/banner.html",
            "buttons_verifiable": True,
            "blocks_prior_to_consent": False
        },
        "frames_audit": {
            "total_frames": 3,
            "third_party_frames": 2,
            "cmp_frames": 1,
            "frames": [
                {
                    "url": "https://consentcdn.cookiebot.com/banner.html",
                    "origin": "https://consentcdn.cookiebot.com",
                    "is_third_party": True,
                    "is_cmp_frame": True,
                    "detected_cmp": "cookiebot"
                }
            ]
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

            # Validar que frames_audit y consent_banner_audit se serialicen adecuadamente
            assert "frames_audit" in data
            assert data["frames_audit"]["total_frames"] == 3
            assert data["frames_audit"]["third_party_frames"] == 2
            assert data["frames_audit"]["cmp_frames"] == 1
            assert len(data["frames_audit"]["frames"]) == 1

            assert "consent_banner_audit" in data
            assert data["consent_banner_audit"]["banner_detected"] is True
            assert data["consent_banner_audit"]["cmp_provider"] == "cookiebot"
            assert data["consent_banner_audit"]["blocks_prior_to_consent"] is False


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
        },
        "consent_banner_audit": {
            "banner_detected": False,
            "cmp_provider": None,
            "has_reject_option": False,
            "has_accept_option": False,
            "has_settings_option": False,
            "detected_buttons": [],
            "banner_source_frame": None,
            "buttons_verifiable": True,
            "blocks_prior_to_consent": None
        },
        "frames_audit": {
            "total_frames": 1,
            "third_party_frames": 0,
            "cmp_frames": 0,
            "frames": []
        }
    }

    with patch("src.services.audit_service.WebInspector.scan_url", return_value=mock_scan_raw):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/api/v1/scan?url=https://sitio-test.cl")
            assert response.status_code == 200
            data = response.json()
            assert data["verdict"] == "APROBADO"
            assert data["score"] >= 80
            assert data["frames_audit"]["total_frames"] == 1
            assert data["frames_audit"]["third_party_frames"] == 0
