import pytest
from src.scanner.rules_engine import RulesEngine


def test_evaluate_aprobado_with_remediation_tickets():
    mock_scan_data = {
        "target_url": "https://sitio-ejemplar.cl/",
        "page_load_status": 200,
        "error_message": None,
        "tracker_audit": {
            "detected_tracker_domains": [],
            "detected_tracker_cookies": [],
            "has_unauthorized_trackers": False
        },
        "privacy_policy_audit": {
            "found": True,
            "url": "https://sitio-ejemplar.cl/privacidad",
            "http_status": 200,
            "has_mandatory_keywords": True,
            "found_keywords": ["titular", "responsable", "derechos", "tratamiento", "finalidad"]
        },
        "arco_channels_audit": {
            "found": True,
            "detected_emails": ["privacidad@sitio-ejemplar.cl"],
            "detected_terms": ["arco", "derechos"],
            "has_explicit_arco_mention": True
        }
    }

    result = RulesEngine.evaluate(mock_scan_data)
    assert result["verdict"] == "APROBADO"
    assert result["score"] >= 80
    assert result["page_load_status"] == 1
    assert len(result["findings"]) > 0

    # Todos los findings deben tener ticket técnico de remediación
    for finding in result["findings"]:
        assert "remediation_ticket" in finding
        assert len(finding["remediation_ticket"]) > 10


def test_evaluate_rechazado_con_trackers_generates_actionable_tickets():
    mock_scan_data = {
        "target_url": "https://tienda-ejemplo.cl/",
        "page_load_status": 200,
        "error_message": None,
        "tracker_audit": {
            "detected_tracker_domains": ["google-analytics.com", "connect.facebook.net"],
            "detected_tracker_cookies": ["_ga", "_fbp"],
            "has_unauthorized_trackers": True
        },
        "privacy_policy_audit": {
            "found": True,
            "url": "https://tienda-ejemplo.cl/politica",
            "http_status": 200,
            "has_mandatory_keywords": True,
            "found_keywords": ["titular", "responsable", "derechos", "tratamiento"]
        },
        "arco_channels_audit": {
            "found": True,
            "detected_emails": ["contacto@tienda-ejemplo.cl"],
            "detected_terms": ["arco"],
            "has_explicit_arco_mention": True
        }
    }

    result = RulesEngine.evaluate(mock_scan_data)
    assert result["verdict"] == "RECHAZADO"
    assert result["pilares"]["consentimiento_cookies"]["score"] == 0
    assert result["pilares"]["consentimiento_cookies"]["status"] == "FALLA"

    fail_findings = [f for f in result["findings"] if f["status"] == "FAIL"]
    assert len(fail_findings) >= 2

    # Validar que los tickets de remediación mencionen herramientas técnicas (GTM, opt-in, etc.)
    ga_tickets = [f["remediation_ticket"] for f in fail_findings if "google-analytics.com" in f.get("technical_raw", "")]
    assert len(ga_tickets) > 0
    assert "Google Tag Manager" in ga_tickets[0] or "CMP" in ga_tickets[0] or "evento" in ga_tickets[0]


def test_evaluate_observaciones_without_trackers_but_missing_privacy_keywords():
    mock_scan_data = {
        "target_url": "https://portal.cl/",
        "page_load_status": 200,
        "error_message": None,
        "tracker_audit": {
            "detected_tracker_domains": [],
            "detected_tracker_cookies": [],
            "has_unauthorized_trackers": False
        },
        "privacy_policy_audit": {
            "found": True,
            "url": "https://portal.cl/aviso",
            "http_status": 200,
            "has_mandatory_keywords": False,
            "found_keywords": ["derechos"],
            "missing_keywords": ["titular", "responsable", "tratamiento", "finalidad"]
        },
        "arco_channels_audit": {
            "found": True,
            "detected_emails": ["info@portal.cl"],
            "detected_terms": ["contacto"],
            "has_explicit_arco_mention": False
        }
    }

    result = RulesEngine.evaluate(mock_scan_data)
    assert result["verdict"] == "CON_OBSERVACIONES"
    assert 55 <= result["score"] < 80
