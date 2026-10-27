"""
Suite Exhaustiva de Pruebas para el Motor de Reglas (FB-02 / FB-04 / FB-06).
Cubre los 6 escenarios principales de dictamen determinista y tickets de remediación.
"""

import pytest
from src.scanner.rules_engine import RulesEngine


def test_rules_case_1_aprobado_sitio_conforme():
    """Caso 1: Aprobado (score >= 80, 0 trackers, política accesible con keywords, canales ARCO completos)."""
    scan_data = {
        "target_url": "https://sitio-conforme.cl/",
        "page_load_status": 200,
        "tracker_audit": {
            "has_unauthorized_trackers": False,
            "detected_tracker_domains": [],
            "detected_tracker_cookies": []
        },
        "privacy_policy_audit": {
            "found": True,
            "url": "https://sitio-conforme.cl/privacidad",
            "http_status": 200,
            "has_mandatory_keywords": True,
            "found_keywords": ["titular", "responsable", "derechos", "tratamiento"]
        },
        "arco_channels_audit": {
            "found": True,
            "detected_emails": ["privacidad@sitio-conforme.cl"],
            "has_explicit_arco_mention": True,
            "detected_terms": ["acceso", "rectificación", "cancelación", "oposición"]
        }
    }
    result = RulesEngine.evaluate(scan_data)
    assert result["verdict"] == "APROBADO"
    assert result["score"] >= 80
    assert result["page_load_status"] == 1
    for f in result["findings"]:
        assert "remediation_ticket" in f and len(f["remediation_ticket"]) > 0


def test_rules_case_2_rechazado_trackers_no_autorizados():
    """Caso 2: Rechazado (inyección de rastreadores o cookies de terceros previo a consentimiento)."""
    scan_data = {
        "target_url": "https://tienda-trackers.cl/",
        "page_load_status": 200,
        "tracker_audit": {
            "has_unauthorized_trackers": True,
            "detected_tracker_domains": ["google-analytics.com", "connect.facebook.net"],
            "detected_tracker_cookies": ["_ga", "_fbp"]
        },
        "privacy_policy_audit": {
            "found": True,
            "url": "https://tienda-trackers.cl/privacidad",
            "http_status": 200,
            "has_mandatory_keywords": True,
            "found_keywords": ["titular", "responsable"]
        },
        "arco_channels_audit": {
            "found": True,
            "detected_emails": ["info@tienda-trackers.cl"],
            "has_explicit_arco_mention": True,
            "detected_terms": ["arco"]
        }
    }
    result = RulesEngine.evaluate(scan_data)
    assert result["verdict"] == "RECHAZADO"
    assert result["pilares"]["consentimiento_cookies"]["score"] == 0
    fail_findings = [f for f in result["findings"] if f["status"] == "FAIL"]
    assert len(fail_findings) >= 2
    for f in fail_findings:
        assert "Google Tag Manager" in f["remediation_ticket"] or "cookie" in f["remediation_ticket"].lower()


def test_rules_case_3_no_accesible_bloqueo_waf_403():
    """Caso 3: No accesible (WAF 403 / 503 / Anti-bot challenge). Dictamen neutro no sancionatorio."""
    scan_data = {
        "target_url": "https://sitio-cloudflare.cl/",
        "page_load_status": 403,
        "error_message": "BLOQUEO_WAF_ANTIBOT",
        "tracker_audit": {"has_unauthorized_trackers": False, "detected_tracker_domains": [], "detected_tracker_cookies": []},
        "privacy_policy_audit": {"found": False, "http_status": 403},
        "arco_channels_audit": {"found": False, "detected_emails": []}
    }
    result = RulesEngine.evaluate(scan_data)
    assert result["verdict"] == "NO_ACCESIBLE"
    assert result["score"] == 0
    assert result["page_load_status"] == 0
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["pilar"] == "ACCESIBILIDAD_PERIMETRAL"
    assert finding["status"] == "WARNING"
    assert "remediation_ticket" in finding
    assert "WAF" in finding["remediation_ticket"] or "Cloudflare" in finding["remediation_ticket"]


def test_rules_case_4_politica_rota_o_faltante_404():
    """Caso 4: Política de privacidad rota (HTTP 404) genera hallazgo FAIL y ticket de ruta canónica."""
    scan_data = {
        "target_url": "https://sitio-politica-rota.cl/",
        "page_load_status": 200,
        "tracker_audit": {"has_unauthorized_trackers": False, "detected_tracker_domains": [], "detected_tracker_cookies": []},
        "privacy_policy_audit": {
            "found": False,
            "url": "https://sitio-politica-rota.cl/privacidad",
            "http_status": 404
        },
        "arco_channels_audit": {
            "found": True,
            "detected_emails": ["contacto@sitio.cl"],
            "has_explicit_arco_mention": True,
            "detected_terms": ["arco"]
        }
    }
    result = RulesEngine.evaluate(scan_data)
    assert result["pilares"]["politica_privacidad"]["status"] == "FALLA"
    assert result["pilares"]["politica_privacidad"]["score"] == 0
    policy_findings = [f for f in result["findings"] if f["pilar"] == "POLITICA_PRIVACIDAD"]
    assert len(policy_findings) > 0
    assert policy_findings[0]["status"] == "FAIL"
    assert "/privacidad" in policy_findings[0]["remediation_ticket"]


def test_rules_case_5_canales_arco_incompletos_o_ausentes():
    """Caso 5: Canales ARCO ausentes genera FAIL y ticket con plantilla HTML mailto."""
    scan_data = {
        "target_url": "https://sitio-sin-arco.cl/",
        "page_load_status": 200,
        "tracker_audit": {"has_unauthorized_trackers": False, "detected_tracker_domains": [], "detected_tracker_cookies": []},
        "privacy_policy_audit": {
            "found": True,
            "url": "https://sitio-sin-arco.cl/privacidad",
            "http_status": 200,
            "has_mandatory_keywords": True,
            "found_keywords": ["titular", "responsable"]
        },
        "arco_channels_audit": {
            "found": False,
            "detected_emails": [],
            "has_explicit_arco_mention": False,
            "detected_terms": []
        }
    }
    result = RulesEngine.evaluate(scan_data)
    assert result["pilares"]["canales_arco"]["score"] == 0
    assert result["pilares"]["canales_arco"]["status"] == "FALLA"
    arco_findings = [f for f in result["findings"] if f["pilar"] == "CANALES_ARCO"]
    assert len(arco_findings) > 0
    assert arco_findings[0]["status"] == "FAIL"
    assert "mailto:" in arco_findings[0]["remediation_ticket"] or "privacidad@" in arco_findings[0]["remediation_ticket"]


def test_rules_case_6_banner_sin_opcion_rechazo_con_observaciones():
    """Caso 6: Banner de cookies puramente informativo sin botón de rechazo -> CON_OBSERVACIONES."""
    scan_data = {
        "target_url": "https://sitio-banner-informativo.cl/",
        "page_load_status": 200,
        "tracker_audit": {"has_unauthorized_trackers": False, "detected_tracker_domains": [], "detected_tracker_cookies": []},
        "privacy_policy_audit": {
            "found": True,
            "url": "https://sitio-banner-informativo.cl/privacidad",
            "http_status": 200,
            "has_mandatory_keywords": True,
            "found_keywords": ["titular", "responsable", "derechos", "tratamiento"]
        },
        "arco_channels_audit": {
            "found": True,
            "detected_emails": ["arco@sitio.cl"],
            "has_explicit_arco_mention": True,
            "detected_terms": ["arco"]
        },
        "consent_banner_audit": {
            "banner_detected": True,
            "has_reject_option": False,
            "has_accept_option": True,
            "has_settings_option": False,
            "buttons_verifiable": True,
            "cmp_provider": "Generico",
            "detected_buttons": ["Aceptar"]
        }
    }
    result = RulesEngine.evaluate(scan_data)
    assert result["verdict"] == "CON_OBSERVACIONES"
    banner_findings = [f for f in result["findings"] if "Banner" in f["title"]]
    assert len(banner_findings) > 0
    assert "Rechazar" in banner_findings[0]["remediation_ticket"] or "rechazo" in banner_findings[0]["remediation_ticket"].lower()
