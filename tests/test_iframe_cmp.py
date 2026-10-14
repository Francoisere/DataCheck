"""
Pruebas unitarias para detección de CMPs, auditoría de banners en iframes y filtrado de falsos positivos en cookies (Paso 11).

Este módulo valida mediante mocks y verificación estática:
1. Coincidencia exacta y por prefijo de cookies de rastreo (is_tracker_cookie).
2. Estructura y cobertura de firmas de CMP (CMP_SIGNATURES, CMP_FRAME_DOMAINS).
3. Diccionario de términos en español para botones de banners de consentimiento (BANNER_BUTTON_TEXTS).
4. Reglas de negocio del motor de cumplimiento (RulesEngine) ante presencia/ausencia de banner y opción de rechazo.
5. Principio de inspección pasiva estricta (DA-01 / EC-04) sin métodos de mutación activa en WebInspector.
"""

import pytest
from src.scanner.trackers_db import (
    is_tracker_cookie,
    CMP_SIGNATURES,
    CMP_FRAME_DOMAINS,
    BANNER_BUTTON_TEXTS
)
from src.scanner.rules_engine import RulesEngine
from src.scanner.inspector import WebInspector


def test_is_tracker_cookie_exact_match():
    """
    Test 1: Valida que la coincidencia exacta de cookies de rastreo identifique cookies conocidas
    sin generar falsos positivos con nombres que contengan substrings accidentales.
    """
    assert is_tracker_cookie("_ga") is True
    assert is_tracker_cookie("fr") is True
    assert is_tracker_cookie("lang_fr") is False
    assert is_tracker_cookie("preferred") is False


def test_is_tracker_cookie_prefix_match():
    """
    Test 2: Valida que las cookies con prefijos dinámicos conocidos de rastreo
    sean detectadas correctamente.
    """
    assert is_tracker_cookie("_gac_UA12345") is True
    assert is_tracker_cookie("_hjSession_123456") is True
    assert is_tracker_cookie("_ga_ABC123") is True


def test_cmp_signatures_structure():
    """
    Test 3: Valida que CMP_SIGNATURES contenga las plataformas CMP requeridas
    (cookiebot, onetrust, didomi, usercentrics, iubenda, quantcast) y que cada entrada
    posea las claves 'frame_domains' (lista), 'selectors' (lista) y 'container_id'.
    """
    expected_cmps = ["cookiebot", "onetrust", "didomi", "usercentrics", "iubenda", "quantcast"]
    for cmp_name in expected_cmps:
        assert cmp_name in CMP_SIGNATURES, f"El CMP '{cmp_name}' no se encuentra en CMP_SIGNATURES"
        cmp_entry = CMP_SIGNATURES[cmp_name]
        assert "frame_domains" in cmp_entry, f"Falta clave 'frame_domains' en '{cmp_name}'"
        assert isinstance(cmp_entry["frame_domains"], list), f"'frame_domains' en '{cmp_name}' debe ser una lista"
        assert "selectors" in cmp_entry, f"Falta clave 'selectors' en '{cmp_name}'"
        assert isinstance(cmp_entry["selectors"], list), f"'selectors' en '{cmp_name}' debe ser una lista"
        assert "container_id" in cmp_entry, f"Falta clave 'container_id' en '{cmp_name}'"


def test_cmp_frame_domains_flattened():
    """
    Test 4: Valida que CMP_FRAME_DOMAINS contenga los dominios conocidos de iframes
    utilizados comúnmente por los gestores de consentimiento.
    """
    expected_domains = [
        "consentcdn.cookiebot.com",
        "cdn.cookielaw.org",
        "sdk.privacy-center.org"
    ]
    for domain in expected_domains:
        assert domain in CMP_FRAME_DOMAINS, f"Dominio esperado '{domain}' no presente en CMP_FRAME_DOMAINS"


def test_banner_button_texts_include_spanish():
    """
    Test 5: Valida que BANNER_BUTTON_TEXTS contenga términos en español indispensables
    para detectar acciones de consentimiento (aceptar, rechazar, configurar, solo necesarias).
    """
    expected_terms = ["aceptar", "rechazar", "configurar", "solo necesarias"]

    if isinstance(BANNER_BUTTON_TEXTS, dict):
        flattened = []
        for val in BANNER_BUTTON_TEXTS.values():
            if isinstance(val, (list, set, tuple)):
                flattened.extend(val)
            elif isinstance(val, str):
                flattened.append(val)
        corpus = [str(t).lower() for t in flattened]
    else:
        corpus = [str(t).lower() for t in BANNER_BUTTON_TEXTS]

    for term in expected_terms:
        assert any(term in item for item in corpus), f"El término en español '{term}' no fue encontrado en BANNER_BUTTON_TEXTS"


def test_rules_engine_banner_no_reject_gives_observaciones():
    """
    Test 6: Valida que cuando se detecta un banner de consentimiento sin opción de rechazo,
    RulesEngine.evaluate genere un hallazgo WARNING y dictamine CON_OBSERVACIONES.
    """
    mock_scan_data = {
        "target_url": "https://sitio-banner-sin-rechazo.cl/",
        "page_load_status": 200,
        "error_message": None,
        "tracker_audit": {
            "detected_tracker_domains": [],
            "detected_tracker_cookies": [],
            "has_unauthorized_trackers": False
        },
        "privacy_policy_audit": {
            "found": True,
            "url": "https://sitio-banner-sin-rechazo.cl/privacidad",
            "http_status": 200,
            "has_mandatory_keywords": True,
            "found_keywords": ["titular", "responsable", "derechos", "tratamiento", "finalidad"]
        },
        "arco_channels_audit": {
            "found": True,
            "detected_emails": ["contacto@sitio-banner-sin-rechazo.cl"],
            "detected_terms": ["arco", "derechos"],
            "has_explicit_arco_mention": True
        },
        "consent_banner_audit": {
            "banner_detected": True,
            "has_reject_option": False,
            "detected_cmp": "cookiebot",
            "detected_buttons": ["Aceptar todas"]
        }
    }

    result = RulesEngine.evaluate(mock_scan_data)

    # Debe producir un finding de estado WARNING
    warning_findings = [f for f in result["findings"] if f["status"] == "WARNING"]
    assert len(warning_findings) > 0, "Se esperaba al menos un hallazgo con status WARNING"

    # Verificar que el finding se refiera a la falta de opción de rechazo
    reject_warnings = [
        f for f in warning_findings
        if any(term in (f.get("title", "") + " " + f.get("detail", "") + " " + f.get("remediation_ticket", "")).lower()
               for term in ["rechazo", "rechazar", "reject", "opción"])
    ]
    assert len(reject_warnings) > 0, "No se encontró un hallazgo WARNING sobre la ausencia de opción de rechazo"
    assert result["verdict"] == "CON_OBSERVACIONES"


def test_rules_engine_banner_with_reject_gives_ok_finding():
    """
    Test 7: Valida que cuando un banner cuenta con opción explícita de rechazo,
    RulesEngine.evaluate registre un hallazgo con status OK reconociendo los controles adecuados.
    """
    mock_scan_data = {
        "target_url": "https://sitio-banner-conforme.cl/",
        "page_load_status": 200,
        "error_message": None,
        "tracker_audit": {
            "detected_tracker_domains": [],
            "detected_tracker_cookies": [],
            "has_unauthorized_trackers": False
        },
        "privacy_policy_audit": {
            "found": True,
            "url": "https://sitio-banner-conforme.cl/privacidad",
            "http_status": 200,
            "has_mandatory_keywords": True,
            "found_keywords": ["titular", "responsable", "derechos", "tratamiento", "finalidad"]
        },
        "arco_channels_audit": {
            "found": True,
            "detected_emails": ["privacidad@sitio-banner-conforme.cl"],
            "detected_terms": ["arco", "derechos"],
            "has_explicit_arco_mention": True
        },
        "consent_banner_audit": {
            "banner_detected": True,
            "has_reject_option": True,
            "detected_cmp": "onetrust",
            "detected_buttons": ["Aceptar", "Rechazar todo"]
        }
    }

    result = RulesEngine.evaluate(mock_scan_data)

    ok_findings = [f for f in result["findings"] if f["status"] == "OK"]
    banner_ok_findings = [
        f for f in ok_findings
        if any(term in (f.get("title", "") + " " + f.get("detail", "")).lower()
               for term in ["banner", "consentimiento", "control", "rechazar", "rechazo"])
    ]
    assert len(banner_ok_findings) > 0, "No se encontró un hallazgo OK sobre los controles del banner de consentimiento"


def test_rules_engine_no_banner_no_trackers_partial_score():
    """
    Test 8: Valida que la ausencia de banner sin trackers resulte en un puntaje parcial (25 pts)
    en el pilar de consentimiento, ya que la transparencia exige mecanismos visibles de información.
    """
    mock_scan_data = {
        "target_url": "https://sitio-sin-banner.cl/",
        "page_load_status": 200,
        "error_message": None,
        "tracker_audit": {
            "detected_tracker_domains": [],
            "detected_tracker_cookies": [],
            "has_unauthorized_trackers": False
        },
        "privacy_policy_audit": {
            "found": True,
            "url": "https://sitio-sin-banner.cl/privacidad",
            "http_status": 200,
            "has_mandatory_keywords": True,
            "found_keywords": ["titular", "responsable", "derechos", "tratamiento", "finalidad"]
        },
        "arco_channels_audit": {
            "found": True,
            "detected_emails": ["contacto@sitio-sin-banner.cl"],
            "detected_terms": ["arco"],
            "has_explicit_arco_mention": True
        },
        "consent_banner_audit": {
            "banner_detected": False,
            "has_reject_option": False
        }
    }

    result = RulesEngine.evaluate(mock_scan_data)
    consent_pilar = result["pilares"]["consentimiento_cookies"]
    assert consent_pilar["score"] == 25, f"Se esperaban 25 puntos en consentimiento_cookies, pero se obtuvo {consent_pilar['score']}"


def test_ec04_still_passes_no_mutation_methods():
    """
    Test 9: Re-verifica que WebInspector no contenga métodos de mutación activa
    (post_form, submit_form, click_and_fill), asegurando el cumplimiento estricto de DA-01 (inspección pasiva).
    """
    inspector = WebInspector()
    assert not hasattr(inspector, "post_form"), "WebInspector no debe exponer método post_form"
    assert not hasattr(inspector, "submit_form"), "WebInspector no debe exponer método submit_form"
    assert not hasattr(inspector, "click_and_fill"), "WebInspector no debe exponer método click_and_fill"
