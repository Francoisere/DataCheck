"""
Pruebas unitarias y de integración para detección de CMPs, auditoría de banners en iframes y Shadow DOM (Paso 11).

Este módulo valida:
1. Coincidencia exacta y por prefijo de cookies de rastreo (is_tracker_cookie).
2. Estructura y cobertura de firmas de CMP (CMP_SIGNATURES, CMP_FRAME_DOMAINS) incluyendo Sourcepoint y TrustArc.
3. Diccionario de términos en español para botones de banners de consentimiento (BANNER_BUTTON_TEXTS).
4. Reglas de negocio del motor de cumplimiento (RulesEngine):
   - Banner sin rechazo directo (2 pasos o puramente informativo).
   - Banner con opción de rechazo conforme.
   - Sitio limpio sin trackers ni banner (35 pts, dictamen APROBADO 100/100).
   - Shadow DOM cerrado (no penaliza puntaje, 35 pts si no hay trackers).
   - Evaluación del dictamen de bloqueo preventivo (blocks_prior_to_consent).
5. Principio de inspección pasiva estricta (DA-01 / EC-04) en WebInspector y ConsentDetector.
6. Pruebas reales en navegador Chromium con Playwright simulando Shadow DOM abierto, Shadow DOM cerrado e iframes de terceros con rutas interceptadas.
"""

import pytest
from playwright.async_api import async_playwright

from src.scanner.trackers_db import (
    is_tracker_cookie,
    CMP_SIGNATURES,
    CMP_FRAME_DOMAINS,
    BANNER_BUTTON_TEXTS
)
from src.scanner.rules_engine import RulesEngine
from src.scanner.inspector import WebInspector
from src.scanner.consent_detector import ConsentDetector


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
    (cookiebot, onetrust, didomi, usercentrics, iubenda, quantcast, sourcepoint, trustarc)
    y que cada entrada posea las claves 'frame_domains', 'selectors' y 'container_id'.
    """
    expected_cmps = [
        "cookiebot", "onetrust", "didomi", "usercentrics",
        "iubenda", "quantcast", "sourcepoint", "trustarc"
    ]
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
        "sdk.privacy-center.org",
        "consent.trustarc.com"
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
    Test 6: Valida que cuando se detecta un banner de consentimiento puramente informativo
    sin opción de rechazo, RulesEngine.evaluate genere un hallazgo WARNING y dictamine CON_OBSERVACIONES.
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
            "has_settings_option": False,
            "detected_cmp": "cookiebot",
            "detected_buttons": ["Aceptar todas"]
        }
    }

    result = RulesEngine.evaluate(mock_scan_data)

    warning_findings = [f for f in result["findings"] if f["status"] == "WARNING"]
    assert len(warning_findings) > 0, "Se esperaba al menos un hallazgo con status WARNING"

    reject_warnings = [
        f for f in warning_findings
        if any(term in (f.get("title", "") + " " + f.get("detail", "") + " " + f.get("remediation_ticket", "")).lower()
               for term in ["rechazo", "rechazar", "reject", "opción"])
    ]
    assert len(reject_warnings) > 0, "No se encontró un hallazgo WARNING sobre la ausencia de opción de rechazo"
    assert result["verdict"] == "CON_OBSERVACIONES"
    assert result["pilares"]["consentimiento_cookies"]["score"] == 20


def test_rules_engine_banner_two_steps_settings_warning():
    """
    Test 7: Valida el tratamiento de banner de 2 pasos (Aceptar + Configurar, sin Rechazar directo):
    veredicto CON_OBSERVACIONES, puntaje 20/35 y ticket técnico aclarando la limitación de inspección pasiva.
    """
    mock_scan_data = {
        "target_url": "https://sitio-dos-pasos.cl/",
        "page_load_status": 200,
        "error_message": None,
        "tracker_audit": {
            "detected_tracker_domains": [],
            "detected_tracker_cookies": [],
            "has_unauthorized_trackers": False
        },
        "privacy_policy_audit": {
            "found": True,
            "url": "https://sitio-dos-pasos.cl/privacidad",
            "http_status": 200,
            "has_mandatory_keywords": True,
            "found_keywords": ["titular", "responsable", "derechos", "tratamiento", "finalidad"]
        },
        "arco_channels_audit": {
            "found": True,
            "detected_emails": ["contacto@sitio-dos-pasos.cl"],
            "detected_terms": ["arco", "derechos"],
            "has_explicit_arco_mention": True
        },
        "consent_banner_audit": {
            "banner_detected": True,
            "has_reject_option": False,
            "has_settings_option": True,
            "has_accept_option": True,
            "detected_cmp": "onetrust",
            "detected_buttons": ["Aceptar", "Configuración de cookies"]
        }
    }

    result = RulesEngine.evaluate(mock_scan_data)
    assert result["verdict"] == "CON_OBSERVACIONES"
    assert result["pilares"]["consentimiento_cookies"]["score"] == 20

    two_step_finding = next((f for f in result["findings"] if "2 Pasos" in f.get("title", "")), None)
    assert two_step_finding is not None
    assert "primer nivel" in two_step_finding["detail"].lower()
    assert "da-01" in two_step_finding["detail"].lower()


def test_rules_engine_banner_with_reject_gives_ok_finding():
    """
    Test 8: Valida que cuando un banner cuenta con opción explícita de rechazo,
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
            "has_accept_option": True,
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
    assert result["verdict"] == "APROBADO"
    assert result["pilares"]["consentimiento_cookies"]["score"] == 35


def test_rules_engine_no_banner_no_trackers_full_score_aprobado():
    """
    Test 9: Valida que un sitio web sin trackers y sin banner obtenga puntaje completo (35/35)
    en el pilar de consentimiento y veredicto APROBADO (100 pts), reconociendo que un sitio estático
    o limpio no requiere banner si no ejecuta rastreo.
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
    assert consent_pilar["score"] == 35, f"Se esperaban 35 puntos en consentimiento_cookies, pero se obtuvo {consent_pilar['score']}"
    assert result["verdict"] == "APROBADO"
    assert result["score"] == 100


def test_rules_engine_closed_shadow_dom_no_penalty():
    """
    Test 10: Valida que un banner dentro de un Shadow DOM cerrado (buttons_verifiable=False)
    no sea penalizado cuando no hay trackers activos (35 pts y veredicto APROBADO),
    generando un hallazgo informativo que declara la limitación técnica de inspección pasiva.
    """
    mock_scan_data = {
        "target_url": "https://sitio-shadow-cerrado.cl/",
        "page_load_status": 200,
        "error_message": None,
        "tracker_audit": {
            "detected_tracker_domains": [],
            "detected_tracker_cookies": [],
            "has_unauthorized_trackers": False
        },
        "privacy_policy_audit": {
            "found": True,
            "url": "https://sitio-shadow-cerrado.cl/privacidad",
            "http_status": 200,
            "has_mandatory_keywords": True,
            "found_keywords": ["titular", "responsable", "derechos", "tratamiento", "finalidad"]
        },
        "arco_channels_audit": {
            "found": True,
            "detected_emails": ["contacto@sitio-shadow-cerrado.cl"],
            "detected_terms": ["arco"],
            "has_explicit_arco_mention": True
        },
        "consent_banner_audit": {
            "banner_detected": True,
            "buttons_verifiable": False,
            "has_reject_option": False,
            "cmp_provider": "usercentrics"
        }
    }

    result = RulesEngine.evaluate(mock_scan_data)
    assert result["pilares"]["consentimiento_cookies"]["score"] == 35
    assert result["verdict"] == "APROBADO"

    shadow_finding = next((f for f in result["findings"] if "Shadow DOM Cerrado" in f.get("title", "")), None)
    assert shadow_finding is not None
    assert "da-01" in shadow_finding["detail"].lower()


def test_rules_engine_blocks_prior_to_consent_verdict():
    """
    Test 11: Valida el cálculo del dictamen de bloqueo preventivo pre-consentimiento:
    - True cuando existe banner y no se detectan trackers.
    - False cuando existe banner pero se interceptaron trackers no autorizados.
    """
    # Caso 1: Bloquea
    clean_data = {
        "target_url": "https://bloquea.cl/",
        "page_load_status": 200,
        "tracker_audit": {"has_unauthorized_trackers": False, "detected_tracker_domains": [], "detected_tracker_cookies": []},
        "privacy_policy_audit": {"found": True, "http_status": 200, "has_mandatory_keywords": True, "found_keywords": ["titular"]},
        "arco_channels_audit": {"found": True, "detected_emails": ["a@b.cl"], "detected_terms": ["arco"], "has_explicit_arco_mention": True},
        "consent_banner_audit": {"banner_detected": True, "has_reject_option": True}
    }
    r1 = RulesEngine.evaluate(clean_data)
    assert r1["consent_banner_audit"]["blocks_prior_to_consent"] is True

    # Caso 2: No bloquea
    leaking_data = {
        "target_url": "https://no-bloquea.cl/",
        "page_load_status": 200,
        "tracker_audit": {"has_unauthorized_trackers": True, "detected_tracker_domains": ["google-analytics.com"], "detected_tracker_cookies": ["_ga"]},
        "privacy_policy_audit": {"found": True, "http_status": 200, "has_mandatory_keywords": True, "found_keywords": ["titular"]},
        "arco_channels_audit": {"found": True, "detected_emails": ["a@b.cl"], "detected_terms": ["arco"], "has_explicit_arco_mention": True},
        "consent_banner_audit": {"banner_detected": True, "has_reject_option": True}
    }
    r2 = RulesEngine.evaluate(leaking_data)
    assert r2["consent_banner_audit"]["blocks_prior_to_consent"] is False
    assert r2["verdict"] == "RECHAZADO"


def test_ec04_still_passes_no_mutation_methods():
    """
    Test 12: Re-verifica que WebInspector y ConsentDetector no contengan métodos de mutación activa
    (post_form, submit_form, click_and_fill, click, fill, submit), asegurando el cumplimiento estricto de DA-01.
    """
    inspector = WebInspector()
    assert not hasattr(inspector, "post_form"), "WebInspector no debe exponer método post_form"
    assert not hasattr(inspector, "submit_form"), "WebInspector no debe exponer método submit_form"
    assert not hasattr(inspector, "click_and_fill"), "WebInspector no debe exponer método click_and_fill"

    for forbidden in ["click", "fill", "submit", "post_form", "click_and_fill"]:
        assert not hasattr(ConsentDetector, forbidden), f"ConsentDetector no debe exponer método mutativo '{forbidden}'"


# =========================================================================
# PRUEBAS DE INTEGRACIÓN CON CHROMIUM (PLAYWRIGHT)
# =========================================================================

async def _launch_browser(p):
    """Lanza Chromium usando binario descargado o navegador del sistema (Chrome/Edge)."""
    try:
        return await p.chromium.launch(headless=True)
    except Exception:
        try:
            return await p.chromium.launch(channel="chrome", headless=True)
        except Exception:
            return await p.chromium.launch(channel="msedge", headless=True)


@pytest.mark.asyncio
async def test_playwright_consent_detector_open_shadow_dom():
    """
    Test 13: Prueba en Chromium real con un componente web que encapsula el banner
    en un Shadow DOM abierto (modo 'open'). Valida que queryAllDeep atraviese la frontera
    y extraiga los botones de Aceptar y Rechazar.
    """
    async with async_playwright() as p:
        browser = await _launch_browser(p)
        context = await browser.new_context()
        page = await context.new_page()

        html = """
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><title>Open Shadow DOM CMP</title></head>
        <body>
            <h1>Sitio con Gestor en Shadow DOM</h1>
            <div id="usercentrics-cmp-host"></div>
            <script>
                const host = document.getElementById('usercentrics-cmp-host');
                const shadow = host.attachShadow({mode: 'open'});
                shadow.innerHTML = `
                    <div id="uc-banner" style="position:fixed;bottom:0;left:0;width:100%;height:100px;background:#f1f5f9;display:block;">
                        <p>Utilizamos cookies propias y de terceros.</p>
                        <button id="btn-accept">Aceptar todas</button>
                        <button id="btn-reject">Rechazar todas</button>
                    </div>
                `;
            </script>
        </body>
        </html>
        """
        await page.set_content(html)
        result = await ConsentDetector.detect_consent(page, "https://shadow-open.cl", max_poll_seconds=1.0)

        banner = result["consent_banner_audit"]
        assert banner["banner_detected"] is True
        assert banner["has_accept_option"] is True
        assert banner["has_reject_option"] is True
        assert banner["buttons_verifiable"] is True
        assert any("aceptar" in b.lower() for b in banner["detected_buttons"])
        assert any("rechazar" in b.lower() for b in banner["detected_buttons"])

        await browser.close()


@pytest.mark.asyncio
async def test_playwright_consent_detector_closed_shadow_dom():
    """
    Test 14: Prueba en Chromium real con Shadow DOM cerrado (modo 'closed').
    Valida que el banner sea detectado por el contenedor host de CMP pero catalogado
    con buttons_verifiable=False de forma no penalizante.
    """
    async with async_playwright() as p:
        browser = await _launch_browser(p)
        context = await browser.new_context()
        page = await context.new_page()

        html = """
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><title>Closed Shadow DOM CMP</title></head>
        <body>
            <h1>Sitio con Gestor Encapsulado Cerrado</h1>
            <div id="usercentrics-root" data-shadow="closed" style="position:fixed;bottom:0;width:100%;height:80px;background:#333;display:block;"></div>
            <script>
                const host = document.getElementById('usercentrics-root');
                const shadow = host.attachShadow({mode: 'closed'});
                shadow.innerHTML = '<button>Aceptar cookies</button>';
            </script>
        </body>
        </html>
        """
        await page.set_content(html)
        result = await ConsentDetector.detect_consent(page, "https://shadow-closed.cl", max_poll_seconds=1.0)

        banner = result["consent_banner_audit"]
        assert banner["banner_detected"] is True
        assert banner["buttons_verifiable"] is False

        await browser.close()


@pytest.mark.asyncio
async def test_playwright_consent_detector_cross_origin_cmp_iframe():
    """
    Test 15: Prueba en Chromium real con un iframe de origen cruzado perteneciente
    a un dominio CMP conocido (consentcdn.cookiebot.com). Valida la detección del frame,
    su clasificación en frames_audit y la extracción de controles dentro del iframe.
    """
    async with async_playwright() as p:
        browser = await _launch_browser(p)
        context = await browser.new_context()
        page = await context.new_page()

        # Interceptar solicitudes a consentcdn.cookiebot.com para servir el banner simulado
        async def handle_cookiebot(route):
            iframe_html = """
            <!DOCTYPE html>
            <html>
            <head><meta charset="utf-8"></head>
            <body>
                <div id="cookiebot-dialog">
                    <p>Gestionar preferencias de privacidad</p>
                    <button id="CybotCookiebotDialogBodyLevelButtonLevelOptinAllowallSelection">Aceptar todo</button>
                    <button id="CybotCookiebotDialogBodyButtonDecline">Rechazar todo</button>
                    <button id="CybotCookiebotDialogBodyLevelButtonCustomize">Configurar</button>
                </div>
            </body>
            </html>
            """
            await route.fulfill(status=200, content_type="text/html", body=iframe_html)

        await page.route("https://consentcdn.cookiebot.com/**", handle_cookiebot)

        main_html = """
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"><title>Sitio Principal</title></head>
        <body>
            <h1>Tienda Nacional</h1>
            <iframe src="https://consentcdn.cookiebot.com/banner.html" width="500" height="250"></iframe>
        </body>
        </html>
        """
        await page.set_content(main_html)
        await page.wait_for_timeout(600)

        result = await ConsentDetector.detect_consent(page, "https://tienda-nacional.cl", max_poll_seconds=1.5)

        banner = result["consent_banner_audit"]
        frames = result["frames_audit"]

        assert banner["banner_detected"] is True
        assert banner["has_accept_option"] is True
        assert banner["has_reject_option"] is True
        assert banner["has_settings_option"] is True
        assert banner["cmp_provider"] == "cookiebot"
        assert frames["cmp_frames"] >= 1
        assert frames["third_party_frames"] >= 1

        await browser.close()
