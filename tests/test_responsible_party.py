# -*- coding: utf-8 -*-
"""
Pruebas automatizadas para la verificación del Art. 14 ter (letras b y c) de la Ley N° 21.719:
- Detección de RUT, Razón Social y Representante legal.
- Detección de DPO / Encargado de prevención.
- Detección de canales de notificación (email, formulario, domicilio).
- Extracción de datos concretos de individualización y contacto.
- Integración en el motor de reglas (RulesEngine) y reporte técnico PDF.
"""

import pytest
from bs4 import BeautifulSoup

from src.scanner.responsible_detector import ResponsiblePartyDetector
from src.scanner.rules_engine import RulesEngine
from src.api.schemas import ScanResponse, ResponsiblePartyAudit
from src.services.pdf_report_service import PdfReportService


def test_detector_with_rut_and_email():
    html = """
    <html>
        <body>
            <p>Servicio provisto por Comercio Digital SpA, RUT 76.543.210-K.</p>
            <p>Contacto de privacidad: privacidad@comerciodigital.cl</p>
            <p>Domicilio: Av. Presidente Kennedy 5413, Las Condes, Santiago, Chile.</p>
        </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    result = ResponsiblePartyDetector.detect(soup, html, policy_text=html, policy_found=True)

    assert result["identified"] is True
    assert result["detected_rut"] == "76.543.210-K"
    assert result["corporate_name"] == "Comercio Digital SpA"
    assert result["contact_email"] == "privacidad@comerciodigital.cl"
    assert "Santiago, Chile" in result["postal_address"]
    assert "email" in result["contact_channels_found"]
    assert "domicilio" in result["contact_channels_found"]
    assert result["verdict"] == "CUMPLE"
    assert "conforme al Art. 14 ter" in result["notes"]


def test_detector_with_dpo_and_form():
    html = """
    <html>
        <body>
            <p>Representante legal: Juan Pérez. Encargado de prevención de datos (DPO) designado: dpo@empresa-ejemplo.cl.</p>
            <form action="/contacto" method="post">
                <input type="text" name="nombre" />
                <textarea name="mensaje"></textarea>
                <button type="submit">Enviar</button>
            </form>
        </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    result = ResponsiblePartyDetector.detect(soup, html, policy_text=html, policy_found=True)

    assert result["representative_found"] is True
    assert result["dpo_found"] is True
    assert result["dpo_email"] == "dpo@empresa-ejemplo.cl"
    assert "formulario" in result["contact_channels_found"]
    assert result["verdict"] == "CUMPLE"


def test_detector_missing_info_observacion():
    html = """
    <html>
        <body>
            <p>Esta es una política de privacidad genérica sin datos de la empresa ni formularios.</p>
        </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    result = ResponsiblePartyDetector.detect(soup, html, policy_text=html, policy_found=True)

    assert result["identified"] is False
    assert result["representative_found"] is False
    assert result["detected_rut"] is None
    assert result["corporate_name"] is None
    assert result["verdict"] == "OBSERVACION"
    assert "omisión" in result["notes"].lower()


def test_detector_policy_not_found_no_verificable():
    result = ResponsiblePartyDetector.detect(None, "", policy_text="", policy_found=False)

    assert result["verdict"] == "NO_VERIFICABLE"
    assert "ausencia o inaccesibilidad" in result["notes"]


def test_rules_engine_art14ter_cumple():
    mock_scan_data = {
        "target_url": "https://empresa-conforme.cl/",
        "page_load_status": 200,
        "error_message": None,
        "tracker_audit": {
            "detected_tracker_domains": [],
            "detected_tracker_cookies": [],
            "has_unauthorized_trackers": False
        },
        "privacy_policy_audit": {
            "found": True,
            "url": "https://empresa-conforme.cl/privacidad",
            "http_status": 200,
            "has_mandatory_keywords": True,
            "found_keywords": ["titular", "responsable", "derechos", "tratamiento", "finalidad"]
        },
        "arco_channels_audit": {
            "found": True,
            "detected_emails": ["privacidad@empresa-conforme.cl"],
            "detected_terms": ["arco", "derechos"],
            "has_explicit_arco_mention": True
        },
        "responsible_party_audit": {
            "identified": True,
            "representative_found": True,
            "dpo_found": True,
            "contact_channels_found": ["email", "formulario"],
            "verdict": "CUMPLE",
            "notes": "Conforme al Art. 14 ter.",
            "corporate_name": "Empresa Conforme SpA",
            "detected_rut": "76.111.222-3",
            "contact_email": "privacidad@empresa-conforme.cl",
            "postal_address": "Santiago, Chile"
        }
    }

    result = RulesEngine.evaluate(mock_scan_data)
    assert result["pilares"]["politica_privacidad"]["score"] == 35
    assert result["pilares"]["politica_privacidad"]["status"] == "CUMPLE"

    art14_findings = [f for f in result["findings"] if "Art. 14 ter" in f["title"]]
    assert len(art14_findings) == 1
    assert art14_findings[0]["status"] == "OK"
    assert "Empresa Conforme SpA" in art14_findings[0]["detail"]
    assert "76.111.222-3" in art14_findings[0]["detail"]
    assert art14_findings[0].get("legal_basis_key") == "POLITICA_PRIVACIDAD_ART14TER_OK"


def test_rules_engine_art14ter_warning_generates_ticket():
    mock_scan_data = {
        "target_url": "https://empresa-incompleta.cl/",
        "page_load_status": 200,
        "error_message": None,
        "tracker_audit": {
            "detected_tracker_domains": [],
            "detected_tracker_cookies": [],
            "has_unauthorized_trackers": False
        },
        "privacy_policy_audit": {
            "found": True,
            "url": "https://empresa-incompleta.cl/privacidad",
            "http_status": 200,
            "has_mandatory_keywords": True,
            "found_keywords": ["titular", "responsable", "derechos", "tratamiento", "finalidad"]
        },
        "arco_channels_audit": {
            "found": True,
            "detected_emails": ["contacto@empresa-incompleta.cl"],
            "detected_terms": ["arco"],
            "has_explicit_arco_mention": True
        },
        "responsible_party_audit": {
            "identified": False,
            "representative_found": False,
            "dpo_found": False,
            "contact_channels_found": [],
            "verdict": "OBSERVACION",
            "notes": "Omisión de individualización y canales."
        }
    }

    result = RulesEngine.evaluate(mock_scan_data)
    assert result["pilares"]["politica_privacidad"]["score"] == 30
    assert result["pilares"]["politica_privacidad"]["status"] == "OBSERVACION"

    warn_findings = [f for f in result["findings"] if "Art. 14 ter" in f["title"]]
    assert len(warn_findings) == 1
    assert warn_findings[0]["status"] == "WARNING"
    assert "Art. 14 ter" in warn_findings[0]["remediation_ticket"]
    assert warn_findings[0].get("legal_basis_key") == "POLITICA_PRIVACIDAD_ART14TER_WARNING"


def test_pdf_generation_with_responsible_party():
    audit_data = {
        "audit_id": "123e4567-e89b-12d3-a456-426614174000",
        "target_url": "https://empresa-test.cl/",
        "verdict": "APROBADO",
        "score": 95,
        "verdict_summary": "Conforme con la normativa.",
        "pilares": {
            "politica_privacidad": {"status": "CUMPLE", "score": 35, "max_score": 35},
            "canales_arco": {"status": "CUMPLE", "score": 30, "max_score": 30},
            "consentimiento_cookies": {"status": "CUMPLE", "score": 30, "max_score": 35}
        },
        "findings": [
            {
                "pilar": "POLITICA_PRIVACIDAD",
                "status": "OK",
                "title": "Identificación del Responsable (Art. 14 ter)",
                "detail": "RUT e identidad del responsable detectados.",
                "remediation_ticket": "Mantener actualizados los datos.",
                "articulo_ley": "Art. 14 ter - Ley 21.719",
                "principio_vulnerado": "Ninguno",
                "sancion_estimada": "Sin sanción"
            }
        ],
        "consent_banner_audit": {
            "banner_detected": True,
            "cmp_provider": "cookiebot",
            "has_reject_option": True,
            "has_accept_option": True,
            "has_settings_option": True,
            "detected_buttons": ["Aceptar", "Rechazar"],
            "banner_source_frame": "Frame principal",
            "buttons_verifiable": True,
            "blocks_prior_to_consent": True
        },
        "frames_audit": {
            "total_frames": 1,
            "third_party_frames": 0,
            "cmp_frames": 0,
            "frames": []
        },
        "responsible_party_audit": {
            "identified": True,
            "representative_found": True,
            "dpo_found": True,
            "contact_channels_found": ["email", "formulario", "domicilio"],
            "verdict": "CUMPLE",
            "notes": "Conforme al Art. 14 ter.",
            "corporate_name": "Retail Test S.A.",
            "detected_rut": "77.888.999-0",
            "contact_email": "dpo@empresa-test.cl",
            "postal_address": "Santiago, Chile",
            "dpo_email": "dpo@empresa-test.cl"
        }
    }

    pdf_buffer = PdfReportService.generate_pdf_report(audit_data)
    assert pdf_buffer is not None
    assert len(pdf_buffer.getvalue()) > 1000
