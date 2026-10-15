"""
Pruebas para el Módulo de Auditoría de Flujo Multietapa (C-05).
Valida:
1. Definición y descubrimiento de etapas (FLOW_STAGES, PAYMENT_GATEWAY_DOMAINS).
2. Inspección pasiva estricta (DA-01 / EC-04): Cero métodos de mutación activa (click, fill, submit) y 0 requests distintos de GET.
3. Reglas de negocio del motor de flujo (FlowRulesEngine) ante flujos limpios, con nuevos rastreadores, con pasarelas externas o no detectados.
4. Resiliencia y manejo de timeouts.
5. Contrato de API asíncrono C-05 (POST /api/v1/flow-audit y GET /api/v1/flow-audit/{job_id}).
"""

import pytest
from unittest.mock import patch, MagicMock
from httpx import AsyncClient, ASGITransport

from src.api.main import app
from src.scanner.stage_patterns import (
    FLOW_STAGES,
    PAYMENT_GATEWAY_DOMAINS,
    get_stage_names,
    get_stage_by_name,
)
from src.scanner.flow_inspector import FlowInspector, StageCapture
from src.scanner.flow_rules import FlowRulesEngine, FLOW_LEGAL_DISCLAIMER
from src.api.schemas import FlowScanRequest, FlowAuditResponse, FlowStageResult


def test_flow_stages_defined():
    """Valida que FLOW_STAGES defina las etapas secuenciales requeridas."""
    names = get_stage_names()
    assert "catalogo" in names
    assert "registro" in names
    assert "carrito" in names

    for stage in FLOW_STAGES:
        assert "name" in stage
        assert "label" in stage
        assert isinstance(stage["url_patterns"], list)
        assert isinstance(stage["text_patterns"], list)
        assert len(stage["url_patterns"]) > 0


def test_payment_gateways_include_chilean_and_international():
    """Valida cobertura de pasarelas de pago nacionales e internacionales."""
    assert any("webpay" in gw for gw in PAYMENT_GATEWAY_DOMAINS)
    assert any("flow" in gw for gw in PAYMENT_GATEWAY_DOMAINS)
    assert any("mercadopago" in gw for gw in PAYMENT_GATEWAY_DOMAINS)
    assert any("stripe" in gw for gw in PAYMENT_GATEWAY_DOMAINS)
    assert any("paypal" in gw for gw in PAYMENT_GATEWAY_DOMAINS)


def test_flow_inspector_zero_mutation_methods():
    """DA-01 / EC-04: FlowInspector no debe exponer métodos de mutación activa."""
    inspector = FlowInspector()
    assert not hasattr(inspector, "post_form")
    assert not hasattr(inspector, "submit_form")
    assert not hasattr(inspector, "click_and_fill")
    assert not hasattr(inspector, "click_button")


def test_flow_inspector_is_payment_gateway():
    """Valida la detección determinista de pasarelas de pago externas."""
    assert FlowInspector._is_payment_gateway("https://webpay.transbank.cl/portal") is True
    assert FlowInspector._is_payment_gateway("https://checkout.stripe.com/c/pay/123") is True
    assert FlowInspector._is_payment_gateway("https://app.flow.cl/pago") is True
    assert FlowInspector._is_payment_gateway("https://tienda.cl/carrito") is False
    assert FlowInspector._is_payment_gateway("https://tienda.cl/productos") is False


def test_stage_capture_tracks_requests_and_methods():
    """Valida que StageCapture registre el método HTTP, URL y dominios de rastreo."""
    capture = StageCapture("catalogo")

    req1 = MagicMock()
    req1.url = "https://tienda.cl/api/catalog"
    req1.method = "GET"
    capture.handle_request(req1)

    req2 = MagicMock()
    req2.url = "https://www.google-analytics.com/g/collect"
    req2.method = "GET"
    capture.handle_request(req2)

    assert len(capture.requests) == 2
    assert capture.requests[0]["method"] == "GET"
    assert capture.requests[1]["method"] == "GET"
    assert "google-analytics.com" in capture.tracker_domains


def test_flow_rules_no_flow_detected():
    """Valida que ante un sitio sin flujo se informe claramente y se ofrezca escaneo estándar."""
    mock_data = {
        "target_url": "https://blog-informativo.cl/",
        "flow_detected": False,
        "flow_not_detected_reason": "No se encontraron enlaces a etapas de compra/registro.",
        "stages": [],
        "limitations": ["Limitación Nivel 0"],
    }
    result = FlowRulesEngine.evaluate(mock_data)
    assert result["flow_detected"] is False
    assert result["flow_verdict"] == "NO_APLICABLE"
    assert "estándar" in result["flow_verdict_summary"].lower()


def test_flow_rules_clean_flow_cumple():
    """Valida que un flujo donde ninguna etapa inyecta rastreadores nuevos obtenga CUMPLE."""
    mock_data = {
        "target_url": "https://tienda-limpia.cl/",
        "flow_detected": True,
        "stages": [
            {
                "stage_name": "inicio",
                "stage_label": "Página de Inicio",
                "url": "https://tienda-limpia.cl/",
                "verdict": "CUMPLE",
                "status": "ok",
                "new_tracker_domains": [],
                "new_tracker_cookies": [],
            },
            {
                "stage_name": "catalogo",
                "stage_label": "Catálogo",
                "url": "https://tienda-limpia.cl/productos",
                "verdict": "CUMPLE",
                "status": "ok",
                "new_tracker_domains": [],
                "new_tracker_cookies": [],
            },
            {
                "stage_name": "registro",
                "stage_label": "Registro",
                "url": "https://tienda-limpia.cl/registro",
                "verdict": "CUMPLE",
                "status": "ok",
                "new_tracker_domains": [],
                "new_tracker_cookies": [],
            },
        ],
        "limitations": ["Carrito visitado vacío"],
    }
    result = FlowRulesEngine.evaluate(mock_data)
    assert result["flow_detected"] is True
    assert result["flow_verdict"] == "CUMPLE"
    assert len(result["stages_evaluated"]) == 3
    ok_findings = [f for f in result["flow_findings"] if f["status"] == "OK"]
    assert len(ok_findings) == 3


def test_flow_rules_new_trackers_in_registration_no_cumple():
    """Valida que la aparición de trackers nuevos en la etapa de registro produzca NO_CUMPLE."""
    mock_data = {
        "target_url": "https://tienda-insegura.cl/",
        "flow_detected": True,
        "stages": [
            {
                "stage_name": "inicio",
                "stage_label": "Página de Inicio",
                "url": "https://tienda-insegura.cl/",
                "verdict": "CUMPLE",
                "status": "ok",
                "new_tracker_domains": [],
                "new_tracker_cookies": [],
            },
            {
                "stage_name": "registro",
                "stage_label": "Registro / Cuenta",
                "url": "https://tienda-insegura.cl/cuenta",
                "verdict": "NO_CUMPLE",
                "status": "ok",
                "new_tracker_domains": ["connect.facebook.net"],
                "new_tracker_cookies": ["_fbp"],
            },
        ],
        "limitations": [],
    }
    result = FlowRulesEngine.evaluate(mock_data)
    assert result["flow_verdict"] == "NO_CUMPLE"
    fail_findings = [f for f in result["flow_findings"] if f["status"] == "FAIL"]
    assert len(fail_findings) >= 2
    assert any("connect.facebook.net" in f["technical_raw"] for f in fail_findings)
    assert any("_fbp" in f["technical_raw"] for f in fail_findings)


def test_flow_rules_external_payment_gateway():
    """Valida el manejo de etapas donde se detecta una pasarela de pago externa."""
    mock_data = {
        "target_url": "https://tienda-pagos.cl/",
        "flow_detected": True,
        "stages": [
            {
                "stage_name": "carrito",
                "stage_label": "Carrito / Checkout",
                "url": "https://webpay.transbank.cl/portal",
                "verdict": "NO_ALCANZADA",
                "status": "pasarela_externa",
                "new_tracker_domains": [],
                "new_tracker_cookies": [],
            }
        ],
        "limitations": [],
    }
    result = FlowRulesEngine.evaluate(mock_data)
    warn_findings = [f for f in result["flow_findings"] if f["status"] == "WARNING"]
    assert any("pasarela" in f["title"].lower() for f in warn_findings)


def test_flow_inspector_timeout_result():
    """Valida la respuesta de fallback ante timeout global del flujo."""
    inspector = FlowInspector(total_timeout_seconds=60.0)
    res = inspector._build_timeout_result("https://tienda-lenta.cl/")
    assert res["flow_detected"] is False
    assert "Tiempo límite" in res["flow_not_detected_reason"]


def test_flow_inspector_source_has_no_active_mutation_calls():
    """DA-01: Verificación estática de que flow_inspector.py no invoque .click(, .fill( ni .submit(."""
    import inspect
    from src.scanner import flow_inspector
    source = inspect.getsource(flow_inspector)
    assert ".click(" not in source
    assert ".fill(" not in source
    assert ".submit(" not in source


@pytest.mark.asyncio
async def test_api_flow_audit_lifecycle():
    """Valida el contrato C-05: POST /flow-audit devuelve job_id y GET consulta estado."""
    mock_flow_eval = {
        "target_url": "https://tienda-test.cl/",
        "flow_detected": True,
        "flow_verdict": "CUMPLE",
        "flow_verdict_summary": "Flujo auditado correctamente.",
        "total_stages_evaluated": 2,
        "stages_evaluated": [],
        "flow_findings": [],
        "limitations": [],
        "legal_disclaimer": FLOW_LEGAL_DISCLAIMER,
    }

    with patch("src.scanner.flow_inspector.FlowInspector.audit_flow", return_value={"target_url": "https://tienda-test.cl/", "flow_detected": True, "stages": []}):
        with patch("src.scanner.flow_rules.FlowRulesEngine.evaluate", return_value=mock_flow_eval):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                # 1. Iniciar flujo
                post_res = await client.post("/api/v1/flow-audit", json={"url": "https://tienda-test.cl"})
                assert post_res.status_code == 200
                data = post_res.json()
                assert "job_id" in data
                job_id = data["job_id"]

                # 2. Consultar estado del job
                get_res = await client.get(f"/api/v1/flow-audit/{job_id}")
                assert get_res.status_code == 200
                job_data = get_res.json()
                assert job_data["status"] in ("queued", "running", "completed")
