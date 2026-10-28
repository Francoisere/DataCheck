import pytest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, AsyncMock, MagicMock
from httpx import AsyncClient, ASGITransport

from src.api.main import app
from src.db.session import get_db_session
from src.services.email_service import EmailService
from src.services.schedule_service import ScheduleService
from src.db.models import AuditoriaProgramada, Auditoria, SitioAnalizado


# ==============================================================================
# Pruebas Unitarias de EmailService
# ==============================================================================

@pytest.mark.asyncio
async def test_email_service_graceful_fallback():
    """Valida que si SMTP falla o no está disponible, retorna False sin romper la ejecución."""
    with patch("aiosmtplib.send", side_effect=ConnectionRefusedError("SMTP offline")):
        sent = await EmailService.send_audit_notification(
            to_email="test@ejemplo.cl",
            target_url="https://ejemplo.cl",
            verdict="RECHAZADO",
            score=30,
            previous_verdict="RECHAZADO",
            previous_score=30,
            verdict_summary="Rechazado",
            findings_count=2
        )
        assert sent is False


@pytest.mark.asyncio
async def test_email_service_successful_send():
    """Valida el despacho exitoso cuando el transporte SMTP responde."""
    with patch("aiosmtplib.send", new_callable=AsyncMock) as mock_send:
        sent = await EmailService.send_audit_notification(
            to_email="cliente@ejemplo.cl",
            target_url="https://ejemplo.cl",
            verdict="APROBADO",
            score=100,
            previous_verdict="RECHAZADO",
            previous_score=30,
            verdict_summary="Aprobado",
            findings_count=0,
            pdf_bytes=b"%PDF-1.4 test"
        )
        assert sent is True
        assert mock_send.called
        # Validar adjunto presente
        call_msg = mock_send.call_args[0][0]
        assert call_msg["To"] == "cliente@ejemplo.cl"
        assert len(call_msg.get_payload()) == 2  # multipart/alternative + attachment


# ==============================================================================
# Pruebas de API: POST y GET /api/v1/schedules
# ==============================================================================

@pytest.mark.asyncio
@pytest.mark.asyncio
async def test_create_schedule_invalid_email_returns_400():
    """RF-SCHED-02: Rechazar correo sin formato válido."""
    random_uuid = str(uuid.uuid4())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/api/v1/schedules",
            json={
                "audit_id": random_uuid,
                "email": "correo-invalido",
                "interval_mode": "DEMO_2_MIN"
            }
        )
        assert res.status_code == 400
        assert "correo" in res.json()["detail"].lower()


@pytest.mark.asyncio
@pytest.mark.asyncio
async def test_create_schedule_audit_not_found_returns_404():
    """RF-SCHED-03: Auditoría inexistente en BD retorna 404."""
    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(return_value=AsyncMock(scalar_one_or_none=lambda: None))

    async def override_db():
        yield mock_db

    app.dependency_overrides[get_db_session] = override_db
    try:
        random_uuid = str(uuid.uuid4())
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.post(
                "/api/v1/schedules",
                json={
                    "audit_id": random_uuid,
                    "email": "devops@empresa.cl",
                    "interval_mode": "DEMO_2_MIN"
                }
            )
            assert res.status_code == 404
            assert "No se encontró" in res.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_db_session, None)


@pytest.mark.asyncio
async def test_create_schedule_aprobado_rejected_400():
    """RF-SCHED-01: No se permite programar re-evaluaciones para auditorías que ya fueron APROBADAS."""
    audit_uuid = uuid.uuid4()
    sitio_uuid = uuid.uuid4()

    mock_sitio = SitioAnalizado(id=sitio_uuid, url_normalizada="https://ejemplo-aprobado.cl/", dominio="ejemplo-aprobado.cl")
    mock_audit = Auditoria(
        id=audit_uuid,
        sitio_id=sitio_uuid,
        verdict="APROBADO",
        score=95,
        page_load_status=1,
        sitio=mock_sitio
    )

    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(return_value=AsyncMock(scalar_one_or_none=lambda: mock_audit))

    async def override_db():
        yield mock_db

    app.dependency_overrides[get_db_session] = override_db
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.post(
                "/api/v1/schedules",
                json={
                    "audit_id": str(audit_uuid),
                    "email": "seguridad@empresa.cl",
                    "interval_mode": "DEMO_2_MIN"
                }
            )
            assert res.status_code == 400
            assert "Solo se pueden programar" in res.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_db_session, None)


@pytest.mark.asyncio
async def test_create_schedule_rechazado_success():
    """RF-SCHED-01, RF-SCHED-02, RF-SCHED-03: Programación exitosa de re-auditoría para sitio RECHAZADO."""
    audit_uuid = uuid.uuid4()
    sitio_uuid = uuid.uuid4()

    mock_sitio = SitioAnalizado(id=sitio_uuid, url_normalizada="https://ejemplo-rechazado.cl/", dominio="ejemplo-rechazado.cl")
    mock_audit = Auditoria(
        id=audit_uuid,
        sitio_id=sitio_uuid,
        verdict="RECHAZADO",
        score=20,
        page_load_status=1,
        sitio=mock_sitio
    )

    created_schedule = None

    async def mock_execute(stmt):
        return AsyncMock(
            scalar_one_or_none=lambda: mock_audit,
            scalar_one=lambda: created_schedule or AuditoriaProgramada(
                id=uuid.uuid4(),
                sitio_id=sitio_uuid,
                ultima_auditoria_id=audit_uuid,
                email_notificacion="admin@ejemplo-rechazado.cl",
                intervalo_tipo="DEMO_2_MIN",
                proxima_ejecucion_en=datetime.now(timezone.utc) + timedelta(minutes=2),
                estado="PENDIENTE",
                sitio=mock_sitio
            )
        )

    mock_db = AsyncMock()
    mock_db.execute = mock_execute
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    async def override_db():
        yield mock_db

    app.dependency_overrides[get_db_session] = override_db
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.post(
                "/api/v1/schedules",
                json={
                    "audit_id": str(audit_uuid),
                    "email": "admin@ejemplo-rechazado.cl",
                    "interval_mode": "DEMO_2_MIN"
                }
            )
            assert res.status_code == 201
            data = res.json()
            assert data["status"] == "PENDIENTE"
            assert data["email"] == "admin@ejemplo-rechazado.cl"
            assert data["target_url"] == "https://ejemplo-rechazado.cl/"
            assert "scheduled_at" in data
            assert "schedule_id" in data
    finally:
        app.dependency_overrides.pop(get_db_session, None)


@pytest.mark.asyncio
async def test_get_schedule_endpoint():
    """Valida consulta de estado de re-auditoría programada."""
    sched_uuid = uuid.uuid4()
    sitio_uuid = uuid.uuid4()
    mock_sitio = SitioAnalizado(id=sitio_uuid, url_normalizada="https://ejemplo.cl/", dominio="ejemplo.cl")
    mock_sched = AuditoriaProgramada(
        id=sched_uuid,
        sitio_id=sitio_uuid,
        ultima_auditoria_id=uuid.uuid4(),
        email_notificacion="test@ejemplo.cl",
        intervalo_tipo="DEMO_2_MIN",
        proxima_ejecucion_en=datetime.now(timezone.utc),
        estado="PENDIENTE",
        sitio=mock_sitio
    )

    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(return_value=AsyncMock(scalar_one_or_none=lambda: mock_sched))

    async def override_db():
        yield mock_db

    app.dependency_overrides[get_db_session] = override_db
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            res = await client.get(f"/api/v1/schedules/{sched_uuid}")
            assert res.status_code == 200
            data = res.json()
            assert data["schedule_id"] == str(sched_uuid)
            assert data["status"] == "PENDIENTE"
            assert data["target_url"] == "https://ejemplo.cl/"
    finally:
        app.dependency_overrides.pop(get_db_session, None)


# ==============================================================================
# Pruebas de Ejecución de Re-auditoría (ScheduleService.execute_scheduled_audit)
# ==============================================================================

@pytest.mark.asyncio
async def test_execute_scheduled_audit_full_flow():
    """RF-SCHED-05, RF-SCHED-06: Ejecución completa de re-auditoría desatendida y despacho de notificación."""
    sched_uuid = uuid.uuid4()
    audit_uuid = uuid.uuid4()
    sitio_uuid = uuid.uuid4()

    mock_sitio = SitioAnalizado(id=sitio_uuid, url_normalizada="https://tienda-demo.cl/", dominio="tienda-demo.cl")
    prev_audit = Auditoria(id=audit_uuid, sitio_id=sitio_uuid, verdict="RECHAZADO", score=20, page_load_status=1, sitio=mock_sitio)
    sched_record = AuditoriaProgramada(
        id=sched_uuid,
        sitio_id=sitio_uuid,
        ultima_auditoria_id=audit_uuid,
        email_notificacion="contacto@tienda-demo.cl",
        intervalo_tipo="DEMO_2_MIN",
        proxima_ejecucion_en=datetime.now(timezone.utc) - timedelta(minutes=1),
        estado="PENDIENTE",
        sitio=mock_sitio,
        ultima_auditoria=prev_audit
    )

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=AsyncMock(scalar_one_or_none=lambda: sched_record))
    mock_session.commit = AsyncMock()

    mock_audit_result = {
        "audit_id": str(uuid.uuid4()),
        "target_url": "https://tienda-demo.cl/",
        "verdict": "APROBADO",
        "score": 90,
        "verdict_summary": "Subsanado correctamente.",
        "pilares": {
            "politica_privacidad": {"status": "CUMPLE", "score": 35, "max_score": 35},
            "canales_arco": {"status": "CUMPLE", "score": 30, "max_score": 30},
            "consentimiento_cookies": {"status": "CUMPLE", "score": 25, "max_score": 35}
        },
        "findings": []
    }

    with patch("src.services.schedule_service.AsyncSessionLocal", return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_session), __aexit__=AsyncMock())), \
         patch("src.services.schedule_service.AuditService.execute_audit", new_callable=AsyncMock, return_value=mock_audit_result) as mock_exec, \
         patch("src.services.schedule_service.EmailService.send_audit_notification", new_callable=AsyncMock, return_value=True) as mock_email:

        await ScheduleService.execute_scheduled_audit(sched_uuid)

        # Verificar que el motor de auditoría fue invocado con la URL original
        mock_exec.assert_called_once_with(raw_url="https://tienda-demo.cl/", db_session=mock_session)

        # Verificar que se envió el correo con la comparativa de veredictos
        mock_email.assert_called_once()
        assert mock_email.call_args[1]["to_email"] == "contacto@tienda-demo.cl"
        assert mock_email.call_args[1]["verdict"] == "APROBADO"
        assert mock_email.call_args[1]["previous_verdict"] == "RECHAZADO"

        # Verificar que la tarea quedó como COMPLETADA
        assert sched_record.estado == "COMPLETADA"
        assert sched_record.ejecutado_en is not None
        assert sched_record.nueva_auditoria_id == uuid.UUID(mock_audit_result["audit_id"])
