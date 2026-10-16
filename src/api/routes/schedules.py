"""
Rutas de Re-auditorías Programadas (DataCheck.cl).
Cumple con RF-SCHED-03:
- POST /api/v1/schedules: Registrar una nueva auditoría programada.
- GET /api/v1/schedules/{id}: Consultar el estado de una auditoría programada.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.session import get_db_session
from src.api.schemas import ScheduleCreateRequest, ScheduleResponse
from src.services.schedule_service import ScheduleService

router = APIRouter(prefix="/api/v1/schedules", tags=["Re-auditorías Programadas"])


@router.post(
    "",
    response_model=ScheduleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registrar re-evaluación automática programada"
)
async def create_schedule(
    request: ScheduleCreateRequest,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Registra una nueva re-auditoría para un sitio web que obtuvo veredicto RECHAZADO o CON_OBSERVACIONES.
    - Demostración: 2 minutos (DEMO_2_MIN).
    - Producción: 15 días (PROD_15_DAYS).
    """
    schedule = await ScheduleService.create_schedule(
        db=db,
        audit_id=request.audit_id,
        email=request.email,
        interval_mode=request.interval_mode
    )

    target_url = schedule.sitio.url_normalizada if schedule.sitio else ""

    return ScheduleResponse(
        schedule_id=str(schedule.id),
        target_url=target_url,
        email=schedule.email_notificacion,
        scheduled_at=schedule.proxima_ejecucion_en.isoformat(),
        status=schedule.estado,
        message="Re-auditoría programada con éxito. El reporte será enviado a su correo una vez concluido el escaneo."
    )


@router.get(
    "/{schedule_id}",
    response_model=ScheduleResponse,
    summary="Consultar estado de una re-evaluación programada"
)
async def get_schedule(
    schedule_id: str,
    db: AsyncSession = Depends(get_db_session)
):
    """
    Retorna el estado de ejecución y datos de la re-auditoría programada.
    """
    schedule = await ScheduleService.get_schedule(db=db, schedule_id=schedule_id)
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No se encontró ninguna tarea programada con ID: {schedule_id}"
        )

    target_url = schedule.sitio.url_normalizada if schedule.sitio else ""

    return ScheduleResponse(
        schedule_id=str(schedule.id),
        target_url=target_url,
        email=schedule.email_notificacion,
        scheduled_at=schedule.proxima_ejecucion_en.isoformat(),
        status=schedule.estado,
        message=f"Tarea programada en estado: {schedule.estado}",
        executed_at=schedule.ejecutado_en.isoformat() if schedule.ejecutado_en else None,
        nueva_auditoria_id=str(schedule.nueva_auditoria_id) if schedule.nueva_auditoria_id else None
    )
