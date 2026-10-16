"""
Configuración del Scheduler Asíncrono de Fondo (DataCheck.cl).
Cumple con RF-SCHED-04:
- Ejecuta dentro del event loop de asyncio de FastAPI con APScheduler.
- Consulta tareas vencidas cada SCHEDULER_CHECK_INTERVAL_SECONDS (por defecto 30s).
- Gestión limpia de ciclo de vida con inicio y apagado gracefully.
"""

import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from src.core.config import settings

logger = logging.getLogger(__name__)

# Instancia global del scheduler asíncrono
scheduler = AsyncIOScheduler()


async def check_pending_schedules_job():
    """Job periódico invocado por APScheduler para procesar auditorías vencidas."""
    try:
        from src.services.schedule_service import ScheduleService
        await ScheduleService.process_due_schedules()
    except Exception as e:
        logger.warning(f"Excepción en job periódico de re-auditorías programadas: {e}")


def start_scheduler():
    """Inicia el scheduler en el ciclo de vida de la aplicación."""
    try:
        if not scheduler.running:
            interval = settings.SCHEDULER_CHECK_INTERVAL_SECONDS
            scheduler.add_job(
                check_pending_schedules_job,
                trigger="interval",
                seconds=interval,
                id="check_pending_schedules",
                replace_existing=True
            )
            scheduler.start()
            logger.info(f"Scheduler de re-auditorías iniciado (revisión cada {interval} segundos).")
    except Exception as e:
        logger.warning(f"No se pudo iniciar el scheduler asíncrono: {e}")


def shutdown_scheduler():
    """Detiene el scheduler de forma limpia al apagar FastAPI."""
    try:
        if scheduler.running:
            scheduler.shutdown(wait=False)
            logger.info("Scheduler de re-auditorías detenido limpiamente.")
    except Exception as e:
        logger.warning(f"Excepción al detener scheduler: {e}")
