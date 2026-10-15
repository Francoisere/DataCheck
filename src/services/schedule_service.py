"""
Servicio de Gestión de Re-auditorías Programadas (DataCheck.cl).
Cumple con RF-SCHED-03, RF-SCHED-04, RF-SCHED-05, RF-SCHED-06 y RNF-PRIV-01:
- Registro de tareas programadas vinculadas a la auditoría anterior y al sitio.
- Consulta de tareas vencidas (proxima_ejecucion_en <= now).
- Ejecución desatendida del escaneo (reutilizando AuditService como caja negra).
- Generación de informe PDF en memoria y despacho de notificación por correo (EmailService).
"""

import asyncio
import logging
import uuid
from datetime import timedelta
from typing import List, Optional

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from src.db.session import AsyncSessionLocal
from src.db.models import AuditoriaProgramada, Auditoria, SitioAnalizado, utc_now
from src.services.audit_service import AuditService
from src.services.email_service import EmailService
from src.services.pdf_report_service import PdfReportService

logger = logging.getLogger(__name__)


class ScheduleService:
    @classmethod
    async def create_schedule(
        cls,
        db: AsyncSession,
        audit_id: str,
        email: str,
        interval_mode: str = "DEMO_2_MIN"
    ) -> AuditoriaProgramada:
        """
        Registra una re-evaluación programada en estado PENDIENTE.
        - Valida formato UUID y correo electrónico.
        - Valida que la auditoría exista y tenga veredicto RECHAZADO o CON_OBSERVACIONES.
        - Calcula proxima_ejecucion_en (2 minutos para DEMO_2_MIN, 15 días para PROD_15_DAYS).
        """
        # 1. Validación de UUID
        try:
            val_uuid = uuid.UUID(audit_id)
        except (ValueError, AttributeError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El identificador de auditoría provisto no tiene un formato UUID válido."
            )

        # 2. Validación de correo (Privacy by design: solo sintaxis básica y sin logging)
        clean_email = email.strip() if email else ""
        if not clean_email or "@" not in clean_email or "." not in clean_email.split("@")[-1]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El formato del correo electrónico ingresado no es válido."
            )

        # 3. Validación de intervalo
        if interval_mode not in ("DEMO_2_MIN", "PROD_15_DAYS"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Modo de intervalo inválido: '{interval_mode}'. Use 'DEMO_2_MIN' o 'PROD_15_DAYS'."
            )

        # 4. Consulta de auditoría previa
        stmt = (
            select(Auditoria)
            .options(selectinload(Auditoria.sitio))
            .where(Auditoria.id == val_uuid)
        )
        res = await db.execute(stmt)
        auditoria = res.scalar_one_or_none()

        if not auditoria:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No se encontró ninguna auditoría con ID: {audit_id}"
            )

        # 5. Validación de veredicto
        if auditoria.verdict not in ("RECHAZADO", "CON_OBSERVACIONES"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Solo se pueden programar re-evaluaciones para sitios con veredicto RECHAZADO o CON_OBSERVACIONES."
            )

        # 6. Cálculo de fecha de ejecución
        now = utc_now()
        if interval_mode == "DEMO_2_MIN":
            next_run = now + timedelta(minutes=2)
        else:
            next_run = now + timedelta(days=15)

        schedule = AuditoriaProgramada(
            sitio_id=auditoria.sitio_id,
            ultima_auditoria_id=auditoria.id,
            email_notificacion=clean_email,
            intervalo_tipo=interval_mode,
            proxima_ejecucion_en=next_run,
            estado="PENDIENTE"
        )
        db.add(schedule)
        await db.commit()
        await db.refresh(schedule)

        # Cargar relaciones necesarias para la respuesta
        stmt_refresh = (
            select(AuditoriaProgramada)
            .options(selectinload(AuditoriaProgramada.sitio))
            .where(AuditoriaProgramada.id == schedule.id)
        )
        res_refresh = await db.execute(stmt_refresh)
        refreshed_schedule = res_refresh.scalar_one()

        logger.info(f"Re-auditoría programada creada con ID: {schedule.id} para {interval_mode}")
        return refreshed_schedule

    @classmethod
    async def get_schedule(cls, db: AsyncSession, schedule_id: str) -> Optional[AuditoriaProgramada]:
        """Obtiene una auditoría programada por su UUID."""
        try:
            val_uuid = uuid.UUID(schedule_id)
        except (ValueError, AttributeError):
            return None

        stmt = (
            select(AuditoriaProgramada)
            .options(
                selectinload(AuditoriaProgramada.sitio),
                selectinload(AuditoriaProgramada.ultima_auditoria),
                selectinload(AuditoriaProgramada.nueva_auditoria)
            )
            .where(AuditoriaProgramada.id == val_uuid)
        )
        res = await db.execute(stmt)
        return res.scalar_one_or_none()

    @classmethod
    async def get_due_schedules(cls, db: AsyncSession) -> List[AuditoriaProgramada]:
        """Consulta tareas pendientes cuya proxima_ejecucion_en sea menor o igual a ahora."""
        now = utc_now()
        stmt = (
            select(AuditoriaProgramada)
            .options(selectinload(AuditoriaProgramada.sitio))
            .where(
                AuditoriaProgramada.estado == "PENDIENTE",
                AuditoriaProgramada.proxima_ejecucion_en <= now
            )
            .order_by(AuditoriaProgramada.proxima_ejecucion_en.asc())
        )
        res = await db.execute(stmt)
        return list(res.scalars().all())

    @classmethod
    async def process_due_schedules(cls) -> None:
        """
        Paso del worker periódico:
        1. Consulta tareas vencidas.
        2. Marca su estado en PROCESANDO atómicamente para evitar colisiones.
        3. Despacha tareas asíncronas para su ejecución.
        """
        async with AsyncSessionLocal() as session:
            try:
                due_schedules = await cls.get_due_schedules(session)
                if not due_schedules:
                    return

                logger.info(f"Scheduler encontró {len(due_schedules)} auditoría(s) vencida(s) para ejecutar.")
                task_ids = []
                for sched in due_schedules:
                    sched.estado = "PROCESANDO"
                    task_ids.append(sched.id)
                await session.commit()

                for task_id in task_ids:
                    asyncio.create_task(cls.execute_scheduled_audit(task_id))
            except Exception as e:
                logger.warning(f"Error consultando tareas vencidas en el scheduler: {e}")

    @classmethod
    async def execute_scheduled_audit(cls, schedule_id: uuid.UUID) -> None:
        """
        Ejecuta el ciclo de re-auditoría para una tarea programada:
        1. Rescata la URL original.
        2. Llama a AuditService.execute_audit (Scraping pasivo Playwright + RulesEngine).
        3. Persiste la nueva auditoría en la base de datos.
        4. Genera el PDF en memoria.
        5. Envía la notificación con comparativa y PDF adjunto por correo electrónico.
        6. Marca la tarea como COMPLETADA (o maneja reintentos en caso de fallo).
        """
        async with AsyncSessionLocal() as session:
            try:
                stmt = (
                    select(AuditoriaProgramada)
                    .options(
                        selectinload(AuditoriaProgramada.sitio),
                        selectinload(AuditoriaProgramada.ultima_auditoria)
                    )
                    .where(AuditoriaProgramada.id == schedule_id)
                )
                res = await session.execute(stmt)
                schedule = res.scalar_one_or_none()

                if not schedule:
                    logger.error(f"Auditoría programada no encontrada: {schedule_id}")
                    return

                target_url = schedule.sitio.url_normalizada if schedule.sitio else None
                if not target_url:
                    logger.error(f"No se encontró URL asociada a la auditoría programada: {schedule_id}")
                    schedule.estado = "FALLIDA"
                    await session.commit()
                    return

                logger.info(f"Iniciando re-auditoría automática para {target_url} (Tarea {schedule_id})...")

                # Ejecutar auditoría pasiva reutilizando el servicio como caja negra
                audit_service = AuditService()
                new_audit_result = await audit_service.execute_audit(
                    raw_url=target_url,
                    db_session=session
                )

                new_audit_id_str = new_audit_result.get("audit_id")
                new_audit_id = uuid.UUID(new_audit_id_str) if new_audit_id_str else None

                # Generar PDF en memoria
                pdf_bytes = None
                try:
                    pdf_buf = PdfReportService.generate_pdf_report(new_audit_result)
                    pdf_bytes = pdf_buf.getvalue()
                except Exception as pe:
                    logger.warning(f"No se pudo generar PDF para re-auditoría {schedule_id}: {pe}")

                # Datos comparativos
                previous_verdict = schedule.ultima_auditoria.verdict if schedule.ultima_auditoria else "RECHAZADO"
                previous_score = schedule.ultima_auditoria.score if schedule.ultima_auditoria else 0
                download_url = f"/api/v1/audits/{new_audit_id_str}/pdf" if new_audit_id_str else None

                # Despachar correo electrónico
                await EmailService.send_audit_notification(
                    to_email=schedule.email_notificacion,
                    target_url=target_url,
                    verdict=new_audit_result.get("verdict", "RECHAZADO"),
                    score=new_audit_result.get("score", 0),
                    previous_verdict=previous_verdict,
                    previous_score=previous_score,
                    verdict_summary=new_audit_result.get("verdict_summary", ""),
                    findings_count=len(new_audit_result.get("findings", [])),
                    pdf_bytes=pdf_bytes,
                    download_url=download_url
                )

                # Actualizar estado de la tarea programada
                schedule.estado = "COMPLETADA"
                schedule.ejecutado_en = utc_now()
                schedule.nueva_auditoria_id = new_audit_id
                await session.commit()
                logger.info(f"Re-auditoría programada {schedule_id} completada exitosamente.")

            except Exception as e:
                logger.exception(f"Fallo durante la ejecución de la re-auditoría {schedule_id}: {e}")
                try:
                    stmt_err = select(AuditoriaProgramada).where(AuditoriaProgramada.id == schedule_id)
                    res_err = await session.execute(stmt_err)
                    sched_err = res_err.scalar_one_or_none()
                    if sched_err:
                        sched_err.reintentos += 1
                        if sched_err.reintentos >= 3:
                            sched_err.estado = "FALLIDA"
                        else:
                            sched_err.estado = "PENDIENTE"
                        await session.commit()
                except Exception as db_err:
                    logger.error(f"Error al registrar fallo de tarea programada {schedule_id}: {db_err}")
