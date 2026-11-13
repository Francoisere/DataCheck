"""
Repositorio Asíncrono de Auditorías e Historial Evolutivo (RF-HIST-01, RF-HIST-02, RNF-PERF-01).
Implementa carga ansiosa (selectinload) para evitar problemas de consultas N+1 y filtra
estrictamente auditorías válidas (page_load_status == 1) para comparaciones históricas.
"""

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.db.models import Auditoria, SitioAnalizado


class AuditRepository:
    @staticmethod
    async def get_audit_with_details(
        db: AsyncSession,
        audit_id: uuid.UUID
    ) -> Optional[Auditoria]:
        """
        Obtiene una auditoría por su UUID cargando ansiosamente su sitio,
        resultados de pilares y evidencias de rastreadores en una sola operación lógica.
        """
        stmt = (
            select(Auditoria)
            .options(
                selectinload(Auditoria.sitio),
                selectinload(Auditoria.resultados_pilares),
                selectinload(Auditoria.evidencias_rastreadores),
            )
            .where(Auditoria.id == audit_id)
        )
        res = await db.execute(stmt)
        return res.scalar_one_or_none()

    @staticmethod
    async def get_previous_valid_audit(
        db: AsyncSession,
        sitio_id: uuid.UUID,
        current_executed_at: datetime,
        current_audit_id: Optional[uuid.UUID] = None
    ) -> Optional[Auditoria]:
        """
        Busca la auditoría válida (page_load_status == 1) inmediatamente anterior
        para el mismo sitio_id, ignorando auditorías fallidas por bloqueo WAF o timeout.
        """
        conditions = [
            Auditoria.sitio_id == sitio_id,
            Auditoria.page_load_status == 1,
            Auditoria.score.is_not(None),
        ]
        if current_audit_id is not None:
            conditions.append(Auditoria.id != current_audit_id)
            conditions.append(Auditoria.ejecutada_en <= current_executed_at)
        else:
            conditions.append(Auditoria.ejecutada_en < current_executed_at)

        stmt = (
            select(Auditoria)
            .options(
                selectinload(Auditoria.sitio),
                selectinload(Auditoria.resultados_pilares),
                selectinload(Auditoria.evidencias_rastreadores),
            )
            .where(*conditions)
            .order_by(Auditoria.ejecutada_en.desc())
            .limit(1)
        )
        res = await db.execute(stmt)
        return res.scalar_one_or_none()

    @staticmethod
    async def get_audits_by_domain(
        db: AsyncSession,
        domain: str
    ) -> List[Auditoria]:
        """
        Retorna todas las auditorías ejecutadas sobre un dominio ordenadas
        descendentemente por fecha (más reciente primero), con relaciones pre-cargadas.
        """
        clean_domain = domain.strip().lower()
        stmt = (
            select(Auditoria)
            .join(SitioAnalizado, Auditoria.sitio_id == SitioAnalizado.id)
            .options(
                selectinload(Auditoria.sitio),
                selectinload(Auditoria.resultados_pilares),
                selectinload(Auditoria.evidencias_rastreadores),
            )
            .where(
                SitioAnalizado.dominio == clean_domain,
                Auditoria.score.is_not(None),
            )
            .order_by(Auditoria.ejecutada_en.desc())
        )
        res = await db.execute(stmt)
        return list(res.scalars().all())
