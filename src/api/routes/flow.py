"""
Endpoint de auditoría de flujo multietapa (C-05).
POST /api/v1/flow-audit: Inicia una auditoría de flujo (async, devuelve job_id).
GET /api/v1/flow-audit/{job_id}: Consulta el estado/resultado.
"""

import uuid
import asyncio
import logging
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks
from sqlalchemy import select

from src.api.schemas import FlowScanRequest, FlowAuditResponse
from src.scanner.flow_inspector import FlowInspector
from src.scanner.flow_rules import FlowRulesEngine
from src.core.sanitizer import sanitize_url
from src.db.session import AsyncSessionLocal
from src.db.models import SitioAnalizado, Auditoria, EtapaFlujo, EvidenciaEtapa

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Auditoría de Flujo"])

# In-memory job store (para persistencia de estado de jobs asíncronos)
_flow_jobs: Dict[str, Dict[str, Any]] = {}

flow_inspector = FlowInspector()


async def _persist_flow_to_db(url: str, evaluated: Dict[str, Any], raw_result: Dict[str, Any]) -> Optional[str]:
    """Persiste los resultados de la auditoría de flujo en PostgreSQL (Paso 5)."""
    try:
        async with AsyncSessionLocal() as session:
            normalized_url, domain = sanitize_url(url)
            stmt = select(SitioAnalizado).where(SitioAnalizado.url_normalizada == normalized_url)
            res = await session.execute(stmt)
            sitio = res.scalar_one_or_none()

            if not sitio:
                sitio = SitioAnalizado(url_normalizada=normalized_url, dominio=domain)
                session.add(sitio)
                await session.flush()

            verdict = evaluated.get("flow_verdict", "NO_APLICABLE")
            score = 100 if verdict == "CUMPLE" else (50 if verdict == "NO_VERIFICABLE" else 0)

            auditoria = Auditoria(
                sitio_id=sitio.id,
                page_load_status=1,
                verdict=verdict,
                score=score,
                duracion_ms=0,
                resumen=evaluated.get("flow_verdict_summary", "")[:500],
            )
            session.add(auditoria)
            await session.flush()

            stages = raw_result.get("stages", [])
            for idx, stage in enumerate(stages):
                etapa = EtapaFlujo(
                    auditoria_id=auditoria.id,
                    nombre_etapa=stage.get("stage_name", "")[:50],
                    etiqueta=stage.get("stage_label", "")[:100],
                    url=stage.get("url", "")[:500],
                    orden=idx,
                    veredicto=stage.get("verdict", "NO_VERIFICABLE")[:30],
                    http_status=stage.get("http_status", 0),
                    requests_count=stage.get("requests_count", 0),
                )
                session.add(etapa)
                await session.flush()

                # Guardar solo nombres de dominios y cookies, nunca valores (DA-04 Privacy by Design)
                for dom in stage.get("new_tracker_domains", []):
                    session.add(EvidenciaEtapa(
                        etapa_id=etapa.id,
                        tipo="DOMINIO_NUEVO",
                        valor=dom[:255],
                        es_nuevo_en_etapa=True,
                    ))

                for ck in stage.get("new_tracker_cookies", []):
                    session.add(EvidenciaEtapa(
                        etapa_id=etapa.id,
                        tipo="COOKIE_NUEVA",
                        valor=ck[:255],
                        es_nuevo_en_etapa=True,
                    ))

            await session.commit()
            return str(auditoria.id)
    except Exception as e:
        logger.warning(f"No se pudo persistir el flujo en PostgreSQL (degradación elegante): {e}")
        return None


async def _run_flow_audit(job_id: str, url: str) -> None:
    """Ejecuta la auditoría de flujo en background y almacena el resultado."""
    try:
        _flow_jobs[job_id]["status"] = "running"
        raw_result = await flow_inspector.audit_flow(url)
        evaluated = FlowRulesEngine.evaluate(raw_result)
        
        # Persistencia en BD
        audit_id = await _persist_flow_to_db(url, evaluated, raw_result)
        if audit_id:
            evaluated["audit_id"] = audit_id

        _flow_jobs[job_id]["status"] = "completed"
        _flow_jobs[job_id]["result"] = evaluated
    except Exception as e:
        _flow_jobs[job_id]["status"] = "error"
        _flow_jobs[job_id]["error"] = str(e)[:300]


@router.post(
    "/flow-audit",
    summary="Iniciar auditoría de flujo de compra/registro",
    response_model=Dict[str, str],
)
async def start_flow_audit(
    request: FlowScanRequest,
    background_tasks: BackgroundTasks,
):
    """
    Inicia una auditoría de flujo multietapa en background.
    Retorna un job_id para consultar el estado con GET /flow-audit/{job_id}.
    El flujo puede tardar 60-75 segundos.
    """
    raw_url = request.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="La URL no puede estar vacía.")

    try:
        url, _ = sanitize_url(raw_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Limpieza de jobs en memoria para evitar crecimiento indefinido
    if len(_flow_jobs) > 100:
        for old_k in list(_flow_jobs.keys())[:20]:
            _flow_jobs.pop(old_k, None)

    job_id = str(uuid.uuid4())
    _flow_jobs[job_id] = {
        "status": "queued",
        "url": url,
        "result": None,
        "error": None,
    }

    background_tasks.add_task(_run_flow_audit, job_id, url)

    return {
        "job_id": job_id,
        "status": "queued",
        "message": f"Auditoría de flujo iniciada. Consulte GET /api/v1/flow-audit/{job_id}",
    }


@router.get(
    "/flow-audit/{job_id}",
    summary="Consultar estado de auditoría de flujo",
)
async def get_flow_audit_status(job_id: str):
    """
    Consulta el estado de una auditoría de flujo en curso.
    - status=queued: En cola.
    - status=running: En ejecución.
    - status=completed: Resultado disponible en 'result'.
    - status=error: Error durante la ejecución.
    """
    if job_id not in _flow_jobs:
        raise HTTPException(status_code=404, detail="Job no encontrado.")

    job = _flow_jobs[job_id]

    if job["status"] == "completed":
        return {
            "job_id": job_id,
            "status": "completed",
            "result": job["result"],
        }
    elif job["status"] == "error":
        return {
            "job_id": job_id,
            "status": "error",
            "error": job["error"],
        }
    else:
        return {
            "job_id": job_id,
            "status": job["status"],
            "message": "Auditoría de flujo en progreso...",
        }
