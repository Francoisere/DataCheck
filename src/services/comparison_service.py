"""
Servicio de Comparación Evolutiva y Detección de Regresiones ("Antes vs. Después").
Cumple con RF-HIST-01, RF-HIST-02 y RF-HIST-03:
- Lógica pura desacoplada de la base de datos para cálculo de deltas de puntaje global y por pilar.
- Operaciones de conjuntos sobre evidencias de rastreadores (REMEDIATED, PERSISTENT, REGRESSION).
- Clasificación determinista de transiciones de veredicto (IMPROVED, REGRESSED, UNCHANGED).
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


VERDICT_RANK: Dict[str, int] = {
    "NO_ACCESIBLE": -1,
    "NO_VERIFICABLE": -1,
    "NO_APLICABLE": -1,
    "RECHAZADO": 0,
    "NO_CUMPLE": 0,
    "CON_OBSERVACIONES": 1,
    "APROBADO": 2,
    "CUMPLE": 2,
}

CANONICAL_PILLARS: List[str] = [
    "POLITICA_PRIVACIDAD",
    "CANALES_ARCO",
    "CONSENTIMIENTO_COOKIES",
]


def _get_val(obj: Any, key: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _extract_trackers(audit: Any) -> Dict[Tuple[str, str], str]:
    """
    Extrae un diccionario {(tipo, valor): categoria} desde una instancia de Auditoria o dict.
    """
    raw_items = (
        _get_val(audit, "evidencias_rastreadores")
        or _get_val(audit, "evidencias")
        or _get_val(audit, "trackers")
        or []
    )
    tracker_map: Dict[Tuple[str, str], str] = {}
    for item in raw_items:
        tipo = str(_get_val(item, "tipo", "COOKIE")).upper()
        valor = str(_get_val(item, "valor", "")).strip()
        categoria = str(_get_val(item, "categoria", "TRACKER")).strip() or "TRACKER"
        if valor:
            tracker_map[(tipo, valor)] = categoria
    return tracker_map


def _extract_pillars(audit: Any) -> Dict[str, Dict[str, Any]]:
    """
    Extrae un mapa {pilar_key: {"estado": str, "puntaje": int}} desde una instancia de Auditoria o dict.
    """
    raw_pillars = _get_val(audit, "resultados_pilares") or _get_val(audit, "pilares") or []
    pillar_map: Dict[str, Dict[str, Any]] = {}

    if isinstance(raw_pillars, dict):
        key_mapping = {
            "politica_privacidad": "POLITICA_PRIVACIDAD",
            "canales_arco": "CANALES_ARCO",
            "consentimiento_cookies": "CONSENTIMIENTO_COOKIES",
        }
        for k, val in raw_pillars.items():
            norm_key = key_mapping.get(k, str(k).upper())
            pillar_map[norm_key] = {
                "estado": str(_get_val(val, "status") or _get_val(val, "estado", "FALLA")),
                "puntaje": int(_get_val(val, "score") if _get_val(val, "score") is not None else (_get_val(val, "puntaje", 0) or 0)),
            }
    else:
        for item in raw_pillars:
            pilar_name = str(_get_val(item, "pilar", "")).upper()
            if pilar_name:
                pillar_map[pilar_name] = {
                    "estado": str(_get_val(item, "estado") or _get_val(item, "status", "FALLA")),
                    "puntaje": int(_get_val(item, "puntaje") if _get_val(item, "puntaje") is not None else (_get_val(item, "score", 0) or 0)),
                }

    return pillar_map


class ComparisonService:
    @staticmethod
    def compare_audits(
        current_audit: Any,
        previous_audit: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Compara la auditoría actual (T_n) contra la auditoría válida inmediatamente anterior (T_{n-1}).
        Si previous_audit es None (primer escaneo), retorna has_previous=False sin lanzar excepción.
        """
        current_id = str(_get_val(current_audit, "id") or _get_val(current_audit, "audit_id", ""))

        if previous_audit is None:
            return {
                "current_audit_id": current_id,
                "previous_audit_id": None,
                "has_previous": False,
                "time_elapsed_hours": None,
                "verdict_transition": None,
                "score_comparison": None,
                "pilares_delta": [],
                "trackers_diff": {
                    "remediated": [],
                    "persistent": [],
                    "regressions": [],
                },
            }

        previous_id = str(_get_val(previous_audit, "id") or _get_val(previous_audit, "audit_id", ""))

        # 1. Tiempo transcurrido en horas
        curr_dt = _ensure_utc(_get_val(current_audit, "ejecutada_en") or _get_val(current_audit, "executed_at"))
        prev_dt = _ensure_utc(_get_val(previous_audit, "ejecutada_en") or _get_val(previous_audit, "executed_at"))
        time_elapsed_hours: Optional[float] = None
        if curr_dt and prev_dt:
            diff_seconds = max(0.0, (curr_dt - prev_dt).total_seconds())
            time_elapsed_hours = round(diff_seconds / 3600.0, 2)

        # 2. Comparación de puntaje global
        prev_score = int(_get_val(previous_audit, "score", 0) or 0)
        curr_score = int(_get_val(current_audit, "score", 0) or 0)
        score_delta = curr_score - prev_score

        score_comparison = {
            "previous_score": prev_score,
            "current_score": curr_score,
            "delta": score_delta,
        }

        # 3. Operaciones de conjuntos sobre evidencias de rastreadores
        prev_trackers_map = _extract_trackers(previous_audit)
        curr_trackers_map = _extract_trackers(current_audit)

        prev_keys = set(prev_trackers_map.keys())
        curr_keys = set(curr_trackers_map.keys())

        remediated_keys = sorted(prev_keys - curr_keys)
        persistent_keys = sorted(prev_keys & curr_keys)
        regressions_keys = sorted(curr_keys - prev_keys)

        remediated_list = [
            {"tipo": k[0], "valor": k[1], "categoria": prev_trackers_map[k]}
            for k in remediated_keys
        ]
        persistent_list = [
            {"tipo": k[0], "valor": k[1], "categoria": curr_trackers_map[k]}
            for k in persistent_keys
        ]
        regressions_list = [
            {"tipo": k[0], "valor": k[1], "categoria": curr_trackers_map[k]}
            for k in regressions_keys
        ]

        trackers_diff = {
            "remediated": remediated_list,
            "persistent": persistent_list,
            "regressions": regressions_list,
        }

        # 4. Evolución por cada pilar normativo
        prev_pillars = _extract_pillars(previous_audit)
        curr_pillars = _extract_pillars(current_audit)

        all_pillar_keys: List[str] = []
        for p in CANONICAL_PILLARS:
            if p in prev_pillars or p in curr_pillars:
                all_pillar_keys.append(p)
        for p in sorted(set(prev_pillars.keys()) | set(curr_pillars.keys())):
            if p not in all_pillar_keys:
                all_pillar_keys.append(p)

        pilares_delta: List[Dict[str, Any]] = []
        for p_key in all_pillar_keys:
            p_prev = prev_pillars.get(p_key, {"estado": "NO_EVALUADO", "puntaje": 0})
            p_curr = curr_pillars.get(p_key, {"estado": "NO_EVALUADO", "puntaje": 0})
            p_prev_score = int(p_prev["puntaje"])
            p_curr_score = int(p_curr["puntaje"])
            pilares_delta.append({
                "pilar": p_key,
                "previous_status": p_prev["estado"],
                "current_status": p_curr["estado"],
                "previous_score": p_prev_score,
                "current_score": p_curr_score,
                "delta": p_curr_score - p_prev_score,
            })

        # 5. Transición de veredicto
        prev_verdict = str(_get_val(previous_audit, "verdict", "RECHAZADO")).upper()
        curr_verdict = str(_get_val(current_audit, "verdict", "RECHAZADO")).upper()
        prev_rank = VERDICT_RANK.get(prev_verdict, 0)
        curr_rank = VERDICT_RANK.get(curr_verdict, 0)

        if len(regressions_list) > 0 or score_delta < 0 or curr_rank < prev_rank:
            transition_status = "REGRESSED"
        elif curr_rank > prev_rank or score_delta > 0 or len(remediated_list) > 0:
            transition_status = "IMPROVED"
        else:
            transition_status = "UNCHANGED"

        verdict_transition = {
            "from": prev_verdict,
            "to": curr_verdict,
            "status": transition_status,
        }

        return {
            "current_audit_id": current_id,
            "previous_audit_id": previous_id,
            "has_previous": True,
            "time_elapsed_hours": time_elapsed_hours,
            "verdict_transition": verdict_transition,
            "score_comparison": score_comparison,
            "pilares_delta": pilares_delta,
            "trackers_diff": trackers_diff,
        }

    @staticmethod
    def build_domain_history(
        domain: str,
        audits_desc: List[Any],
        limit: int = 10
    ) -> Dict[str, Any]:
        """
        Construye el resumen histórico evolutivo para un dominio a partir de sus auditorías
        ordenadas descendentemente por fecha (más reciente primero).
        Respeta la regla de integridad: ignora auditorías con page_load_status == 0
        como base de cálculo de deltas.
        """
        total_audits = len(audits_desc)
        if total_audits == 0:
            return {
                "domain": domain,
                "total_audits": 0,
                "latest_verdict": "SIN_DATOS",
                "overall_score_delta": 0,
                "timeline": [],
            }

        # Recorrer cronológicamente (de más antigua a más reciente) para calcular deltas válidos
        audits_asc = list(reversed(audits_desc))
        deltas_by_id: Dict[str, Optional[int]] = {}
        last_valid_score: Optional[int] = None
        first_valid_score: Optional[int] = None
        latest_valid_score: Optional[int] = None

        for audit in audits_asc:
            aid = str(_get_val(audit, "id") or _get_val(audit, "audit_id", ""))
            status_load = int(_get_val(audit, "page_load_status", 1) or 0)
            score_val = int(_get_val(audit, "score", 0) or 0)

            if status_load == 1:
                if last_valid_score is None:
                    deltas_by_id[aid] = None
                    first_valid_score = score_val
                else:
                    deltas_by_id[aid] = score_val - last_valid_score
                last_valid_score = score_val
                latest_valid_score = score_val
            else:
                deltas_by_id[aid] = None

        overall_score_delta = 0
        if first_valid_score is not None and latest_valid_score is not None:
            overall_score_delta = latest_valid_score - first_valid_score

        latest_verdict = str(_get_val(audits_desc[0], "verdict", "RECHAZADO"))

        timeline: List[Dict[str, Any]] = []
        for audit in audits_desc[: max(1, limit)]:
            aid = str(_get_val(audit, "id") or _get_val(audit, "audit_id", ""))
            exec_dt = _ensure_utc(_get_val(audit, "ejecutada_en") or _get_val(audit, "executed_at"))
            exec_iso = exec_dt.strftime("%Y-%m-%dT%H:%M:%SZ") if exec_dt else ""
            trackers_map = _extract_trackers(audit)
            timeline.append({
                "audit_id": aid,
                "executed_at": exec_iso,
                "verdict": str(_get_val(audit, "verdict", "RECHAZADO")),
                "score": int(_get_val(audit, "score", 0) or 0),
                "score_delta_from_previous": deltas_by_id.get(aid),
                "trackers_count": len(trackers_map),
            })

        return {
            "domain": domain,
            "total_audits": total_audits,
            "latest_verdict": latest_verdict,
            "overall_score_delta": overall_score_delta,
            "timeline": timeline,
        }
