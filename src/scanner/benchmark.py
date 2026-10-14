"""
Script de calibración y validación empírica con muestra de sitios chilenos (Sprint 3 / Tarea 2).
Evalúa la tasa de falsos positivos frente a los 3 pilares de cumplimiento.
"""

import asyncio
from typing import List, Dict, Any
from src.scanner.inspector import WebInspector
from src.scanner.rules_engine import RulesEngine
from src.core.sanitizer import sanitize_url

SAMPLE_SITES: List[str] = [
    "https://gob.cl",
    "https://chileatiende.gob.cl",
    "https://www.bancochile.cl",
    "https://www.falabella.com",
    "https://www.paris.cl",
    "https://www.emol.com",
    "https://www.latercera.com",
    "https://www.sii.cl",
    "https://www.uchile.cl",
    "https://www.mercadolibre.cl"
]


async def run_benchmark():
    inspector = WebInspector(timeout_seconds=25.0, page_timeout_ms=15000)
    print("=" * 70)
    print("INICIANDO BENCHMARK DE CALIBRACIÓN - DATACHECK.CL (MUESTRA 10 SITIOS)")
    print("=" * 70)

    results: List[Dict[str, Any]] = []

    for site in SAMPLE_SITES:
        normalized, _ = sanitize_url(site)
        print(f"\n[SCAN] Auditando: {normalized} ...")
        try:
            raw = await inspector.scan_url(normalized)
            evaluation = RulesEngine.evaluate(raw)
            results.append({
                "url": normalized,
                "status": evaluation["page_load_status"],
                "verdict": evaluation["verdict"],
                "score": evaluation["score"],
                "privacy_pilar": evaluation["pilares"]["politica_privacidad"]["status"],
                "arco_pilar": evaluation["pilares"]["canales_arco"]["status"],
                "cookies_pilar": evaluation["pilares"]["consentimiento_cookies"]["status"],
                "findings_count": len(evaluation["findings"])
            })
            print(f" -> Veredicto: {evaluation['verdict']} | Score: {evaluation['score']}/100")
        except Exception as e:
            print(f" -> ERROR: {e}")
            results.append({"url": normalized, "verdict": "ERROR", "score": 0})

    print("\n" + "=" * 70)
    print("RESUMEN DE BENCHMARK")
    print("=" * 70)
    for r in results:
        print(f"{r['url']:<35} | {r.get('verdict','-'):<18} | {r.get('score', 0):>3} pts")

    return results


if __name__ == "__main__":
    asyncio.run(run_benchmark())
