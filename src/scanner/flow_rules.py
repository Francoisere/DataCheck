"""
Motor de Reglas para Auditoría de Flujo Multietapa.
Evalúa el mapa de navegación producido por FlowInspector y genera
hallazgos y tickets de remediación por etapa.

Estados posibles por etapa:
- CUMPLE: Sin trackers nuevos detectados en la etapa.
- NO_CUMPLE: Trackers nuevos aparecieron en esta etapa sin consentimiento previo.
- NO_VERIFICABLE: Etapa que requiere interacción activa (ej: agregar al carrito).
- NO_ALCANZADA: Etapa que lleva a pasarela de pago externa.
"""

from typing import Dict, Any, List

FLOW_LEGAL_DISCLAIMER = (
    "Esta auditoría de flujo opera en modo pasivo (Nivel 0) y tiene limitaciones inherentes. "
    "No se ejecutaron acciones interactivas como agregar productos o rellenar formularios. "
    "Los resultados 'no verificable' no deben interpretarse como cumplimiento."
)


class FlowRulesEngine:
    @staticmethod
    def evaluate(flow_raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evalúa el resultado del recorrido de flujo y genera hallazgos por etapa.
        """
        target_url = flow_raw_data.get("target_url", "")
        flow_detected = flow_raw_data.get("flow_detected", False)
        stages = flow_raw_data.get("stages", [])
        limitations = flow_raw_data.get("limitations", [])

        if not flow_detected:
            return {
                "target_url": target_url,
                "flow_detected": False,
                "flow_not_detected_reason": flow_raw_data.get(
                    "flow_not_detected_reason",
                    "Flujo no detectado en este sitio."
                ),
                "flow_verdict": "NO_APLICABLE",
                "flow_verdict_summary": (
                    "No se detectó un flujo de compra o registro en el sitio. "
                    "Se recomienda utilizar el escaneo estándar."
                ),
                "stages_evaluated": [],
                "flow_findings": [],
                "limitations": limitations,
                "legal_disclaimer": FLOW_LEGAL_DISCLAIMER,
            }

        flow_findings: List[Dict[str, Any]] = []
        stages_evaluated = []
        any_non_compliant = False
        all_not_verifiable = True

        for stage in stages:
            stage_name = stage.get("stage_name", "")
            stage_label = stage.get("stage_label", "")
            stage_url = stage.get("url", "")
            verdict = stage.get("verdict", "NO_VERIFICABLE")
            new_domains = stage.get("new_tracker_domains", [])
            new_cookies = stage.get("new_tracker_cookies", [])
            status = stage.get("status", "error")

            stage_eval = {
                "stage_name": stage_name,
                "stage_label": stage_label,
                "url": stage_url,
                "verdict": verdict,
                "new_tracker_domains": new_domains,
                "new_tracker_cookies": new_cookies,
            }
            stages_evaluated.append(stage_eval)

            if verdict == "NO_CUMPLE":
                any_non_compliant = True
                all_not_verifiable = False

                if new_domains:
                    dom_str = ", ".join(new_domains)
                    flow_findings.append({
                        "stage": stage_name,
                        "stage_label": stage_label,
                        "status": "FAIL",
                        "title": f"Nuevos dominios de rastreo en etapa '{stage_label}'",
                        "detail": (
                            f"Al navegar a '{stage_label}' ({stage_url}), se detectó tráfico "
                            f"hacia {len(new_domains)} dominio(s) de rastreo: {dom_str} sin consentimiento previo."
                        )[:300],
                        "technical_raw": dom_str[:500],
                        "items": list(new_domains),
                        "remediation_ticket": (
                            f"Condicionar la carga de scripts asociados ({dom_str}) en la etapa "
                            f"'{stage_label}' al evento de consentimiento explícito del usuario."
                        ),
                    })

                if new_cookies:
                    ck_str = ", ".join(new_cookies)
                    flow_findings.append({
                        "stage": stage_name,
                        "stage_label": stage_label,
                        "status": "FAIL",
                        "title": f"Nuevas cookies de rastreo en etapa '{stage_label}'",
                        "detail": (
                            f"Al navegar a '{stage_label}' ({stage_url}), se depositaron "
                            f"{len(new_cookies)} cookie(s) de rastreo: {ck_str} que no existían previamente."
                        )[:300],
                        "technical_raw": ck_str[:500],
                        "items": list(new_cookies),
                        "remediation_ticket": (
                            f"Configurar las cookies ({ck_str}) para que solo se emitan tras "
                            f"la confirmación de consentimiento en la etapa '{stage_label}'."
                        ),
                    })

            elif verdict == "CUMPLE":
                all_not_verifiable = False
                flow_findings.append({
                    "stage": stage_name,
                    "stage_label": stage_label,
                    "status": "OK",
                    "title": f"Navegación limpia en etapa '{stage_label}'",
                    "detail": (
                        f"No se detectaron trackers nuevos al navegar a '{stage_label}'. "
                        f"Los scripts y cookies existentes no variaron."
                    )[:300],
                    "technical_raw": "0 trackers nuevos",
                    "remediation_ticket": "Mantener el bloqueo preventivo de scripts no esenciales.",
                })

            elif verdict == "NO_ALCANZADA":
                flow_findings.append({
                    "stage": stage_name,
                    "stage_label": stage_label,
                    "status": "WARNING",
                    "title": f"Etapa '{stage_label}' no alcanzada: pasarela externa",
                    "detail": (
                        f"El enlace de la etapa '{stage_label}' apunta a una pasarela "
                        f"de pago externa. El recorrido se detuvo aquí."
                    )[:300],
                    "technical_raw": stage_url,
                    "remediation_ticket": (
                        "Esta etapa no puede auditarse en modo pasivo. "
                        "Verificar manualmente los trackers en el flujo de pago."
                    ),
                })

            elif verdict == "NO_VERIFICABLE":
                verification_note = stage.get("verification_note", "")
                flow_findings.append({
                    "stage": stage_name,
                    "stage_label": stage_label,
                    "status": "WARNING",
                    "title": f"Etapa '{stage_label}' no verificable completamente",
                    "detail": (
                        f"La etapa '{stage_label}' requiere interacción activa para "
                        f"una verificación completa. {verification_note}"
                    )[:300],
                    "technical_raw": "Nivel 0: inspección pasiva",
                    "remediation_ticket": (
                        "Esta etapa no puede verificarse completamente en modo pasivo. "
                        "Los trackers que se activan con acciones del usuario no son visibles."
                    ),
                })

        # Veredicto global del flujo
        if any_non_compliant:
            flow_verdict = "NO_CUMPLE"
            flow_verdict_summary = (
                "Se detectaron transferencias no consentidas en al menos una etapa del flujo. "
                "Nuevos dominios de rastreo o cookies aparecieron sin mecanismo de consentimiento."
            )
        elif all_not_verifiable:
            flow_verdict = "NO_VERIFICABLE"
            flow_verdict_summary = (
                "Ninguna etapa del flujo pudo verificarse completamente en modo pasivo. "
                "Se requiere inspección manual o interactiva."
            )
        else:
            flow_verdict = "CUMPLE"
            flow_verdict_summary = (
                "No se detectaron transferencias no consentidas en las etapas verificables del flujo. "
                "No aparecieron nuevos trackers en las transiciones entre etapas."
            )

        return {
            "target_url": target_url,
            "flow_detected": True,
            "flow_verdict": flow_verdict,
            "flow_verdict_summary": flow_verdict_summary,
            "total_stages_evaluated": len(stages_evaluated),
            "stages_evaluated": stages_evaluated,
            "flow_findings": flow_findings,
            "limitations": limitations,
            "legal_disclaimer": FLOW_LEGAL_DISCLAIMER,
        }
