"""
Motor de Reglas de Cumplimiento Legal (Ley N° 19.628 y Nueva Ley de Protección de Datos Personales Chile).
Incremento 2:
- Ponderación de 100 pts: Política de Privacidad (35 pts), Canales ARCO (30 pts), Consentimiento & Cookies (35 pts).
- Dictamen determinista: APROBADO (score >= 80 y 0 trackers), CON_OBSERVACIONES (score >= 55 o banner sin opción de rechazo), RECHAZADO (< 55 o trackers no autorizados con score bajo).
- Generación sistemática de tickets técnicos de remediación (remediation_ticket) para desarrolladores (PBI-03 / RC-03).
"""

from typing import Dict, Any, List

LEGAL_DISCLAIMER = (
    "DataCheck.cl es una herramienta de auditoría técnica académica de apoyo. "
    "Este reporte no constituye asesoría jurídica formal ni certificación vinculante "
    "de la Agencia de Protección de Datos Personales."
)


class RulesEngine:
    @staticmethod
    def evaluate(scan_raw_data: Dict[str, Any]) -> Dict[str, Any]:
        target_url = scan_raw_data.get("target_url", "")
        raw_page_status = scan_raw_data.get("page_load_status", 0)
        page_load_status = 1 if (isinstance(raw_page_status, int) and 200 <= raw_page_status < 400) else 0

        tracker_audit = scan_raw_data.get("tracker_audit", {})
        privacy_audit = scan_raw_data.get("privacy_policy_audit", {})
        arco_audit = scan_raw_data.get("arco_channels_audit", {})
        consent_banner_audit = scan_raw_data.get("consent_banner_audit")
        frames_audit = scan_raw_data.get("frames_audit")

        score = 0
        findings: List[Dict[str, Any]] = []

        # =========================================================================
        # 1. PILAR: POLÍTICA DE PRIVACIDAD (Máx 35 pts)
        # =========================================================================
        pilar_privacy_score = 0
        privacy_status = "FALLA"

        if privacy_audit.get("found") and privacy_audit.get("http_status") == 200:
            pilar_privacy_score += 20
            findings.append({
                "pilar": "POLITICA_PRIVACIDAD",
                "status": "OK",
                "title": "Política de Privacidad Accesible",
                "detail": f"Enlace a la política detectado en {privacy_audit.get('url')} respondiendo con código HTTP 200.",
                "technical_raw": f"HTTP {privacy_audit.get('http_status')} - {privacy_audit.get('url')}",
                "remediation_ticket": "Mantener la visibilidad y accesibilidad directa del enlace en el footer institucional."
            })

            if privacy_audit.get("has_mandatory_keywords"):
                pilar_privacy_score += 15
                found_kws = ", ".join(privacy_audit.get("found_keywords", []))
                findings.append({
                    "pilar": "POLITICA_PRIVACIDAD",
                    "status": "OK",
                    "title": "Contenido Normativo Mínimo Verificado",
                    "detail": f"Se detectaron términos esenciales exigidos por la ley: {found_kws}.",
                    "technical_raw": found_kws,
                    "remediation_ticket": "Verificar periódicamente la vigencia de las finalidades y la identificación del responsable del tratamiento."
                })
            else:
                missing_kws = ", ".join(privacy_audit.get("missing_keywords", []))
                findings.append({
                    "pilar": "POLITICA_PRIVACIDAD",
                    "status": "WARNING",
                    "title": "Texto Normativo Incompleto o Genérico",
                    "detail": f"El documento omite cláusulas esenciales requeridas: {missing_kws}.",
                    "technical_raw": f"Faltantes: {missing_kws}",
                    "remediation_ticket": "Actualizar el documento de política incorporando secciones explícitas de: identificación del responsable, finalidades del tratamiento y derechos de los titulares."
                })

            privacy_status = "CUMPLE" if pilar_privacy_score >= 35 else "OBSERVACION"
        else:
            findings.append({
                "pilar": "POLITICA_PRIVACIDAD",
                "status": "FAIL",
                "title": "Ausencia o Inaccesibilidad de Política de Privacidad",
                "detail": "No se localizó un enlace visible o la URL de privacidad retornó un código de error HTTP.",
                "technical_raw": f"HTTP {privacy_audit.get('http_status', 'No encontrado')}",
                "remediation_ticket": "Publicar la Política de Privacidad en una URL pública accesible (HTTP 200) y enlazarla de forma persistente en el pie de página (footer) de todo el sitio."
            })

        score += pilar_privacy_score

        # =========================================================================
        # 2. PILAR: CANALES DERECHOS ARCO (Máx 30 pts)
        # =========================================================================
        pilar_arco_score = 0
        arco_status = "FALLA"

        if arco_audit.get("found"):
            detected_emails = arco_audit.get("detected_emails", [])
            has_explicit = arco_audit.get("has_explicit_arco_mention", False)

            if detected_emails:
                pilar_arco_score += 15
                emails_str = ", ".join(detected_emails)
                findings.append({
                    "pilar": "CANALES_ARCO",
                    "status": "OK",
                    "title": "Canal de Contacto Directo Detectado",
                    "detail": f"Canal de correo formal disponible para titulares: {emails_str}.",
                    "technical_raw": emails_str,
                    "remediation_ticket": "Asegurar que el buzón de correo cuente con protocolo de respuesta dentro de los plazos legales establecidos."
                })

            if has_explicit:
                pilar_arco_score += 15
                terms_str = ", ".join(arco_audit.get("detected_terms", []))
                findings.append({
                    "pilar": "CANALES_ARCO",
                    "status": "OK",
                    "title": "Mención Explícita a Derechos ARCO",
                    "detail": f"El sitio informa expresamente sobre derechos de Acceso, Rectificación, Cancelación u Oposición: {terms_str}.",
                    "technical_raw": terms_str,
                    "remediation_ticket": "Mantener publicado el procedimiento paso a paso para el ejercicio de cada derecho ARCO."
                })
            elif len(arco_audit.get("detected_terms", [])) > 0:
                pilar_arco_score += 5
                terms_str = ", ".join(arco_audit.get("detected_terms", []))
                findings.append({
                    "pilar": "CANALES_ARCO",
                    "status": "WARNING",
                    "title": "Mención Parcial de Derechos del Titular",
                    "detail": f"Se identificaron términos generales ({terms_str}) pero sin mención exhaustiva de los derechos ARCO.",
                    "technical_raw": terms_str,
                    "remediation_ticket": "Detallar expresamente en la política los derechos de Acceso, Rectificación, Cancelación y Oposición según la Ley N° 19.628."
                })

            arco_status = "CUMPLE" if pilar_arco_score >= 25 else "OBSERVACION"
        else:
            findings.append({
                "pilar": "CANALES_ARCO",
                "status": "FAIL",
                "title": "Sin Canales Formales para Ejercicio de Derechos ARCO",
                "detail": "No se detectaron correos ni mecanismos claros para que el titular gestione sus derechos de datos personales.",
                "technical_raw": "0 canales identificados",
                "remediation_ticket": "Habilitar un canal de comunicación directo (ej: privacidad@dominio.cl o formulario web dedicado) e indicarlo claramente en la política."
            })

        score += pilar_arco_score

        # =========================================================================
        # 3. PILAR: CONSENTIMIENTO Y COOKIES (Máx 35 pts)
        # =========================================================================
        pilar_consent_score = 0
        consent_status = "FALLA"

        has_unauthorized = tracker_audit.get("has_unauthorized_trackers", False)
        detected_domains = tracker_audit.get("detected_tracker_domains", [])
        detected_cookies = tracker_audit.get("detected_tracker_cookies", [])

        banner_audit = consent_banner_audit or {}
        banner_detected = banner_audit.get("banner_detected", False)
        has_reject_option = banner_audit.get("has_reject_option", False)

        # Ajuste de puntaje del pilar de consentimiento según presencia de rastreadores y banner
        if not has_unauthorized:
            if banner_detected and has_reject_option:
                pilar_consent_score = 35
                consent_status = "CUMPLE"
            elif banner_detected and not has_reject_option:
                pilar_consent_score = 20
                consent_status = "OBSERVACION"
            else:
                pilar_consent_score = 25
                consent_status = "CUMPLE"

            findings.append({
                "pilar": "CONSENTIMIENTO_COOKIES",
                "status": "OK",
                "title": "Navegación Limpia Previa al Consentimiento",
                "detail": "No se detectó inyección de cookies de terceros ni solicitudes salientes hacia dominios de rastreo publicitario previo a la interacción del usuario.",
                "technical_raw": "0 trackers activos pre-consentimiento",
                "remediation_ticket": "Mantener el bloqueo preventivo por defecto (opt-in) de todos los scripts de analítica y publicidad."
            })
        else:
            pilar_consent_score = 0
            consent_status = "FALLA"
            for domain in detected_domains:
                findings.append({
                    "pilar": "CONSENTIMIENTO_COOKIES",
                    "status": "FAIL",
                    "title": "Inyección no autorizada de rastreador externo",
                    "detail": f"Petición saliente interceptada hacia dominio de rastreo: '{domain}' antes de recibir consentimiento explícito.",
                    "technical_raw": domain,
                    "remediation_ticket": (
                        f"Condicionar la carga y ejecución de los scripts asociados a '{domain}' "
                        f"(ej. vía Google Tag Manager o gestor de consentimiento CMP) al evento de aceptación explícita del usuario."
                    )
                })

            for cookie in detected_cookies:
                findings.append({
                    "pilar": "CONSENTIMIENTO_COOKIES",
                    "status": "FAIL",
                    "title": "Depósito no autorizado de cookie de rastreo",
                    "detail": f"Cookie no esencial '{cookie}' depositada en el navegador previo a la interacción del usuario.",
                    "technical_raw": cookie,
                    "remediation_ticket": (
                        f"Configurar la cookie '{cookie}' para que solo se almacene tras la confirmación de consentimiento, "
                        f"bloqueando su emisión en la respuesta inicial HTTP Set-Cookie o script local."
                    )
                })

        # Hallazgos de auditoría de banner de consentimiento (Paso 10)
        if banner_detected and not has_reject_option:
            cmp_provider = banner_audit.get("cmp_provider")
            buttons = banner_audit.get("detected_buttons", [])
            tech_raw_parts = []
            if cmp_provider:
                tech_raw_parts.append(f"CMP: {cmp_provider}")
            if buttons:
                tech_raw_parts.append(f"Botones: {', '.join(buttons)}")
            tech_raw = " | ".join(tech_raw_parts) if tech_raw_parts else "Banner sin opción de rechazo"

            findings.append({
                "pilar": "CONSENTIMIENTO_COOKIES",
                "status": "WARNING",
                "title": "Banner de Consentimiento Sin Opción Real de Rechazo",
                "detail": (
                    "El banner o modal de cookies detectado es puramente informativo y no ofrece una opción "
                    "real y accesible para que el titular pueda rechazar o configurar cookies no esenciales."
                ),
                "technical_raw": tech_raw,
                "remediation_ticket": (
                    "Implementar en el banner una opción visible y simétrica para rechazar cookies no esenciales "
                    "(ej. botón 'Rechazar todas' o panel de configuración granular) al mismo nivel visual que el botón "
                    "de aceptación, conforme a las exigencias del Roadmap y la Ley N° 19.628."
                )
            })
        elif banner_detected and has_reject_option:
            cmp_provider = banner_audit.get("cmp_provider")
            tech_raw = f"CMP: {cmp_provider} - Opción de rechazo verificada" if cmp_provider else "Banner con opción de rechazo"
            findings.append({
                "pilar": "CONSENTIMIENTO_COOKIES",
                "status": "OK",
                "title": "Mecanismo de Consentimiento con Opción de Rechazo",
                "detail": (
                    "Se verificó la existencia de un banner de consentimiento que ofrece controles adecuados "
                    "y simétricos al usuario, incluyendo la opción explícita de rechazar cookies."
                ),
                "technical_raw": tech_raw,
                "remediation_ticket": (
                    "Mantener la vigencia de los controles del banner de consentimiento y asegurar la simetría "
                    "entre las acciones de aceptar y rechazar."
                )
            })
        elif not banner_detected and has_unauthorized:
            findings.append({
                "pilar": "CONSENTIMIENTO_COOKIES",
                "status": "FAIL",
                "title": "Ausencia de Mecanismo de Consentimiento con Rastreadores Activos",
                "detail": (
                    "El sitio web ejecuta rastreadores de terceros o deposita cookies de rastreo sin desplegar "
                    "un banner o mecanismo previo para recabar el consentimiento del usuario."
                ),
                "technical_raw": "0 mecanismos de consentimiento detectados",
                "remediation_ticket": (
                    "Implementar de forma urgente una plataforma de gestión de consentimiento (CMP) o banner "
                    "con bloqueo preventivo (opt-in) que impida la activación de scripts de rastreo antes de la decisión del usuario."
                )
            })

        score += pilar_consent_score

        # =========================================================================
        # DICTAMEN FINAL DETERMINISTA (C-01 / C-04 / TEST-RULE-04)
        # =========================================================================
        # Regla estricta Roadmap Fase 3:
        # - RECHAZADO: Inyección de trackers/cookies sin consentimiento previo o ausencia de política.
        # - APROBADO: Política funcional con contenido normativo mínimo, mención de derechos y 0 trackers.
        # - CON_OBSERVACIONES: Política genérica/incompleta, canales parciales o advertencias normativas,
        #   o banner de cookies puramente informativo sin opción real de rechazo o configuración.
        banner_lacks_reject = banner_detected and not has_reject_option

        if has_unauthorized:
            verdict = "RECHAZADO"
            verdict_summary = (
                "Incumplimiento crítico: Se detectaron rastreadores de terceros o cookies "
                "no esenciales activos previo al consentimiento del usuario."
            )
        elif score >= 80 and privacy_audit.get("has_mandatory_keywords", False) and not banner_lacks_reject:
            verdict = "APROBADO"
            verdict_summary = (
                "Conforme: El sitio web cumple con los estándares auditados de transparencia, "
                "disponibilidad de políticas y canales para el ejercicio de derechos ARCO."
            )
        elif score >= 55 or banner_lacks_reject:
            verdict = "CON_OBSERVACIONES"
            if banner_lacks_reject:
                verdict_summary = (
                    "Cumplimiento parcial: Banner de cookies puramente informativo sin opción real "
                    "de rechazo o configuración."
                )
            else:
                verdict_summary = (
                    "Cumplimiento parcial: El sitio presenta advertencias técnicas en la formulación "
                    "de la política de privacidad o en la exhaustividad de los canales ARCO."
                )
        else:
            verdict = "RECHAZADO"
            verdict_summary = (
                "Incumplimiento: Ausencia o inaccesibilidad de la política de privacidad "
                "y carencia de canales formales para el ejercicio de derechos del titular."
            )

        return {
            "target_url": target_url,
            "page_load_status": page_load_status,
            "verdict": verdict,
            "score": score,
            "verdict_summary": verdict_summary,
            "pilares": {
                "politica_privacidad": {
                    "status": privacy_status,
                    "score": pilar_privacy_score,
                    "max_score": 35
                },
                "canales_arco": {
                    "status": arco_status,
                    "score": pilar_arco_score,
                    "max_score": 30
                },
                "consentimiento_cookies": {
                    "status": consent_status,
                    "score": pilar_consent_score,
                    "max_score": 35
                }
            },
            "findings": findings,
            "technical_raw": scan_raw_data,
            "consent_banner_audit": consent_banner_audit,
            "frames_audit": frames_audit,
            "legal_disclaimer": LEGAL_DISCLAIMER
        }
