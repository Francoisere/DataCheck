"""
Motor de Reglas de Cumplimiento Legal (Ley N° 19.628 y Nueva Ley de Protección de Datos Personales Chile N° 21.719).
Incremento 2 + Mejoras de Primera Defensa (FB-02 / FB-04):
- Ponderación de 100 pts: Política de Privacidad (35 pts), Canales ARCO (30 pts), Consentimiento & Cookies (35 pts).
- Dictamen determinista: APROBADO (score >= 80 y 0 trackers), CON_OBSERVACIONES (score >= 55 o banner sin opción de rechazo),
  RECHAZADO (< 55 o trackers no autorizados con score bajo), NO_ACCESIBLE (bloqueo WAF/HTTP 403/503/timeout).
- Generación sistemática de tickets técnicos de remediación (remediation_ticket) con código accionable (FB-04).
"""

from typing import Dict, Any, List
from src.scanner.remediation_catalog import get_remediation_ticket

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
        error_msg = scan_raw_data.get("error_message", "")

        # Validación de accesibilidad perimetral (FB-02 / D-01)
        # Si la navegación inicial devuelve 0, 403, 503 o detecta bloqueo WAF/timeout,
        # emitir estado neutro no sancionatorio NO_ACCESIBLE
        page_load_status = 1 if (isinstance(raw_page_status, int) and 200 <= raw_page_status < 400) else 0

        if page_load_status == 0 or raw_page_status in (0, 403, 503) or error_msg in ("BLOQUEO_WAF_ANTIBOT", "TIMEOUT_EXCEDIDO"):
            is_waf = error_msg == "BLOQUEO_WAF_ANTIBOT" or raw_page_status in (403, 503)
            return {
                "target_url": target_url,
                "page_load_status": 0,
                "verdict": "NO_ACCESIBLE",
                "score": 0,
                "verdict_summary": (
                    "Sitio no accesible para análisis técnico pasivo (Bloqueo WAF / Cortafuegos perimetral)."
                    if is_waf else
                    "Sitio no accesible para análisis técnico pasivo."
                ),
                "pilares": {
                    "politica_privacidad": {
                        "status": "FALLA",
                        "score": 0,
                        "max_score": 35
                    },
                    "canales_arco": {
                        "status": "FALLA",
                        "score": 0,
                        "max_score": 30
                    },
                    "consentimiento_cookies": {
                        "status": "FALLA",
                        "score": 0,
                        "max_score": 35
                    }
                },
                "findings": [
                    {
                        "pilar": "ACCESIBILIDAD_PERIMETRAL",
                        "status": "WARNING",
                        "title": "Inspección Externa Bloqueada" if is_waf else "Inspección Externa No Disponible",
                        "detail": (
                            "El sitio web cuenta con un firewall de aplicaciones web (WAF) que impidió la auditoría pasiva."
                            if is_waf else
                            "No fue posible conectar con el sitio dentro del tiempo límite o el servidor no respondió adecuadamente."
                        ),
                        "technical_raw": f"HTTP {raw_page_status} - {error_msg or 'Sin respuesta'}",
                        "remediation_ticket": get_remediation_ticket(
                            "WAF_PERIMETRAL_BLOCK",
                            f"HTTP {raw_page_status} / {error_msg or 'Bloqueo WAF/Timeout'}"
                        )
                    }
                ],
                "technical_raw": scan_raw_data,
                "consent_banner_audit": None,
                "frames_audit": None,
                "responsible_party_audit": None,
                "legal_disclaimer": LEGAL_DISCLAIMER
            }

        tracker_audit = scan_raw_data.get("tracker_audit", {})
        privacy_audit = scan_raw_data.get("privacy_policy_audit", {})
        arco_audit = scan_raw_data.get("arco_channels_audit", {})
        consent_banner_audit = scan_raw_data.get("consent_banner_audit")
        frames_audit = scan_raw_data.get("frames_audit")
        responsible_audit = scan_raw_data.get("responsible_party_audit")

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
                "remediation_ticket": get_remediation_ticket("POLICY_MISSING_OR_BROKEN", "Ruta activa verificada con HTTP 200.")
            })

            if privacy_audit.get("has_mandatory_keywords"):
                pilar_privacy_score += 10
                found_kws = ", ".join(privacy_audit.get("found_keywords", []))
                findings.append({
                    "pilar": "POLITICA_PRIVACIDAD",
                    "status": "OK",
                    "title": "Contenido Normativo Mínimo Verificado",
                    "detail": f"Se detectaron términos esenciales exigidos por la ley: {found_kws}.",
                    "technical_raw": found_kws,
                    "remediation_ticket": get_remediation_ticket("POLICY_INCOMPLETE", "Contenido normativo verificado.")
                })
            else:
                missing_kws = ", ".join(privacy_audit.get("missing_keywords", []))
                findings.append({
                    "pilar": "POLITICA_PRIVACIDAD",
                    "status": "WARNING",
                    "title": "Texto Normativo Incompleto o Genérico",
                    "detail": f"El documento omite cláusulas esenciales requeridas: {missing_kws}.",
                    "technical_raw": f"Faltantes: {missing_kws}",
                    "remediation_ticket": get_remediation_ticket("POLICY_INCOMPLETE", f"Cláusulas faltantes: {missing_kws}")
                })

            # Sub-evaluación Art. 14 ter (letras b y c): Transparencia del Responsable y Canales de Notificación
            if responsible_audit:
                resp_verdict = responsible_audit.get("verdict", "OBSERVACION")
                channels = responsible_audit.get("contact_channels_found", [])
                channels_str = ", ".join(channels) if channels else "Ninguno detectado"
                dpo_str = "Indicado / Nombrado" if responsible_audit.get("dpo_found") else "No especificado (Opcional según Art. 49/50)"
                ident_str = "Identificado (RUT / Razón Social / Representante)" if (responsible_audit.get("identified") or responsible_audit.get("representative_found")) else "No individualizado explícitamente"

                corp = responsible_audit.get("corporate_name")
                rut = responsible_audit.get("detected_rut")
                mail = responsible_audit.get("contact_email")
                addr = responsible_audit.get("postal_address")

                ident_parts = []
                if corp:
                    ident_parts.append(f"Razón Social: {corp}")
                if rut:
                    ident_parts.append(f"RUT: {rut}")
                if not ident_parts and responsible_audit.get("representative_found"):
                    ident_parts.append("Representante legal identificado")

                ident_summary = " | ".join(ident_parts) if ident_parts else ident_str

                channel_parts = []
                if mail:
                    channel_parts.append(f"Email: {mail}")
                if "formulario" in channels:
                    channel_parts.append("Formulario web")
                if addr:
                    channel_parts.append(f"Domicilio: {addr}")
                elif "domicilio" in channels:
                    channel_parts.append("Domicilio físico")

                channels_summary = " | ".join(channel_parts) if channel_parts else channels_str

                if resp_verdict == "CUMPLE":
                    pilar_privacy_score += 5
                    findings.append({
                        "pilar": "POLITICA_PRIVACIDAD",
                        "status": "OK",
                        "title": "Identificación del Responsable y Canales de Notificación (Art. 14 ter)",
                        "detail": f"El responsable individualiza su identidad ({ident_summary}), canal de atención ({channels_summary}) y estado de DPO ({dpo_str}) conforme al Art. 14 ter literales b y c.",
                        "technical_raw": f"Entidad: {ident_summary} | Canales: {channels_summary} | DPO: {dpo_str}"[:500],
                        "remediation_ticket": get_remediation_ticket("POLICY_INCOMPLETE", "Art. 14 ter Ley 21.719 - Mantener al día la designación del DPO y canales habilitados."),
                        "legal_basis_key": "POLITICA_PRIVACIDAD_ART14TER_OK"
                    })
                else:
                    findings.append({
                        "pilar": "POLITICA_PRIVACIDAD",
                        "status": "WARNING",
                        "title": "Omisión de Deberes de Información del Responsable (Art. 14 ter)",
                        "detail": "La política de privacidad o la página pública no individualiza con claridad el RUT/Razón Social, representante legal o carece de canales idóneos de notificación (Art. 14 ter b y c).",
                        "technical_raw": f"Canales detectados: {channels_str} | DPO: {dpo_str} | Identificación: {ident_str}"[:500],
                        "remediation_ticket": get_remediation_ticket("POLICY_INCOMPLETE", "Art. 14 ter Ley 21.719 - Incorporar en el pie de página (footer) o en la sección inicial de la Política de Privacidad la individualización legal del responsable (Razón Social y RUT), el nombre o cargo del Representante Legal/DPO, y un correo de contacto o formulario directo dedicado a la recepción de solicitudes de derechos titulares."),
                        "legal_basis_key": "POLITICA_PRIVACIDAD_ART14TER_WARNING"
                    })
            elif privacy_audit.get("has_mandatory_keywords"):
                # Fallback retrocompatible para mocks antiguos que aprobaban contenido normativo completo
                pilar_privacy_score += 5

            privacy_status = "CUMPLE" if pilar_privacy_score >= 35 else "OBSERVACION"
        else:
            findings.append({
                "pilar": "POLITICA_PRIVACIDAD",
                "status": "FAIL",
                "title": "Ausencia o Inaccesibilidad de Política de Privacidad",
                "detail": "No se localizó un enlace visible o la URL de privacidad retornó un código de error HTTP.",
                "technical_raw": f"HTTP {privacy_audit.get('http_status', 'No encontrado')}",
                "remediation_ticket": get_remediation_ticket("POLICY_MISSING_OR_BROKEN", f"HTTP {privacy_audit.get('http_status', 'No encontrado')}")
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
                    "remediation_ticket": get_remediation_ticket("ARCO_INCOMPLETE", f"Buzón formal detectado: {emails_str}. Asegurar protocolo dentro de plazos legales (15 días hábiles).")
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
                    "remediation_ticket": get_remediation_ticket("ARCO_INCOMPLETE", f"Derechos identificados: {terms_str}. Mantener publicado procedimiento paso a paso.")
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
                    "remediation_ticket": get_remediation_ticket("ARCO_INCOMPLETE", f"Términos parciales: {terms_str}. Detallar expresamente Acceso, Rectificación, Cancelación y Oposición.")
                })

            arco_status = "CUMPLE" if pilar_arco_score >= 25 else "OBSERVACION"
        else:
            findings.append({
                "pilar": "CANALES_ARCO",
                "status": "FAIL",
                "title": "Sin Canales Formales para Ejercicio de Derechos ARCO",
                "detail": "No se detectaron correos ni mecanismos claros para que el titular gestione sus derechos de datos personales.",
                "technical_raw": "0 canales identificados",
                "remediation_ticket": get_remediation_ticket("ARCO_MISSING", "0 canales formales detectados.")
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

        banner_audit = dict(consent_banner_audit) if consent_banner_audit else {}
        banner_detected = banner_audit.get("banner_detected", False)
        has_reject_option = banner_audit.get("has_reject_option", False)
        has_settings_option = banner_audit.get("has_settings_option", False)
        buttons_verifiable = banner_audit.get("buttons_verifiable", True)
        cmp_provider = banner_audit.get("cmp_provider")
        detected_buttons = banner_audit.get("detected_buttons", [])

        # Dictamen de bloqueo preventivo pre-consentimiento (blocks_prior_to_consent)
        if banner_detected:
            blocks_prior_to_consent = not has_unauthorized
            banner_audit["blocks_prior_to_consent"] = blocks_prior_to_consent
            if consent_banner_audit is not None:
                consent_banner_audit["blocks_prior_to_consent"] = blocks_prior_to_consent
        else:
            blocks_prior_to_consent = None

        # Ajuste de puntaje del pilar de consentimiento según presencia de rastreadores y banner
        if not has_unauthorized:
            if banner_detected:
                if not buttons_verifiable:
                    # Shadow DOM cerrado: banner detectado pero controles encapsulados, sin trackers -> 35 pts
                    pilar_consent_score = 35
                    consent_status = "CUMPLE"
                elif has_reject_option:
                    pilar_consent_score = 35
                    consent_status = "CUMPLE"
                else:
                    # Banner sin rechazo directo (informativo o de 2 pasos) -> 20 pts
                    pilar_consent_score = 20
                    consent_status = "OBSERVACION"
            else:
                # Sitio limpio sin trackers ni banner -> 35 pts (sitio estático/limpio conforme)
                pilar_consent_score = 35
                consent_status = "CUMPLE"

            findings.append({
                "pilar": "CONSENTIMIENTO_COOKIES",
                "status": "OK",
                "title": "Navegación Limpia Previa al Consentimiento",
                "detail": "No se detectó inyección de cookies de terceros ni solicitudes salientes hacia dominios de rastreo publicitario previo a la interacción del usuario.",
                "technical_raw": "0 trackers activos pre-consentimiento",
                "remediation_ticket": get_remediation_ticket("TRACKER_UNAUTHORIZED", "Navegación conforme: Mantener bloqueo preventivo por defecto (opt-in).")
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
                    "remediation_ticket": get_remediation_ticket("TRACKER_UNAUTHORIZED", f"Dominio de rastreo externo no autorizado: '{domain}'")
                })

            for cookie in detected_cookies:
                findings.append({
                    "pilar": "CONSENTIMIENTO_COOKIES",
                    "status": "FAIL",
                    "title": "Depósito no autorizado de cookie de rastreo",
                    "detail": f"Cookie no esencial '{cookie}' depositada en el navegador previo a la interacción del usuario.",
                    "technical_raw": cookie,
                    "remediation_ticket": get_remediation_ticket("COOKIE_UNAUTHORIZED", f"Cookie no esencial no autorizada: '{cookie}'")
                })

        # Hallazgos de auditoría de banner de consentimiento
        if banner_detected and not buttons_verifiable:
            findings.append({
                "pilar": "CONSENTIMIENTO_COOKIES",
                "status": "OK",
                "title": "Banner Detectado con Encapsulamiento Avanzado (Shadow DOM Cerrado)",
                "detail": (
                    f"Se identificó la presencia de un banner de consentimiento ('{cmp_provider or 'Genérico'}'), "
                    "pero sus controles internos se encuentran encapsulados en un Shadow DOM en modo cerrado ('closed'). "
                    "Conforme al principio de inspección pasiva estricta (DA-01 / EC-04), los controles se catalogan como "
                    "no verificables de forma pasiva, sin aplicar penalización de puntaje al no registrarse transferencias no consentidas."
                ),
                "technical_raw": f"CMP: {cmp_provider or 'Genérico'} | Shadow DOM: closed | Verificable: False",
                "remediation_ticket": get_remediation_ticket(
                    "BANNER_NO_REJECT",
                    "Shadow DOM Cerrado: Asegurar interfaces accesibles para auditoría y verificación técnica."
                )
            })
        elif banner_detected and not has_reject_option:
            tech_raw_parts = []
            if cmp_provider:
                tech_raw_parts.append(f"CMP: {cmp_provider}")
            if detected_buttons:
                tech_raw_parts.append(f"Botones: {', '.join(detected_buttons)}")
            tech_raw = " | ".join(tech_raw_parts) if tech_raw_parts else "Banner sin opción de rechazo"

            if has_settings_option:
                findings.append({
                    "pilar": "CONSENTIMIENTO_COOKIES",
                    "status": "WARNING",
                    "title": "Banner de 2 Pasos Sin Opción Directa de Rechazo en Primer Nivel",
                    "detail": (
                        f"El banner detectado ({cmp_provider or 'Genérico'}) ofrece opciones de aceptación y configuración "
                        f"({', '.join(detected_buttons)}), pero no dispone de un botón directo de rechazo en primer nivel. "
                        "La opción de rechazo podría requerir navegación adicional hacia el panel de configuración, "
                        "lo cual no es accesible bajo el principio de inspección pasiva estricta (DA-01) al requerir clics activos."
                    ),
                    "technical_raw": tech_raw,
                    "remediation_ticket": get_remediation_ticket("BANNER_NO_REJECT", f"Banner 2 pasos ({tech_raw}): Incorporar botón 'Rechazar todo' en primer nivel.")
                })
            else:
                findings.append({
                    "pilar": "CONSENTIMIENTO_COOKIES",
                    "status": "WARNING",
                    "title": "Banner de Consentimiento Sin Opción Real de Rechazo",
                    "detail": (
                        "El banner o modal de cookies detectado es puramente informativo y no ofrece una opción "
                        "real y accesible para que el titular pueda rechazar o configurar cookies no esenciales."
                    ),
                    "technical_raw": tech_raw,
                    "remediation_ticket": get_remediation_ticket("BANNER_NO_REJECT", tech_raw)
                })
        elif banner_detected and has_reject_option:
            tech_raw = f"CMP: {cmp_provider} - Opción de rechazo verificada" if cmp_provider else "Banner con opción de rechazo"
            if detected_buttons:
                tech_raw += f" | Botones: {', '.join(detected_buttons)}"
            findings.append({
                "pilar": "CONSENTIMIENTO_COOKIES",
                "status": "OK",
                "title": "Mecanismo de Consentimiento con Opción de Rechazo",
                "detail": (
                    "Se verificó la existencia de un banner de consentimiento que ofrece controles adecuados "
                    "y simétricos al usuario, incluyendo la opción explícita de rechazar cookies."
                ),
                "technical_raw": tech_raw,
                "remediation_ticket": get_remediation_ticket("BANNER_NO_REJECT", "Opción de rechazo verificada conforme a Ley 21.719.")
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
                "remediation_ticket": get_remediation_ticket("BANNER_NO_REJECT", "Ausencia total de banner con trackers activos.")
            })

        # Hallazgo de evaluación de bloqueo preventivo (pre-consentimiento)
        if banner_detected:
            if blocks_prior_to_consent:
                findings.append({
                    "pilar": "CONSENTIMIENTO_COOKIES",
                    "status": "OK",
                    "title": "Bloqueo Preventivo Efectivo (Pre-Consentimiento)",
                    "detail": (
                        "El gestor de consentimiento bloquea preventivamente todos los rastreadores y cookies "
                        "de terceros antes de la decisión del usuario."
                    ),
                    "technical_raw": f"CMP: {cmp_provider or 'Genérico'} | Bloqueo preventivo: Activo",
                    "remediation_ticket": get_remediation_ticket("TRACKER_UNAUTHORIZED", "Bloqueo preventivo activo y conforme.")
                })
            else:
                findings.append({
                    "pilar": "CONSENTIMIENTO_COOKIES",
                    "status": "FAIL",
                    "title": "Falla en Bloqueo Preventivo Pre-Consentimiento",
                    "detail": (
                        f"A pesar de contar con un banner de consentimiento ('{cmp_provider or 'Genérico'}'), "
                        "se detectaron solicitudes de rastreo o cookies no esenciales ejecutándose antes de la interacción del usuario."
                    ),
                    "technical_raw": (
                        f"CMP: {cmp_provider or 'Genérico'} | Trackers detectados pre-consentimiento: "
                        f"{len(detected_domains)} dominios, {len(detected_cookies)} cookies"
                    ),
                    "remediation_ticket": get_remediation_ticket("TRACKER_UNAUTHORIZED", "Falla en bloqueo previo: configurar CMP en modo estricto.")
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
        banner_lacks_reject = banner_detected and buttons_verifiable and not has_reject_option

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
                if has_settings_option:
                    verdict_summary = (
                        "Cumplimiento parcial: Banner de consentimiento de 2 pasos sin opción directa de rechazo en primer nivel."
                    )
                else:
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
            "consent_banner_audit": banner_audit if banner_detected else consent_banner_audit,
            "frames_audit": frames_audit,
            "responsible_party_audit": responsible_audit,
            "legal_disclaimer": LEGAL_DISCLAIMER
        }
