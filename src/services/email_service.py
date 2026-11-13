"""
Servicio asíncrono de notificación por correo electrónico para DataCheck.cl.
Soporta:
- Renderizado de plantilla HTML (src/templates/email_notification.html) con comparativa "Antes vs. Después" (RF-HIST-04).
- Envío SMTP asíncrono con aiosmtplib.
- Adjunto de reporte técnico en PDF generado en memoria.
- Modo graceful fallback para entornos locales sin servidor SMTP activo (no rompe el worker).
"""

import logging
import os
from email.message import EmailMessage
from typing import Dict, Any, Optional

import aiosmtplib

from src.core.config import settings

logger = logging.getLogger(__name__)

TEMPLATE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "templates",
    "email_notification.html",
)


class EmailService:
    @staticmethod
    def build_email_content(
        target_url: str,
        verdict: str,
        score: int,
        previous_verdict: str,
        previous_score: int,
        verdict_summary: str,
        findings_count: int,
        download_url: Optional[str] = None,
        comparison: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Genera el HTML del correo con la identidad visual de DataCheck.cl y comparativa evolutiva."""
        verdict_colors = {
            "APROBADO": "#10B981",
            "CON_OBSERVACIONES": "#F59E0B",
            "RECHAZADO": "#EF4444",
            "NO_ACCESIBLE": "#64748B",
        }
        verdict_color = verdict_colors.get(verdict, "#64748B")

        score_delta = int(score) - int(previous_score)
        if comparison and isinstance(comparison.get("score_comparison"), dict):
            score_delta = int(comparison["score_comparison"].get("delta", score_delta))

        if score_delta > 0:
            delta_label = f"+{score_delta} pts"
            delta_color = "#10B981"
            delta_bg = "rgba(16,185,129,0.18)"
        elif score_delta < 0:
            delta_label = f"{score_delta} pts"
            delta_color = "#EF4444"
            delta_bg = "rgba(239,68,68,0.18)"
        else:
            delta_label = "0 pts (Sin cambio)"
            delta_color = "#9CA3AF"
            delta_bg = "rgba(156,163,175,0.18)"

        transition_status = "UNCHANGED"
        if comparison and isinstance(comparison.get("verdict_transition"), dict):
            transition_status = comparison["verdict_transition"].get("status", "UNCHANGED")
        elif score_delta > 0 or (previous_verdict == "RECHAZADO" and verdict == "APROBADO"):
            transition_status = "IMPROVED"
        elif score_delta < 0:
            transition_status = "REGRESSED"

        transition_labels = {
            "IMPROVED": "Mejoró",
            "REGRESSED": "Regresión",
            "UNCHANGED": "Sin cambios",
        }
        transition_label = transition_labels.get(transition_status, transition_status)

        trackers_diff_html = ""
        if comparison and isinstance(comparison.get("trackers_diff"), dict):
            td = comparison["trackers_diff"]
            remediated = td.get("remediated") or []
            persistent = td.get("persistent") or []
            regressions = td.get("regressions") or []

            parts = []
            if remediated:
                items_str = ", ".join(f"<code>{r.get('valor')}</code> ({r.get('tipo')})" for r in remediated)
                parts.append(f"<p style='margin:6px 0; color:#10B981;'>✅ <strong>Rastreadores Remediados ({len(remediated)}):</strong> {items_str}</p>")
            if persistent:
                items_str = ", ".join(f"<code>{p.get('valor')}</code>" for p in persistent)
                parts.append(f"<p style='margin:6px 0; color:#F59E0B;'>⚠️ <strong>Rastreadores Persistentes ({len(persistent)}):</strong> {items_str}</p>")
            if regressions:
                items_str = ", ".join(f"<code>{reg.get('valor')}</code> ({reg.get('tipo')})" for reg in regressions)
                parts.append(f"<p style='margin:6px 0; color:#EF4444;'>🚨 <strong>Nuevas Regresiones ({len(regressions)}):</strong> {items_str}</p>")

            if parts:
                trackers_diff_html = "<div class='tracker-box'>" + "".join(parts) + "</div>"

        download_button_html = (
            f'<a href="{download_url}" class="btn" style="color:#ffffff;">Ver Reporte en DataCheck.cl</a>'
            if download_url
            else ""
        )

        if os.path.exists(TEMPLATE_PATH):
            with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
                template = f.read()
            return (
                template.replace("{{target_url}}", str(target_url))
                .replace("{{verdict}}", str(verdict))
                .replace("{{score}}", str(score))
                .replace("{{previous_verdict}}", str(previous_verdict))
                .replace("{{previous_score}}", str(previous_score))
                .replace("{{verdict_summary}}", str(verdict_summary))
                .replace("{{findings_count}}", str(findings_count))
                .replace("{{verdict_color}}", verdict_color)
                .replace("{{delta_label}}", delta_label)
                .replace("{{delta_color}}", delta_color)
                .replace("{{delta_bg}}", delta_bg)
                .replace("{{transition_status}}", transition_status)
                .replace("{{transition_label}}", transition_label)
                .replace("{{trackers_diff_html}}", trackers_diff_html)
                .replace("{{download_button_html}}", download_button_html)
            )

        return f"""<!DOCTYPE html>
<html lang="es">
<body>
  <p>Resultado de Re-evaluación para {target_url}: {verdict} ({score}/100 pts, {delta_label}).</p>
  <p>Anterior: {previous_verdict} ({previous_score} pts) -> Actual: {verdict} ({score} pts).</p>
  {trackers_diff_html}
</body>
</html>"""

    @classmethod
    async def send_audit_notification(
        cls,
        to_email: str,
        target_url: str,
        verdict: str,
        score: int,
        previous_verdict: str,
        previous_score: int,
        verdict_summary: str,
        findings_count: int,
        pdf_bytes: Optional[bytes] = None,
        download_url: Optional[str] = None,
        comparison: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Despacha el correo de notificación por SMTP asíncrono con el PDF adjunto.
        Si el servidor SMTP no está accesible (ej. en desarrollo local sin Mailhog),
        captura la excepción y registra un log para asegurar resiliencia (no tumba el worker).
        """
        html_content = cls.build_email_content(
            target_url=target_url,
            verdict=verdict,
            score=score,
            previous_verdict=previous_verdict,
            previous_score=previous_score,
            verdict_summary=verdict_summary,
            findings_count=findings_count,
            download_url=download_url,
            comparison=comparison,
        )

        message = EmailMessage()
        message["From"] = settings.SMTP_FROM_EMAIL
        message["To"] = to_email
        message["Subject"] = f"[DataCheck.cl] Resultado de Re-auditoría: {target_url} ({verdict})"

        message.set_content(
            f"Resultado de Re-evaluación para {target_url}: {verdict} ({score}/100 pts).\n"
            f"Diagnóstico: {verdict_summary}\n"
            f"Revise el informe PDF adjunto para más detalles."
        )
        message.add_alternative(html_content, subtype="html")

        # Adjuntar PDF si fue provisto
        if pdf_bytes:
            safe_domain = target_url.replace("https://", "").replace("http://", "").split("/")[0] or "sitio"
            filename = f"DataCheck_ReAuditoria_{safe_domain}.pdf"
            message.add_attachment(
                pdf_bytes,
                maintype="application",
                subtype="pdf",
                filename=filename
            )

        try:
            logger.info(f"Enviando correo de notificación a {to_email} vía {settings.SMTP_HOST}:{settings.SMTP_PORT}...")
            use_tls = settings.SMTP_TLS
            start_tls = True if settings.SMTP_PORT == 587 else False
            if use_tls:
                start_tls = False

            await aiosmtplib.send(
                message,
                hostname=settings.SMTP_HOST,
                port=settings.SMTP_PORT,
                username=settings.SMTP_USER or None,
                password=settings.SMTP_PASSWORD or None,
                use_tls=use_tls,
                start_tls=start_tls,
                timeout=15
            )
            logger.info(f"Correo de notificación enviado exitosamente a {to_email}")
            return True

        except Exception as e:
            logger.warning(
                f"No se pudo despachar el correo SMTP a {to_email} (Servidor SMTP no disponible o simulado): {e}"
            )
            return False
