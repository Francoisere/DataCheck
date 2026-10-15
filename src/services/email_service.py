"""
Servicio asíncrono de notificación por correo electrónico para DataCheck.cl.
Soporta:
- Renderizado de plantilla HTML con comparativa de auditorías previa vs nueva.
- Envío SMTP asíncrono con aiosmtplib.
- Adjunto de reporte técnico en PDF generado en memoria.
- Modo graceful fallback para entornos locales sin servidor SMTP activo (no rompe el worker).
"""

import io
import logging
from email.message import EmailMessage
from email.headerregistry import Address
from typing import Dict, Any, Optional

import aiosmtplib

from src.core.config import settings

logger = logging.getLogger(__name__)


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
        download_url: Optional[str] = None
    ) -> str:
        """Genera el HTML del correo con la identidad visual de DataCheck.cl."""
        verdict_colors = {
            "APROBADO": "#10B981",
            "CON_OBSERVACIONES": "#F59E0B",
            "RECHAZADO": "#EF4444"
        }
        color = verdict_colors.get(verdict, "#64748B")

        return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0B0F19; color: #F3F4F6; margin: 0; padding: 24px; }}
    .container {{ max-width: 600px; margin: 0 auto; background: #171F31; border: 1px solid rgba(255,255,255,0.1); border-radius: 12px; padding: 28px; }}
    .header {{ border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 16px; margin-bottom: 20px; }}
    .logo {{ font-size: 20px; font-weight: 800; color: #F3F4F6; }}
    .logo-cyan {{ color: #00E5FF; }}
    .badge {{ display: inline-block; padding: 6px 14px; border-radius: 6px; font-weight: 700; font-size: 14px; background: {color}; color: #FFFFFF; }}
    .comparison {{ display: flex; justify-content: space-between; background: rgba(11,15,25,0.6); padding: 14px; border-radius: 8px; margin: 20px 0; }}
    .comp-col {{ flex: 1; text-align: center; }}
    .btn {{ display: inline-block; background: linear-gradient(135deg, #0284C7, #0EA5E9); color: #FFFFFF; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 700; margin-top: 16px; }}
    .footer {{ font-size: 11px; color: #64748B; margin-top: 24px; text-align: center; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo">🛡️ DataCheck<span class="logo-cyan">.cl</span></div>
      <p style="color: #9CA3AF; margin: 4px 0 0 0; font-size: 13px;">Informe de Re-evaluación Programada de Datos Personales (Ley 21.719)</p>
    </div>

    <p>Estimado/a usuario,</p>
    <p>Se ha completado la re-auditoría automática para el sitio: <strong style="color: #00E5FF;">{target_url}</strong>.</p>

    <div style="text-align: center; margin: 24px 0;">
      <span class="badge">{verdict} ({score}/100 pts)</span>
    </div>

    <div style="background: rgba(11,15,25,0.6); border: 1px solid rgba(255,255,255,0.08); padding: 14px; border-radius: 8px; font-size: 13px;">
      <p style="margin: 0 0 8px 0;"><strong>Comparativa de Evolución:</strong></p>
      <ul style="margin: 0; padding-left: 20px; color: #9CA3AF;">
        <li>Auditoría Anterior: <strong>{previous_verdict}</strong> ({previous_score} pts)</li>
        <li>Nueva Auditoría: <strong style="color: {color};">{verdict}</strong> ({score} pts)</li>
        <li>Evidencias técnicas evaluadas: {findings_count}</li>
      </ul>
    </div>

    <p style="font-size: 13px; color: #9CA3AF; line-height: 1.5; margin-top: 16px;">
      <strong>Diagnóstico:</strong> {verdict_summary}
    </p>

    <div style="text-align: center; margin: 24px 0;">
      <p style="font-size: 13px; color: #CBD5E1;">El informe técnico detallado con sustento de la Ley 21.719 se encuentra adjunto en este correo.</p>
      {f'<a href="{download_url}" class="btn" style="color:#ffffff;">Ver Reporte en DataCheck.cl</a>' if download_url else ''}
    </div>

    <div class="footer">
      <p>DataCheck.cl - Plataforma de Auditoría Técnica de Datos Personales (Chile)</p>
      <p>Este es un correo automático generado por una tarea programada. No responda a este mensaje.</p>
    </div>
  </div>
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
        download_url: Optional[str] = None
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
            download_url=download_url
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
