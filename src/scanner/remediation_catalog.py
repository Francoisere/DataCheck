"""
Catálogo Centralizado de Tickets Técnicos de Remediación (FB-04 / RC-03 / PBI-03).
Asocia cada tipo de incumplimiento o hallazgo normativo a una solución técnica concreta
con fragmentos de código listos para producción (GTM, HTML semántico, configuración de rutas HTTP).
"""

from typing import Dict, Any, Optional


REMEDIATION_TICKETS: Dict[str, Dict[str, str]] = {
    # -------------------------------------------------------------------------
    # 1. TRACKERS Y COOKIES NO AUTORIZADAS PRE-CONSENTIMIENTO (Art. 14 / RF-01)
    # -------------------------------------------------------------------------
    "TRACKER_UNAUTHORIZED": {
        "ticket_id": "TICK-TRK-01",
        "title": "Condicionar disparo de etiquetas en Google Tag Manager (GTM)",
        "summary": "Condicionar la carga de rastreadores externos al evento de consentimiento explícito afirmativo.",
        "directive": "Modificar el activador (trigger) de la etiqueta en GTM para que no dispare en 'All Pages', sino en el evento personalizado 'cookie_consent_accepted'.",
        "code_snippet": """// 1. Enviar evento al DataLayer al aceptar cookies en el banner:
window.dataLayer = window.dataLayer || [];
window.dataLayer.push({
  'event': 'cookie_consent_accepted',
  'consent_analytics': true,
  'consent_marketing': true
});

// 2. Configurar en Google Tag Manager:
// - Trigger Type: Custom Event
// - Event name: cookie_consent_accepted
// - Firing condition: Solamente asociar a tags de terceros (ej: GA4, Meta Pixel)"""
    },
    "COOKIE_UNAUTHORIZED": {
        "ticket_id": "TICK-TRK-02",
        "title": "Bloqueo preventivo de cookies de rastreo previo al opt-in",
        "summary": "Impedir el depósito de cookies no esenciales en la respuesta inicial HTTP Set-Cookie o script en línea.",
        "directive": "Verificar que el servidor o script de frontend no emita cabeceras 'Set-Cookie' de analítica o marketing antes de que el usuario interactúe con el CMP.",
        "code_snippet": """// Condicionar la escritura de cookies en el cliente:
function setTrackingCookie(name, value, days) {
  if (localStorage.getItem('user_cookie_consent') !== 'accepted') {
    console.warn('[DataCheck] Depósito de cookie bloqueado por falta de consentimiento opt-in:', name);
    return;
  }
  const date = new Date();
  date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
  document.cookie = `${name}=${value}; expires=${date.toUTCString()}; path=/; SameSite=Lax; Secure`;
}"""
    },

    # -------------------------------------------------------------------------
    # 2. POLÍTICA DE PRIVACIDAD Y RUTAS CANÓNICAS (Art. 14 ter / RF-02)
    # -------------------------------------------------------------------------
    "POLICY_MISSING_OR_BROKEN": {
        "ticket_id": "TICK-POL-01",
        "title": "Publicar ruta canónica accesible /privacidad con HTTP 200",
        "summary": "Habilitar y enlazar de forma persistente la Política de Privacidad en el pie de página institucional.",
        "directive": "Configurar una ruta canónica pública en el servidor web o framework de backend que responda con código HTTP 200 y enlace visible en el footer.",
        "code_snippet": """<!-- 1. Enlace semántico en el footer institucional (HTML) -->
<footer class="site-footer">
  <nav aria-label="Enlaces Legales">
    <a href="/privacidad" rel="privacy-policy" class="legal-link">
      Política de Privacidad y Tratamiento de Datos
    </a>
  </nav>
</footer>

// 2. Ejemplo de ruta canónica en Express / FastAPI:
// FastAPI (Python):
@app.get("/privacidad", response_class=HTMLResponse)
async def privacy_policy():
    return render_template("politica_privacidad.html")"""
    },
    "POLICY_INCOMPLETE": {
        "ticket_id": "TICK-POL-02",
        "title": "Actualizar cláusulas normativas esenciales (Ley 21.719)",
        "summary": "Incorporar secciones expresas de individualización del responsable, finalidades legítimas y derechos ARCO.",
        "directive": "Actualizar el texto de la política incluyendo los 4 componentes requeridos por el Art. 14 ter: responsable legal (RUT/Razón Social), finalidades del tratamiento, tiempo de conservación y ejercicio de derechos.",
        "code_snippet": """<!-- Estructura mínima recomendada en /privacidad (HTML) -->
<section id="aviso-privacidad">
  <h2>1. Responsable del Tratamiento</h2>
  <p>Razón Social: <strong>[NOMBRE_EMPRESA]</strong> | RUT: <strong>[XX.XXX.XXX-X]</strong></p>
  <p>Representante Legal / DPO: <strong>[NOMBRE_O_CARGO]</strong></p>

  <h2>2. Finalidades y Base de Licitud</h2>
  <p>Los datos recopilados serán tratados exclusivamente para: [FINALIDADES_CONCRETAS].</p>

  <h2>3. Ejercicio de Derechos ARCO</h2>
  <p>Para ejercer sus derechos de acceso, rectificación, cancelación y oposición, escriba a:
     <a href="mailto:privacidad@dominio.cl">privacidad@dominio.cl</a>.</p>
</section>"""
    },

    # -------------------------------------------------------------------------
    # 3. CANALES PARA EJERCICIO DE DERECHOS ARCO (Art. 14 ter letra c / RF-03)
    # -------------------------------------------------------------------------
    "ARCO_MISSING": {
        "ticket_id": "TICK-ARC-01",
        "title": "Habilitar canal directo para derechos ARCO (mailto / formulario)",
        "summary": "Proveer una vía formal y visible para la recepción de solicitudes de Acceso, Rectificación, Cancelación y Oposición.",
        "directive": "Incorporar en el footer o en la sección de contacto un enlace 'mailto:' dedicado o un formulario web accesible sin autenticación forzada.",
        "code_snippet": """<!-- Bloque HTML para footer con canal ARCO (HTML5) -->
<div class="arco-contact-channel">
  <h4>Ejercicio de Derechos de Datos Personales</h4>
  <p>De acuerdo con la Ley N° 19.628 / 21.719, usted puede solicitar el acceso, rectificación, 
     cancelación u oposición de sus datos personales a través de nuestro canal formal:</p>
  <a href="mailto:privacidad@dominio.cl?subject=Solicitud%20Derechos%20ARCO" class="btn-arco">
    📧 privacidad@dominio.cl
  </a>
</div>"""
    },
    "ARCO_INCOMPLETE": {
        "ticket_id": "TICK-ARC-02",
        "title": "Detallar procedimiento formal de atención de derechos ARCO",
        "summary": "Especificar en la política los plazos legales y requisitos para acreditar titularidad.",
        "directive": "Añadir a la política el protocolo que describa los requisitos del trámite: presentación de solicitud, plazo máximo de respuesta legal (15 días hábiles) y gratuidad del ejercicio.",
        "code_snippet": """// Protocolo de atención ARCO para documentar en la Política:
// 1. Canal de recepción: privacidad@dominio.cl
// 2. Información requerida: Nombre completo, RUT y derecho que desea ejercer (A, R, C u O).
// 3. Plazo máximo de resolución y respuesta: 15 días hábiles conforme a la Ley N° 21.719.
// 4. Costo: Procedimiento 100% gratuito para el titular."""
    },

    # -------------------------------------------------------------------------
    # 4. GESTOR DE CONSENTIMIENTO Y COOKIE BANNER (Art. 14 bis / RF-01)
    # -------------------------------------------------------------------------
    "BANNER_NO_REJECT": {
        "ticket_id": "TICK-CMP-01",
        "title": "Incorporar opción simétrica de rechazo en primer nivel del banner",
        "summary": "Garantizar que el titular pueda rechazar todas las cookies no esenciales con la misma facilidad que aceptarlas.",
        "directive": "Modificar la interfaz del banner de cookies agregando un botón 'Rechazar todo' o 'Solo necesarias' con la misma jerarquía visual que el botón 'Aceptar'.",
        "code_snippet": """<!-- Banner de consentimiento conforme a Ley 21.719 (HTML + JS) -->
<div id="cookie-banner" role="dialog" aria-label="Preferencias de privacidad">
  <p>Utilizamos cookies propias y de terceros para analítica. ¿Acepta su instalación?</p>
  <div class="banner-buttons">
    <button type="button" id="btn-accept-cookies" class="btn-primary">Aceptar todas</button>
    <button type="button" id="btn-reject-cookies" class="btn-secondary">Rechazar todas</button>
    <button type="button" id="btn-config-cookies" class="btn-link">Personalizar</button>
  </div>
</div>
<script>
  document.getElementById('btn-reject-cookies').addEventListener('click', function() {
    localStorage.setItem('cookie_consent', 'rejected');
    document.getElementById('cookie-banner').style.display = 'none';
  });
</script>"""
    },

    # -------------------------------------------------------------------------
    # 5. ACCESIBILIDAD PERIMETRAL / BLOQUEO WAF (FB-02)
    # -------------------------------------------------------------------------
    "WAF_PERIMETRAL_BLOCK": {
        "ticket_id": "TICK-WAF-01",
        "title": "Permitir inspección técnica pasiva de DataCheck en WAF/Cloudflare",
        "summary": "Configurar una regla en el firewall web para permitir cabeceras del agente auditor o verificar en entorno staging.",
        "directive": "Si este sitio requiere auditoría continua en producción, configure una regla de bypass o exclusión en Cloudflare/AWS WAF para el User-Agent institucional 'DataCheck.cl'.",
        "code_snippet": """# Regla de firewall recomendada (Cloudflare WAF Custom Rule / Expression):
(http.user_agent contains "DataCheck.cl" and ip.src in {IPS_AUTORIZADAS}) -> Action: Bypass (WAF)

# O bien verificar en servidor de preproducción:
curl -H "User-Agent: DataCheck.cl/2.0" https://sitio.cl/"""
    }
}


def get_remediation_ticket(ticket_key: str, context_info: Optional[str] = None) -> str:
    """
    Retorna el texto formateado del ticket técnico de remediación con fragmento de código.
    """
    ticket = REMEDIATION_TICKETS.get(ticket_key)
    if not ticket:
        return "Aplicar medidas técnicas de corrección conforme a los estándares de la Ley N° 21.719."

    lines = [
        f"[{ticket['ticket_id']}] {ticket['title']}: {ticket['summary']}",
        f"Directiva: {ticket['directive']}"
    ]
    if context_info:
        lines.append(f"Contexto técnico: {context_info}")

    snippet = ticket.get("code_snippet", "").strip()
    if snippet:
        lines.append(f"Snippet de implementación sugerida:\n{snippet}")

    return "\n\n".join(lines)
