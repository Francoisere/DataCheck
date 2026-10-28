# SPIKE-01: Evaluación de Evasión Pasiva de WAF/Cloudflare y Límite de Timeout en Escaneo Pasivo

- **Identificador:** SPIKE-01 (asociado a RP-01 y DA-01)
- **Fecha de ejecución:** Viernes 09 de octubre de 2026
- **Responsable de ejecución:** Franco Vela (Motor web y Scraping)
- **Revisor técnico:** Benjamín Rodríguez (Dueño del riesgo anti-bot)
- **Estado:** Completado — Decisión arquitectónica adoptada

---

## 1. Pregunta rectora y objetivo

> **¿Puede el inspector con Playwright headless, utilizando únicamente peticiones HTTP GET públicas, cargar y analizar sitios protegidos por WAF o Cloudflare en menos de 25 segundos, garantizando el cumplimiento estricto de la Ley 21.459 y el principio de Privacy by Design?**

El propósito de este Spike técnico es reducir la incertidumbre identificada en la retrospectiva sobre la viabilidad de realizar auditorías de caja negra contra sitios web corporativos que emplean servicios perimetrales de protección anti-bot (Cloudflare, Akamai, F5 BIG-IP, Imperva) sin recurrir a técnicas intrusivas prohibidas (resuelve CAPTCHAs, proxys residenciales forzados o inyección de scripts).

---

## 2. Límite y condiciones de frontera

1. **Tiempo de ejecución:** Sesión única acotada a 3 horas de experimentación.
2. **Muestra evaluada:** 5 sitios chilenos reales con defensas WAF/Cloudflare comprobadas y 2 sitios institucionales de control sin protecciones agresivas.
3. **Alternativas técnicas comparadas:**
   - **Alternativa A:** Playwright headless con el User-Agent bot explícito (`AuditBot/1.0 (+https://datacheck.cl)`).
   - **Alternativa B:** Playwright headless con rotación de User-Agents legítimos modernos de escritorio (Chrome/Firefox/Edge) y pausas de estabilización controladas de 1 a 3 segundos (respetando el límite de 25 s).
   - **Alternativa C:** `httpx.AsyncClient` sin motor de renderizado JavaScript (línea base estática para medir latencia y evaluar pérdida de visibilidad en SPAs/CMPs).
4. **Restricciones innegociables (DA-01, DA-04, Ley 21.459):**
   - 0 envíos de formularios (`fill`, `submit`), 0 clics en elementos activos del sitio.
   - 0 resolución manual o por bypass de desafíos CAPTCHA.
   - Máximo 1 escaneo por sitio por minuto para evitar sobrecarga o denegación de servicio.

---

## 3. Tabla comparativa de resultados

La siguiente matriz documenta las mediciones obtenidas mediante el script reproducible [`tests/spike_waf.py`](../tests/spike_waf.py) y verificadas en el log de ejecución reproducible [`docs/spike_waf_execution.log`](./spike_waf_execution.log):

| URL / Sitio | Alternativa evaluada | Código HTTP | ¿Cargó exitosamente? | Tiempo total (s) | ¿Enlace de privacidad detectado? | ¿Rastreadores capturados? | Observación técnica |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `https://www.falabella.com` | **A** (Bot UA) | 403 | No | 2.15 s | No | No | Bloqueo perimetral inmediato Cloudflare por cabecera de bot. |
| `https://www.falabella.com` | **B** (Legit UA + delay) | **200** | **Sí** | **11.42 s** | **Sí** | **Sí** | Carga completa del DOM, CMP OneTrust identificado y cookies `_ga`/`_fbp`. |
| `https://www.falabella.com` | **C** (httpx sin JS) | 403 | No | 0.85 s | No | No | WAF bloquea cliente Python estándar; ciego a la página. |
| `https://simple.ripley.cl` | **A** (Bot UA) | 403 | No | 1.90 s | No | No | Bloqueo por Akamai Bot Manager. |
| `https://simple.ripley.cl` | **B** (Legit UA + delay) | **200** | **Sí** | **13.10 s** | **Sí** | **Sí** | Renderizado exitoso, captura de scripts pre-consentimiento. |
| `https://simple.ripley.cl` | **C** (httpx sin JS) | 403 | No | 0.92 s | No | No | Bloqueo HTTP 403. |
| `https://www.paris.cl` | **A** (Bot UA) | 503 | No | 3.40 s | No | No | Desafío de JavaScript Cloudflare no resuelto. |
| `https://www.paris.cl` | **B** (Legit UA + delay) | **200** | **Sí** | **9.85 s** | **Sí** | **Sí** | Peticiones de rastreo capturadas antes del banner. |
| `https://www.paris.cl` | **C** (httpx sin JS) | 503 | No | 0.78 s | No | No | Respuesta 503 Service Temporarily Unavailable. |
| `https://portales.bancochile.cl` | **A** (Bot UA) | 403 | No | 2.80 s | No | No | Bloqueo por regla F5 ASM. |
| `https://portales.bancochile.cl` | **B** (Legit UA + delay) | **200** | **Sí** | **14.60 s** | **Sí** | **Sí** | Política de privacidad y canales de contacto detectados correctamente. |
| `https://portales.bancochile.cl` | **C** (httpx sin JS) | 200 | Sí | 1.10 s | No | No | Entrega HTML vacío inicial de SPA; ciego a componentes React. |
| `https://www.latamairlines.com` | **A** (Bot UA) | 403 | No | 2.30 s | No | No | Bloqueo perimetral. |
| `https://www.latamairlines.com` | **B** (Legit UA + delay) | 0 | No | 25.00 s | No | No | **Corte controlado por timeout (DA-02)**: Cloudflare Managed Challenge interactivo; deriva a D-01. |
| `https://www.latamairlines.com` | **C** (httpx sin JS) | 403 | No | 0.95 s | No | No | Bloqueo HTTP 403. |
| `https://www.gob.cl` *(Control)* | **A** (Bot UA) | 200 | Sí | 4.10 s | Sí | Sí | Sin WAF agresivo; inspección exitosa con bot declarado. |
| `https://www.gob.cl` *(Control)* | **B** (Legit UA + delay) | **200** | **Sí** | **5.25 s** | **Sí** | **Sí** | Carga limpia y clasificación de pilares normativos. |
| `https://www.gob.cl` *(Control)* | **C** (httpx sin JS) | 200 | Sí | 0.45 s | Sí | No | Detecta política en HTML crudo pero pierde cookies dinámicas. |
| `https://www.uchile.cl` *(Control)* | **A** (Bot UA) | 200 | Sí | 6.80 s | Sí | Sí | Carga exitosa. |
| `https://www.uchile.cl` *(Control)* | **B** (Legit UA + delay) | **200** | **Sí** | **7.90 s** | **Sí** | **Sí** | Carga limpia y detección de rastreadores analíticos. |
| `https://www.uchile.cl` *(Control)* | **C** (httpx sin JS) | 200 | Sí | 0.60 s | Sí | No | Ciego a cookies inyectadas por scripts externos. |

---

## 4. Análisis de hallazgos

1. **Inviabilidad de la Alternativa A (`AuditBot/1.0`):**
   - El 80% (4 de 5) de los sitios corporativos con WAF rechazan de inmediato la conexión al detectar cadenas de User-Agent automatizadas, arrojando códigos HTTP 403/503.
2. **Efectividad comprobada de la Alternativa B:**
   - La emulación de navegación legítima (Chrome 124 sobre Windows/macOS con pausas de estabilización de 1 a 3 segundos) logró analizar con éxito **4 de los 5 sitios protegidos por WAF (80%)** y el **100% de los sitios de control**, manteniendo el tiempo de respuesta muy por debajo del umbral de 25 segundos (mediana de 11.4 s).
3. **Limitación estructural de la Alternativa C (`httpx` sin renderizado):**
   - Aunque presenta una latencia inferior a 1 segundo, no ejecuta JavaScript, lo que impide detectar Single Page Applications (React/Angular), no captura eventos de red asíncronos y resulta completamente ciega a plataformas de consentimiento (CMPs) renderizadas en el cliente.
4. **Comportamiento ante desafíos irrecuperables (LATAM):**
   - Cuando un sitio impone un desafío CAPTCHA interactivo gestionado por Cloudflare, el sistema no colapsa: el timeout estricto de 25 s corta la navegación, limpia los procesos Chromium y entrega limpiamente el desvío D-01 (*"Sitio no accesible para análisis"*), sin emitir un falso veredicto de cumplimiento ni dejar procesos zombis en el servidor.

---

## 5. Conclusión formal y decisión arquitectónica

Conforme al criterio de aceptación establecido en la Sección 17:
> *Al lograr la Alternativa B analizar exitosamente ≥ 4 de los 5 sitios protegidos en ≤ 25 segundos, se adopta formalmente esta configuración y se da por mitigado el Riesgo RP-01.*

### Acciones adoptadas en la base de código:
1. **Adopción de Configuración B en `src/scanner/inspector.py`:**
   - Configuración de cabeceras de navegación estándar con User-Agent legítimo de navegador moderno y leyenda académica de auditoría.
   - Argumento Chromium `--disable-blink-features=AutomationControlled` para emulación pasiva limpia.
2. **Límite forzado de 25 segundos:**
   - Implementado mediante `asyncio.wait_for` envolviendo la rutina `_execute_scan` en `WebInspector.scan_url`.
3. **Activación de Desvío D-01:**
   - Ante errores HTTP 403/503 o cortes por timeout, el sistema devuelve `page_load_status = 0`, informando al usuario que el sitio no es accesible sin emitir puntajes erróneos.
4. **Preservación de DA-01:**
   - Se mantiene la restricción estricta de 0 clics, 0 fills y 0 métodos distintos de GET, asegurando pleno apego a la Ley 21.459 de Delitos Informáticos.
