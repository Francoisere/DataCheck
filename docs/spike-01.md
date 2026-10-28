# SPIKE-01: Evaluación de Evasión Pasiva de WAF/Cloudflare y Límite de Timeout en Escaneo Pasivo

- **Identificador:** SPIKE-01 (asociado a RP-01 y DA-01)
- **Fecha de ejecución:** Viernes 09 de octubre de 2026 (Actualizado con prueba en vivo: Octubre 2026)
- **Responsable de ejecución:** Franco Vela (Motor web y Scraping)
- **Revisor técnico:** Benjamín Rodríguez (Dueño del riesgo anti-bot)
- **Estado:** Completado — Decisión arquitectónica adoptada y validada en producción

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
   - **Alternativa B (Producción):** Playwright headless con **User-Agent legítimo de navegador moderno fijo** (Chrome 124) con identificación académica (`DataCheck.cl/2.0; Academic Privacy Audit`), supresión nativa de marcas de automatización (`--disable-blink-features=AutomationControlled`) y pausas de estabilización de 1.5 segundos (respetando el límite estricto de 25 s).
   - **Alternativa C:** `httpx.AsyncClient` sin motor de renderizado JavaScript (línea base estática para medir latencia y evaluar pérdida de visibilidad en SPAs/CMPs).
4. **Justificación técnica del flag `--disable-blink-features=AutomationControlled`:**
   - Es una directiva de lanzamiento estándar del motor Chromium que suprime la exposición de la variable `navigator.webdriver = true` en el entorno JavaScript.
   - **No constituye un plugin stealth invasivo ni altera el DOM:** a diferencia de extensiones que interceptan o modifican respuestas del servidor, esta opción simplemente ejecuta el motor Chromium con su comportamiento de renderizado natural, permitiendo que sitios legítimos respondan con su contenido público sin disparar falsas alarmas de bot malicioso, en estricto apego a DA-01 (inspección pasiva de caja negra) y a la Ley 21.459 de Delitos Informáticos.
5. **Aclaración de Hosts evaluados (Banco de Chile):**
   - El SPIKE-01 evaluó el subportal público institucional `https://portales.bancochile.cl`.
   - El Benchmark de 10 sitios evaluó el portal corporativo raíz `https://www.bancochile.cl`, el cual aplica un filtrado perimetral WAF estricto con HTTP 403, clasificando deterministamente como `NO_ACCESIBLE` según el desvío D-01.
6. **Restricciones innegociables (DA-01, DA-04, Ley 21.459):**
   - 0 envíos de formularios (`fill`, `submit`), 0 clics en elementos activos del sitio.
   - 0 resolución manual o por bypass de desafíos CAPTCHA.
   - Máximo 1 escaneo por sitio por minuto para evitar sobrecarga o denegación de servicio.

---

## 3. Tabla comparativa de resultados

La siguiente matriz documenta las mediciones obtenidas mediante el script reproducible [`tests/spike_waf.py`](../tests/spike_waf.py), contrastando las mediciones en vivo con los valores de referencia reproducibles de laboratorio registrados en [`docs/spike_waf_execution.log`](./spike_waf_execution.log):

### A. Mediciones en Vivo (`tests/spike_waf.py --live`)

| URL / Sitio | Alternativa evaluada | Código HTTP | ¿Cargó exitosamente? | Tiempo total (s) | ¿Enlace de privacidad detectado? | ¿Rastreadores capturados? | Observación técnica |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `https://www.falabella.com` | **A** (Bot UA) | 200 | Sí | 3.12 s | Sí | Sí | Carga exitosa pero sujeta a variabilidad WAF. |
| `https://www.falabella.com` | **B** (Legit UA fijo + delay) | **200** | **Sí** | **4.13 s** | **Sí** | **Sí** | Carga completa del DOM, CMP OneTrust y cookies de rastreo detectadas. |
| `https://www.falabella.com` | **C** (httpx sin JS) | 200 | Sí | 0.26 s | Sí | No | HTML inicial sin ejecución de scripts ni detección de cookies. |
| `https://simple.ripley.cl` | **A** (Bot UA) | 200 | Sí | 1.94 s | Sí | No | Akamai permite HTML básico pero bloquea trackers secundarios. |
| `https://simple.ripley.cl` | **B** (Legit UA fijo + delay) | **200** | **Sí** | **3.29 s** | **Sí** | **Sí** | Renderizado exitoso, captura de scripts pre-consentimiento. |
| `https://simple.ripley.cl` | **C** (httpx sin JS) | 403 | No | 0.12 s | No | Sí | Bloqueo perimetral Akamai a cliente Python HTTP crudo. |
| `https://www.paris.cl` | **A** (Bot UA) | 200 | Sí | 2.70 s | Sí | Sí | Conexión admitida. |
| `https://www.paris.cl` | **B** (Legit UA fijo + delay) | **200** | **Sí** | **4.33 s** | **Sí** | **Sí** | Peticiones de rastreo capturadas antes del banner. |
| `https://www.paris.cl` | **C** (httpx sin JS) | 200 | Sí | 1.40 s | Sí | Sí | Entrega HTML parcial. |
| `https://portales.bancochile.cl` | **A** (Bot UA) | 503 | No | 1.01 s | No | No | Bloqueo perimetral Cloudflare / F5 Challenge. |
| `https://portales.bancochile.cl` | **B** (Legit UA fijo + delay) | 503 | No | 2.57 s | No | No | **Desvío D-01**: WAF Challenge activo; retorna neutro NO_ACCESIBLE sin colapso. |
| `https://portales.bancochile.cl` | **C** (httpx sin JS) | 503 | No | 0.09 s | No | No | Bloqueo perimetral HTTP 503. |
| `https://www.latamairlines.com` | **A** (Bot UA) | 403 | No | 0.96 s | No | No | Bloqueo perimetral inmediato Cloudflare por cabecera de bot. |
| `https://www.latamairlines.com` | **B** (Legit UA fijo + delay) | **200** | **Sí** | **4.47 s** | **Sí** | **Sí** | **Superación de Cloudflare**: Carga exitosa y captura de trackers sin bypass invasivo. |
| `https://www.latamairlines.com` | **C** (httpx sin JS) | 403 | No | 0.07 s | No | No | Bloqueo perimetral HTTP 403. |
| `https://www.gob.cl` *(Control)* | **A** (Bot UA) | 200 | Sí | 2.73 s | No | Sí | Sin WAF agresivo. |
| `https://www.gob.cl` *(Control)* | **B** (Legit UA fijo + delay) | **200** | **Sí** | **4.45 s** | **No** | **Sí** | Carga limpia y clasificación de pilares normativos. |
| `https://www.gob.cl` *(Control)* | **C** (httpx sin JS) | 200 | Sí | 0.69 s | No | Sí | Pierde cookies dinámicas renderizadas en cliente. |
| `https://www.uchile.cl` *(Control)* | **A** (Bot UA) | 200 | Sí | 1.64 s | Sí | Sí | Carga exitosa. |
| `https://www.uchile.cl` *(Control)* | **B** (Legit UA fijo + delay) | **200** | **Sí** | **3.30 s** | **Sí** | **Sí** | Carga limpia y detección de rastreadores analíticos. |
| `https://www.uchile.cl` *(Control)* | **C** (httpx sin JS) | 200 | Sí | 0.13 s | Sí | Sí | Ciego a cookies inyectadas por scripts externos. |

### B. Valores de Referencia Reproducibles de Laboratorio (Línea Base)

| URL / Sitio | Alternativa B (Legit UA fijo + delay) | Código HTTP | ¿Cargó exitosamente? | Tiempo medido (s) |
| :--- | :--- | :---: | :---: | :---: |
| `https://www.falabella.com` | Chrome 124 legítimo + delay 1.5s | 200 | Sí | 11.42 s |
| `https://simple.ripley.cl` | Chrome 124 legítimo + delay 1.5s | 200 | Sí | 13.10 s |
| `https://www.paris.cl` | Chrome 124 legítimo + delay 1.5s | 200 | Sí | 9.85 s |
| `https://portales.bancochile.cl` | Chrome 124 legítimo + delay 1.5s | 200 | Sí | 14.60 s |
| `https://www.latamairlines.com` | Chrome 124 legítimo + delay 1.5s | 0 (Corte Timeout 25s) | No (D-01) | 25.00 s |
| `https://www.gob.cl` *(Control)* | Chrome 124 legítimo + delay 1.5s | 200 | Sí | 5.25 s |
| `https://www.uchile.cl` *(Control)* | Chrome 124 legítimo + delay 1.5s | 200 | Sí | 7.90 s |

---

## 4. Análisis de hallazgos

1. **Inviabilidad de la Alternativa A (`AuditBot/1.0`):**
   - Los sitios corporativos con WAF estricto (como LATAM Airlines o subportales bancarios) rechazan de inmediato la conexión al detectar cadenas de User-Agent automatizadas sin emulación adecuada.
2. **Efectividad comprobada de la Alternativa B:**
   - La emulación con User-Agent legítimo fijo (Chrome 124) y pausas de 1.5 segundos logró analizar con éxito **4 de los 5 sitios protegidos por WAF (80%)** y el **100% de los sitios de control**, manteniendo el tiempo de respuesta muy por debajo del umbral de 25 segundos (mediana en vivo de 4.13 s y mediana de referencia de 11.4 s).
3. **Limitación estructural de la Alternativa C (`httpx` sin renderizado):**
   - Aunque presenta una latencia inferior a 1 segundo, no ejecuta JavaScript, no captura eventos de red asíncronos y resulta completamente ciega a plataformas de consentimiento (CMPs) renderizadas en el cliente.
4. **Comportamiento ante desafíos irrecuperables (D-01):**
   - Cuando un sitio impone un desafío interactivo irrecuperable por vía pasiva (WAF 503 o reto Cloudflare interactivo), el sistema no colapsa: el timeout estricto de 25 s corta la navegación, limpia los procesos Chromium y entrega limpiamente el desvío D-01 (*"Sitio no accesible para análisis técnico pasivo"*), sin emitir un falso veredicto de cumplimiento ni dejar procesos zombis en el servidor.

---

## 5. Conclusión formal y decisión arquitectónica

Conforme al criterio de aceptación establecido en la Sección 17:
> *Al lograr la Alternativa B analizar exitosamente ≥ 4 de los 5 sitios protegidos en ≤ 25 segundos, se adopta formalmente esta configuración y se da por mitigado el Riesgo RP-01.*

### Acciones adoptadas en la base de código (`cambios-de-franco`):
1. **Adopción de Configuración B en `src/scanner/inspector.py`:**
   - Cabecera fija estándar con User-Agent legítimo de navegador moderno y leyenda académica de auditoría: `Mozilla/5.0 ... Chrome/124.0.0.0 Safari/537.36 (DataCheck.cl/2.0; Academic Privacy Audit)`.
   - Argumento nativo Chromium `--disable-blink-features=AutomationControlled` para emulación pasiva limpia sin banderas de automatización en `navigator.webdriver`.
2. **Límite forzado de 25 segundos:**
   - Implementado mediante `asyncio.wait_for` envolviendo la rutina `_execute_scan` en `WebInspector.scan_url` con corte y `force_close`.
3. **Activación de Desvío D-01:**
   - Ante errores HTTP 403/503 o cortes por timeout, el sistema devuelve `page_load_status = 0`, informando al usuario que el sitio no es accesible sin emitir puntajes erróneos.
4. **Preservación de DA-01:**
   - Se mantiene la restricción estricta de 0 clics, 0 fills y 0 métodos distintos de GET, asegurando pleno apego a la Ley 21.459 de Delitos Informáticos.
