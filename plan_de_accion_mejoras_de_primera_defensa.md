# Plan de Acción y Remediación Técnica - Primera Defensa (DataCheck.cl)

> **Contexto de Evaluación**: Taller de Desarrollo de Software (UCM)  
> **Resultado de Entrada**: Primera Demostración y Defensa (116 puntos / Nota 5.7)  
> **Objetivo**: Subsanar el 100% de las observaciones docentes (`FB-01` a `FB-06`) para asegurar la calificación máxima (7.0 / 140 puntos) en la entrega final.  
> **Período de Ejecución**: Semanas 7 a 9  

---

## 1. Matriz Resumen de Brechas y Asignación de Responsabilidades

| ID Brecha | Categoría Rúbrica | Causa Raíz Detectada | Acción Técnica Concreta | Responsable Principal | Revisor Par |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FB-01** | Seguridad y Privacidad (7.0 pts) | Ausencia de validación de IP de destino (vulnerabilidad SSRF) y falta de intercepción estricta para bloquear peticiones que no sean `HTTP GET`. | Middleware anti-SSRF + Bloqueador de métodos de red en Playwright. | **Benjamín Vidal** (Backend) | Franco Vela |
| **FB-02** | Comportamiento Funcional (7.0 pts) | El motor de reglas clasifica sitios bloqueados por WAF/Cloudflare (403/503) como `RECHAZADO` en lugar de `NO ACCESIBLE`. | Refactorizar `RulesEngine.evaluate()` integrando `page_load_status == 0` con salida neutra. | **Sofía Díaz** (Legal/Reglas) | Benjamín Vidal |
| **FB-03** | Calidad: Rendimiento y Resiliencia (7.0 pts) | Los reintentos y esperas de Playwright se acumulaban (25s + 15s + inspecciones secundarias), superando el umbral de 25 s. | `asyncio.wait_for` global de 25.0 s con cierre forzoso de contextos de Chromium. | **Franco Vela** (Scraping) | Benjamín Vidal |
| **FB-04** | Criterios de Aceptación: Recorrido Normal (7.0 pts) | Los reportes mostraban diagnósticos descriptivos sin código de remediación ni tickets listos para programadores. | Implementar generador de tickets técnicos de remediación (snippets de código y directivas GTM). | **Benjamín Rodríguez** (Frontend/UX) | Sofía Díaz |
| **FB-05** | Trazabilidad de Extremo a Extremo (7.0 pts) | Inconsistencia en identificadores documentales (`RF-01`/`RF-02` cambiaban de significado; `PBI-04` duplicado). | Congelar y alinear matriz documental en todo el repositorio (`EVI-01` -> `RF-01` -> `PBI-01`). | **Franco Vela** (Scraping) | Todo el equipo |
| **FB-06** | Pruebas y Verificación (7.0 pts) | Solo 2 pruebas unitarias de reglas entregadas; sin tests automatizados para Playwright, timeouts, WAF ni endpoints. | Suite integral con `pytest-asyncio` cubriendo timeouts, SSRF, WAF y el benchmark de 10 sitios. | **Benjamín Vidal** (DevOps) | Benjamín Rodríguez |

---

## 2. Desglose Detallado de Planes de Acción por Brecha

### Brecha FB-01: Seguridad, Mitigación de SSRF y Restricción "Solo GET"

* **Problema Evaluado**: La API aceptaba URLs arbitrarias permitiendo a Playwright navegar hacia `localhost`, IPs RFC1918 (`192.168.x.x`, `10.x.x.x`), loopback `127.0.0.1` o metadatos de nube (`169.254.169.254`). Además, scripts del sitio auditado podían disparar automáticamente peticiones POST/PUT sin que el inspector las abortara.
* **Archivos Afectados**:
  * `src/api/sanitizer.py`
  * `src/scanner/inspector.py`
  * `tests/test_security_ssrf.py`
* **Acciones de Implementación**:
  1. **Resolución DNS y Bloqueo de Redes Privadas**:
     * En `src/api/sanitizer.py`, resolver el nombre de dominio antes de llamar al scraper mediante `socket.gethostbyname()`.
     * Validar contra el módulo `ipaddress`: si la IP pertenece a `is_private`, `is_loopback`, `is_reserved`, `is_multicast` o `is_link_local`, lanzar inmediatamente `HTTP 400 Bad Request: Destino no permitido (red privada o interna)`.
  2. **Intercepción de Peticiones Salientes en Playwright (Abort Non-GET)**:
     * En `src/scanner/inspector.py`, configurar un route interceptor:
       ```python
       async def block_non_get(route, request):
           if request.method != "GET":
               await route.abort("blockedbyclient")
           else:
               await route.continue_()
       
       await page.route("**/*", block_non_get)
       ```
* **Criterio de Aceptación Verificable**:
  * Prueba automatizada `test_ssrf_protection()` verifica que `http://127.0.0.1`, `http://localhost:8000` y `http://169.254.169.254` sean rechazados en $< 100$ ms con código 400.
  * Prueba con servidor mock local que comprueba que un script que intente hacer `fetch('/api', {method: 'POST'})` sea abortado inmediatamente por el navegador.

---

### Brecha FB-02: Manejo de WAF/Cloudflare y Errores HTTP (Desvío D-01)

* **Problema Evaluado**: Cuando un sitio retornaba HTTP 403 o desafío CAPTCHA, el motor de reglas evaluaba la ausencia de políticas y cookies como un incumplimiento legal, emitiendo veredicto `RECHAZADO` con puntaje bajo, en vez de reportar que el sitio no pudo ser inspeccionado.
* **Archivos Afectados**:
  * `src/scanner/inspector.py`
  * `src/engine/rules_engine.py`
  * `tests/test_waf_handling.py`
* **Acciones de Implementación**:
  1. **Captura Estricta en el Inspector**:
     * Si la respuesta de la navegación inicial devuelve status `403`, `503` o detecta selectores típicos de Cloudflare/Cloudfront challenge, fijar `page_load_status = 0` y `error_message = "BLOQUEO_WAF_ANTIBOT"`.
  2. **Ajuste en el Motor de Reglas (`rules_engine.py`)**:
     * Modificar la cabecera de `evaluate()`:
       ```python
       if inspection_data.get("page_load_status") == 0:
           return ScanResponse(
               target_url=inspection_data["target_url"],
               page_load_status=0,
               verdict="NO_ACCESIBLE", # Estado neutro no sancionatorio
               score=0,
               verdict_summary="Sitio no accesible para análisis técnico pasivo.",
               pilares={},
               findings=[
                   FindingDTO(
                       pilar="ACCESIBILIDAD_PERIMETRAL",
                       status="WARNING",
                       title="Inspección Externa Bloqueada",
                       detail="El sitio web cuenta con un firewall de aplicaciones web (WAF) que impidió la auditoría pasiva.",
                       recommendation="Para auditar este sitio, configure una regla temporal que permita las cabeceras de DataCheck o utilice el informe asistido."
                   )
               ]
           )
       ```
* **Criterio de Aceptación Verificable**:
  * Prueba `test_waf_returns_no_accesible()` simula una respuesta 403 y comprueba que el veredicto sea `NO_ACCESIBLE` (no `RECHAZADO`).

---

### Brecha FB-03: Control de Timeout Infranqueable de 25 Segundos

* **Problema Evaluado**: El inspector sumaba tiempos acumulativos (navegación primaria 25s, fallback 15s, navegación secundaria a la política 10s), llegando a tardar más de 45 segundos en páginas caídas.
* **Archivos Afectados**:
  * `src/api/routes/scan.py`
  * `src/scanner/inspector.py`
  * `tests/test_timeout.py`
* **Acciones de Implementación**:
  1. **Límite Asíncrono Global**:
     * Envolver toda la rutina de extracción bajo un único temporizador que gobierne el ciclo completo:
       ```python
       try:
           raw_data = await asyncio.wait_for(
               inspector.scan_url(url), 
               timeout=24.0 # margen de 1 segundo para serialización y respuesta
           )
       except asyncio.TimeoutError:
           await inspector.force_close() # Cierre garantizado del contexto de Chromium
           return build_timeout_response(url)
       ```
  2. **Eliminación de Reintentos Lentos**:
     * Remover la cascada de reintentos con esperas ciegas. Si la URL falla tras el tiempo establecido, fallar inmediatamente por timeout controlado.
* **Criterio de Aceptación Verificable**:
  * Prueba `test_timeout_strict_under_25s()` contra un servidor local configurado con un retardo de 40 s. La API responde en exactamente $24.5 \pm 0.5$ segundos con código 200 y `page_load_status = 0`, dejando 0 procesos Chromium huérfanos.

---

### Brecha FB-04: Tickets Técnicos de Remediación con Snippets de Código

* **Problema Evaluado**: Los hallazgos se limitaban a describir la falta ("Se detectó cookie _ga"), pero no entregaban al desarrollador la solución técnica concreta prometida en la propuesta de valor.
* **Archivos Afectados**:
  * `src/engine/rules_engine.py`
  * `src/engine/remediation_catalog.py` (Nuevo)
  * `src/ui/app.js` e `index.html`
* **Acciones de Implementación**:
  1. **Catálogo de Tickets de Remediación**:
     * Crear `src/engine/remediation_catalog.py` asociando cada incumplimiento a un ticket técnico estructurado:
       * **Trackers sin consentimiento previo**: Instrucción para configurar el trigger condicional en Google Tag Manager (GTM) vinculado al evento `cookie_consent_accepted`.
       * **Enlace a política roto (404/500)**: Instrucción para configurar ruta canónica en `/privacidad` con status HTTP 200 en el router web.
       * **Ausencia de canal ARCO**: Plantilla de bloque HTML para pie de página con selector semántico `mailto:privacidad@dominio.cl` y texto visible.
  2. **Visualización en Dashboard Frontend**:
     * Diseñar una tarjeta colapsable tipo ticket de Jira/GitHub en la interfaz con botón "Copiar Instrucción de Remediación" y visualización de snippet con resaltado de código.
* **Criterio de Aceptación Verificable**:
  * En una auditoría con fallas, el 100% de los ítems en `findings[]` contienen el campo `remediation_ticket` no vacío con al menos un fragmento o directiva de código.

---

### Brecha FB-05: Estandarización y Congelamiento de Trazabilidad

* **Problema Evaluado**: Desajuste entre definiciones iniciales y tablas posteriores (`RF-01`/`RF-02` cambiaban entre cookies y políticas; `PBI-04` aparecía duplicado con dos propósitos distintos).
* **Archivos Afectados**:
  * `docs/trazabilidad_matriz.md`
  * `Semana 6 - Guía de trabajo`
  * Diapositivas de presentación de defensa
* **Acciones de Implementación**:
  1. **Fijar Diccionario Único e Inmutable**:
     * `RF-01`: Detección pasiva de cookies y rastreadores de terceros antes del consentimiento.
     * `RF-02`: Detección, validación de selector y estado HTTP 200 de la política de privacidad.
     * `RF-03`: Detección y verificación de canales de contacto de derechos ARCO.
     * `RF-04`: Generación de veredicto normativo y tickets técnicos de remediación.
     * `PBI-01`: Motor de extracción headless con Playwright y captura de tráfico HTTP.
     * `PBI-02`: Verificador de accesibilidad y enlaces a políticas de privacidad.
     * `PBI-03`: Motor de evaluación determinista de reglas de la Ley 21.719.
     * `PBI-04`: Dashboard web interactivo con semáforo y visualización de remediación.
     * `PBI-05`: Middleware de seguridad (SSRF, timeout de 25s y desvío WAF).
     * `PBI-06`: Generador y descargador de reportes en PDF con sustento legal.
* **Criterio de Aceptación Verificable**:
  * Verificación automatizada con script de linter documental asegurando que no existan discrepancias de IDs en los archivos `.md` del proyecto.

---

### Brecha FB-06: Cobertura de Pruebas Automatizadas y Benchmark de 10 Sitios

* **Problema Evaluado**: Se entregaron solo 2 pruebas unitarias de reglas sin comprobación ejecutable de la integración real ni evidencia del cumplimiento del umbral $<15\%$ de falsos positivos.
* **Archivos Afectados**:
  * Carpeta `tests/` completa
  * `.github/workflows/ci.yml`
  * `docs/benchmark_10_sitios.md` (Nuevo reporte de evidencia)
* **Acciones de Implementación**:
  1. **Desarrollo de Suite Integral de Tests**:
     * `test_sanitizer.py`: 5 casos probando limpieza de query strings, credenciales embebidas y rechazo de protocolos inválidos.
     * `test_security_ssrf.py`: 4 casos verificando bloqueo de IPs privadas y localhost.
     * `test_rules_engine.py`: 6 casos cubriendo Aprobado (0 trackers, política OK), Rechazado (trackers activos), No accesible (WAF 403), y enlaces rotos (404).
     * `test_resilience_timeout.py`: 2 casos con servidor mock verificando corte a los 25 segundos exactos.
     * `test_pdf_report.py`: 3 casos verificando compilación de PDF $> 0$ KB, tiempo $< 3$ s y rechazo ante auditorías vacías.
  2. **Ejecución y Registro del Benchmark (Muestra de 10 Sitios)**:
     * Auditar 10 sitios chilenos reales de e-commerce e instituciones públicas.
     * Generar matriz de confusión (Auditoría Manual de 2 integrantes vs. Resultado del Sistema).
     * Calcular y documentar formalmente la tasa de falsos positivos asegurando que sea $< 10\%$.
* **Criterio de Aceptación Verificable**:
  * Ejecución exitosa de `pytest -v tests/` pasando al menos 20 pruebas en el pipeline de GitHub Actions en $< 2$ minutos.

---

## 3. Cronograma de Construcción y Verificación (Semanas 7 a 9)

```
Semana 7: Seguridad, Resiliencia y Desvíos
├── [Día 1-2] Middleware Anti-SSRF y filtro estricto "Solo GET" (Benjamín Vidal) [FB-01]
├── [Día 3-4] Timeout infranqueable de 25 s y manejo neutro de WAF en RulesEngine (Franco Vela / Sofía Díaz) [FB-02, FB-03]
└── [Día 5] PR #18 con pruebas de integración de seguridad y resiliencia (Revisión par cruzada)

Semana 8: Tickets de Remediación, PDF y Trazabilidad
├── [Día 1-2] Catálogo de tickets de código y renderizado en UI de remediación (Benjamín Rodríguez) [FB-04]
├── [Día 3-4] Generador de reportes PDF normativos con sustento de Ley 21.719 (Benjamín Vidal)
└── [Día 5] Auditoría y congelamiento de identificadores en documentación y código (Franco Vela) [FB-05]

Semana 9: QA Automatizado, Benchmark y Ensayo Final
├── [Día 1-2] Ejecución de suite de 20+ pruebas automatizadas en CI/CD (Benjamín Vidal) [FB-06]
├── [Día 3] Ejecución del Benchmark sobre 10 sitios reales y cálculo de métricas (Todo el equipo) [FB-06]
└── [Día 4-5] Ensayo cronometrado de defensa con la presentación actualizada y demostración en vivo.
```

---

## 4. Definición de Hecho (Definition of Done) para la Defensa Final

Para considerar cerrado el plan de acción y garantizar la nota 7.0:
1. **Zero SSRF**: Comprobado que ninguna URL de red local o servicio interno pueda ser invocada desde la API.
2. **Resiliencia Demostrada**: Toda petición a sitios caídos o lentos responde en un máximo de 25 segundos sin procesos huérfanos.
3. **Manejo de WAF Coherente**: Sitios con Cloudflare devuelven `NO_ACCESIBLE` con recomendación técnica, sin marcar una falsa infracción legal.
4. **Tickets Accionables**: El reporte incluye fragmentos de código listos para implementar por el equipo técnico.
5. **Suite de Pruebas Reproducible**: El comando `pytest` ejecuta y aprueba todas las pruebas de integración dentro del contenedor Docker.