# Matriz Oficial de Trazabilidad y Congelamiento de Requerimientos (DataCheck.cl)
**Versión:** 2.0 (Incremento 2 / Primera Defensa)  
**Normativa Referencial:** Ley N° 19.628 y Nueva Ley N° 21.719 sobre Protección de Datos Personales (Chile)  
**Estado:** CONGELADA Y AUDITADA (FB-05)

---

## 1. Alcance y Regla de Unificación de Identificadores

Conforme a las observaciones de retroalimentación docente (**FB-05**), se establece la presente matriz única como la fuente de verdad inmutable de requerimientos, eliminando toda discrepancia previa entre actas, tickets y documentación técnica.

### Definiciones Base:
* **RF (Requerimiento Funcional)**: Capacidades operativas y legales del sistema.
* **PBI (Product Backlog Item)**: Unidades de implementación técnica y desarrollo.
* **CA (Criterio de Aceptación)**: Condiciones verificables de satisfacción.
* **EVI / TEST (Evidencia Técnica)**: Suites de prueba automatizada y registros empíricos.

---

## 2. Matriz Consolidada de Trazabilidad Extremo a Extremo

| ID RF | Denominación Oficial | ID PBI | Descripción Técnica | Componente / Archivo | Criterios de Aceptación | Suite de Pruebas (EVI) |
|---|---|---|---|---|---|---|
| **RF-01** | Detección y catalogación de rastreadores y cookies pre-consentimiento | **PBI-01** | Motor de extracción headless con Playwright y captura de tráfico HTTP pasivo en red. | `src/scanner/inspector.py`<br/>`src/scanner/flow_inspector.py` | • Detección en modo solo lectura (`GET`).<br/>• Intercepción de scripts de terceros pre-consentimiento.<br/>• Detección de banners y Shadow DOM. | `tests/test_sanitizer.py`<br/>`tests/test_iframe_cmp.py`<br/>`tests/test_security_ssrf.py` |
| **RF-02** | Verificación de disponibilidad y contenido de Política de Privacidad | **PBI-02** | Verificador de enlaces en footer institucional, respuesta HTTP 200 y keywords obligatorias. | `src/scanner/inspector.py`<br/>`src/core/legal_catalog.py` | • Detección de enlaces canónicos `/privacidad`.<br/>• Validación de HTTP 200.<br/>• Verificación de deberes del responsable (Art. 14 ter). | `tests/test_rules_engine.py`<br/>`tests/test_responsible_party.py` |
| **RF-03** | Identificación de canales formales para ejercicio de derechos ARCO | **PBI-03** | Parser de correos dedicados (`mailto:`) y menciones explícitas de derechos ARCO. | `src/scanner/inspector.py`<br/>`src/scanner/remediation_catalog.py` | • Localización de email formal o formulario.<br/>• Mención expresa a Acceso, Rectificación, Cancelación, Oposición.<br/>• Generación de ticket con plantilla de código. | `tests/test_rules.py`<br/>`tests/test_rules_engine.py` |
| **RF-04** | Dictamen técnico determinista y reporte estructurado en PDF | **PBI-04** / **PBI-06** | Motor determinista ponderado (35/30/35) y compilador de informe legal descargable. | `src/scanner/rules_engine.py`<br/>`src/services/pdf_report_service.py` | • Veredictos: `APROBADO`, `CON_OBSERVACIONES`, `RECHAZADO`, `NO_ACCESIBLE`.<br/>• Compilación PDF < 3.0s y tamaño > 0 KB.<br/>• Sustento normativo de Ley 21.719 en cada hallazgo. | `tests/test_pdf_report.py`<br/>`tests/test_pdf_generation.py` |
| **RF-SEC** | Seguridad perimetral, resiliencia y mitigación de desvíos | **PBI-05** | Middleware de protección Anti-SSRF, timeout de 25s y neutralidad WAF. | `src/core/sanitizer.py`<br/>`src/api/routes/scan.py`<br/>`src/services/audit_service.py` | • Bloqueo de loopback, RFC 1918 y cloud metadata.<br/>• Límite temporal infranqueable de 24s/25s.<br/>• Estado neutro `NO_ACCESIBLE` ante Cloudflare/403/503. | `tests/test_security_ssrf.py`<br/>`tests/test_resilience_timeout.py`<br/>`tests/test_e2e_quality.py` |

---

## 3. Desglose Estandarizado de Product Backlog Items (PBI)

* **PBI-01**: *Motor de Extracción Headless y Captura de Tráfico HTTP*.
  * Ejecución en contenedor Chromium sin mutación de estado.
  * Captura asíncrona de eventos de red y cookies en el primer milisegundo pre-consentimiento.
* **PBI-02**: *Verificador de Accesibilidad de Políticas de Privacidad*.
  * Rastreo de hipervínculos en DOM principal y sub-marcos.
  * Verificación de código de estado HTTP 200 y búsqueda de vocabulario jurídico esencial.
* **PBI-03**: *Motor de Evaluación Determinista de Reglas (Ley 21.719)*.
  * Asignación matemática de ponderaciones: 35% Política, 30% ARCO, 35% Consentimiento.
  * Catálogo de tickets técnicos de remediación con fragmentos de código listos para producción.
* **PBI-04**: *Dashboard Web Interactivo con Semáforo y Visualización de Remediación*.
  * Interfaz accesible (Dark/Light mode) con anillo de puntaje SVG nativo.
  * Botón interactivo de copiado al portapapeles de tickets de remediación para desarrolladores.
* **PBI-05**: *Middleware de Seguridad Perimetral y Resiliencia Técnica*.
  * Validación estricta anti-SSRF (DNS resolution + filtro IP loopback/privada/cloud).
  * Control de timeout global con `force_close()` garantizando 0 procesos huérfanos.
  * Manejo neutro de bloqueos de WAF (`NO_ACCESIBLE` con hallazgo `ACCESIBILIDAD_PERIMETRAL`).
* **PBI-06**: *Generador Oficial de Reportes PDF con Sustento Legal*.
  * Generación en memoria con ReportLab en menos de 3.0 segundos.
  * Incorporación de artículos de la Ley 21.719, principios y sanciones estimadas ante la APDP.

---

## 4. Matriz de Evidencias Técnicas Verificables (EVI)

| Código | Evidencia Verificable | Test Suite Asociado | Métrica de Aceptación |
|---|---|---|---|
| **EVI-01** | Bloqueo absoluto de SSRF (IPv4/IPv6 privada, localhost, 169.254.169.254). | `tests/test_security_ssrf.py` | 100% de payloads maliciosos rechazados con HTTP 400. |
| **EVI-02** | Aborto garantizado de métodos no-GET en navegación Playwright. | `tests/test_security_ssrf.py` | Peticiones POST/PUT/DELETE abortadas con `blockedbyclient`. |
| **EVI-03** | Manejo de WAF/Cloudflare (HTTP 403/503) como veredicto neutro. | `tests/test_rules_engine.py`<br/>`tests/test_e2e_quality.py` | Veredicto `NO_ACCESIBLE` con puntaje 0 y ticket de bypass WAF. |
| **EVI-04** | Resiliencia temporal: Corte a los 24s y liberación de procesos. | `tests/test_resilience_timeout.py`<br/>`tests/test_e2e_quality.py` | Respuesta en $\le 25.0$ s y 0 procesos de Chromium activos. |
| **EVI-05** | Entrega de snippets de código ejecutables en 100% de tickets. | `tests/test_rules_engine.py` | Campo `remediation_ticket` no vacío con directiva y código. |
| **EVI-06** | Generación de informe PDF en $< 3.0$ s y peso $> 0$ KB. | `tests/test_pdf_report.py`<br/>`tests/test_pdf_generation.py` | Archivo binario `%PDF-` generado en buffer sin fallas de memoria. |
