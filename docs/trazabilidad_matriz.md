# Matriz Oficial de Trazabilidad y Congelamiento de Requerimientos (DataCheck.cl)
**Versión:** 2.0 (Incremento 1 y 2 / Segunda Defensa)  
**Normativa Referencial:** Ley N° 19.628 y Nueva Ley N° 21.719 sobre Protección de Datos Personales (Chile)  
**Estado:** CONGELADA Y AUDITADA (FB-05)

---

## 1. Alcance y Regla de Unificación de Identificadores

Conforme a las observaciones de retroalimentación (**FB-05**), se establece la presente matriz única como la fuente de verdad inmutable de requerimientos, eliminando toda discrepancia previa entre actas, tickets y documentación técnica.

### Definiciones Base:
* **RF (Requerimiento Funcional)**: Capacidades operativas y legales del sistema.
* **PBI (Product Backlog Item)**: Unidades de implementación técnica y desarrollo.
* **AC (Criterio de Aceptación)**: Condiciones verificables de satisfacción.
* **EVI / TEST (Evidencia Técnica)**: Suites de prueba automatizada y registros empíricos.

---

## 2. Matriz Consolidada de Trazabilidad Extremo a Extremo

| ID RF | Denominación Oficial | ID PBI | Descripción Técnica | Componente / Archivo | Criterios de Aceptación | Suite de Pruebas (EVI) |
|---|---|---|---|---|---|---|
| **RF-01** | Detección y catalogación de rastreadores y cookies pre-consentimiento | **PBI-01** | Motor de extracción headless con Playwright y captura de tráfico HTTP pasivo en red. | `src/scanner/inspector.py` | • Detección en modo solo lectura (`GET`).<br/>• Intercepción de scripts de terceros pre-consentimiento.<br/>• Clasificación por dominios y cookies no esenciales. | `tests/test_sanitizer.py`<br/>`tests/test_sanitization.py`<br/>`tests/test_security_ssrf.py` |
| **RF-02** | Detección de gestores de consentimiento (CMP) y Shadow DOM | **PBI-02** | Inspección de iframes de terceros y árboles Shadow DOM (open/closed) para auditar banners. | `src/scanner/consent_detector.py` | • Detección de botones de aceptación y rechazo.<br/>• Identificación de banners de 2 pasos.<br/>• Evaluación de Shadow DOM cerrado. | `tests/test_iframe_cmp.py` |
| **RF-03** | Generación de catálogo normativo de tickets técnicos de remediación | **PBI-03** | Catálogo estructurado de remediación con fragmentos de código listos para producción. | `src/scanner/remediation_catalog.py` | • Códigos de tickets (`TICK-TRK-01`, `TICK-POL-01`, etc.).<br/>• Pautas técnicas de corrección inmediata.<br/>• Sustento en Ley 21.719. | `tests/test_rules.py`<br/>`tests/test_legal_catalog.py` |
| **RF-04** | Generación y exportación de reporte técnico en formato PDF | **PBI-04** | Compilación de informes PDF descargables en memoria con ReportLab con paridad visual. | `src/services/pdf_report_service.py`<br/>`src/api/routes/reports.py` | • Compilación en < 3.0 s.<br/>• Paridad visual con hallazgos, banners y responsable.<br/>• Botón deshabilitado antes de auditar. | `tests/test_pdf_report.py`<br/>`tests/test_pdf_generation.py` |
| **RF-05** | Recorrido pasivo de flujos multietapa de compra y registro | **PBI-05** | Inspección secuencial de hasta 4 etapas (inicio, catálogo, registro, checkout) sin mutación. | `src/scanner/flow_inspector.py`<br/>`src/scanner/flow_rules.py` | • 0 clics, 0 fills, 0 submits.<br/>• Preservación de cookie jar.<br/>• Detección de pasarelas externas. | `tests/test_flow_audit.py` |
| **RF-06** | Calendarización periódica de re-auditorías con alertas por email | **PBI-06** | Planificador en segundo plano con integración SMTP (Mailpit/externo) y notificación PDF. | `src/services/schedule_service.py`<br/>`src/services/email_service.py` | • Intervalos demo (2 min) y producción.<br/>• Generación automática de informe actualizado.<br/>• Envío de correo con enlace al reporte. | `tests/test_scheduler.py` |
| **RF-SEC** | Seguridad perimetral, resiliencia y mitigación de desvíos WAF | **SPIKE-01** | Middleware de protección anti-SSRF, timeout de 25s, argumentos anti-detección y estado neutro. | `src/core/sanitizer.py`<br/>`src/scanner/inspector.py`<br/>`src/services/audit_service.py` | • Restricción a puertos 80/443 y anti-SSRF.<br/>• Límite forzado de timeout de 25s.<br/>• Estado neutro `NO_ACCESIBLE` ante WAF 403/503. | `tests/test_security_ssrf.py`<br/>`tests/test_resilience_timeout.py`<br/>`tests/test_e2e_quality.py` |

---

## 3. Desglose Estandarizado de Product Backlog Items (PBI)

* **PBI-01**: *Inspección pasiva del landing y cálculo de los 3 pilares normativos*.
  * Ejecución en contenedor Chromium sin mutación de estado.
  * Captura asíncrona de eventos de red y cookies en el primer milisegundo pre-consentimiento.
* **PBI-02**: *Detección y auditoría de banners CMP y encapsulamiento en Shadow DOM*.
  * Rastreo de iframes cross-origin y árboles Shadow DOM abiertos y cerrados.
  * Evaluación de simetría de opciones de consentimiento (aceptar vs. rechazar).
* **PBI-03**: *Catálogo normativo de tickets técnicos de remediación accionables*.
  * Asignación matemática de ponderaciones: 35 pts Política, 30 pts ARCO, 35 pts Consentimiento.
  * Catálogo de tickets técnicos de remediación con fragmentos de código listos para producción (`remediation_catalog.py`).
* **PBI-04**: *Generación y descarga de reporte técnico en formato PDF*.
  * Compilación en memoria con ReportLab en menos de 3.0 segundos.
  * Paridad total con la vista en pantalla (responsable Art. 14 ter, banners, iframes y tickets).
* **PBI-05**: *Recorrido pasivo de flujos multietapa de compra/registro*.
  * Recorrido secuencial pasivo de hasta 4 etapas: inicio, catálogo, registro, checkout.
  * Detección de pasarelas de pago chilenas e internacionales.
* **PBI-06**: *Calendarización periódica de re-auditorías con alertas por email*.
  * Servicio de agendamiento y worker en segundo plano para verificación de remediación.
  * Notificación automática por email vía servidor SMTP.
* **SPIKE-01**: *Evaluación de evasión pasiva de WAF/Cloudflare y límite de timeout*.
  * Reducción de incertidumbre sobre sitios protegidos por Cloudflare/Akamai/F5.
  * Adopción de emulación con User-Agent legítimo, pausas de 1.5s y timeout de 25s.

---

## 4. Matriz de Evidencias Técnicas Verificables (EVI)

| Código | Evidencia Verificable | Test Suite Asociado | Métrica de Aceptación |
|---|---|---|---|
| **EVI-01** | Bloqueo absoluto de SSRF (IPv4/IPv6 privada, localhost, CGNAT, 169.254.169.254, puertos != 80/443). | `tests/test_security_ssrf.py` | 100% de payloads maliciosos rechazados con HTTP 400. |
| **EVI-02** | Resiliencia ante servidores con retardo de 40s (corte en 25s con force_close). | `tests/test_resilience_timeout.py` | Aborto en ≤ 25s con `page_load_status = 0` y cero procesos huérfanos. |
| **EVI-03** | Calibración empírica en 10 sitios reales y tasa de falsos positivos. | `src/scanner/benchmark.py`<br/>`docs/benchmark_10_sitios.md` | Tasa de falsos positivos < 10% (0 falsos positivos en muestra de control). |
| **EVI-04** | Evaluación determinista de reglas según Ley 21.719 y Art. 14 ter. | `tests/test_rules_engine.py`<br/>`tests/test_responsible_party.py` | 100% de casos normativos dictaminados con tickets asignados. |
| **EVI-05** | Compilación de reporte PDF y paridad con vista web. | `tests/test_pdf_report.py`<br/>`tests/test_pdf_generation.py` | Generación de buffer PDF en < 3.0 s. |
| **EVI-06** | Auditoría pasiva de flujos multietapa de compra/registro. | `tests/test_flow_audit.py` | 4 etapas evaluadas con 0 clics, 0 fills y 0 submits. |
| **EVI-07** | Re-auditorías programadas y despacho de alertas SMTP. | `tests/test_scheduler.py` | Creación de tarea, verificación de veredicto y envío de email. |
| **EVI-08** | Suite integral de calidad E2E y Privacy by Design en base de datos. | `tests/test_e2e_quality.py` | 0 credenciales ni tokens en BD, snippets <= 300 caracteres, concurrencia en < 30s. |
