EvidenciaRastreador) sin registrar datos personales.
5. **Cálculo Determinista de Puntajes y Clasificación (C-01 / C-04):** Estructura formal de 3 pilares (Política: 35 pts, Canales ARCO: 30 pts, Cookies: 35 pts) con veredictos `APROBADO` (≥80 pts y 0 trackers no autorizados), `CON_OBSERVACIONES` (≥55 pts) o `RECHAZADO`.
6. **Tickets Técnicos de Remediación (PBI-03 / RC-03):** Salida estructurada de recomendaciones accionables para desarrolladores (reemplazando citas jurídicas complejas).

---

## 2. Drivers Arquitectónicos y Restricciones Operativas

| ID | Driver / Restricción | Impacto en la Implementación (Backend / DevOps) |
| :--- | :--- | :--- |
| **DA-01** | **Inspección Pasiva y Ley 21.459** | Prohibición absoluta de métodos distintos de HTTP GET público. Cero interacciones destructivas (sin `fill`, `click` en formularios internos, ni sondeo de puertos). |
| **DA-02** | **Rendimiento y Disponibilidad** | Cancelación forzada a los 25 s por escaneo (`asyncio.wait_for`). Cierre garantizado de contextos de navegador y limpieza de procesos zombies. |
| **DA-04** | **Privacy by Design** | Almacenamiento exclusivo de metadatos técnicos (dominios, nombres de cookies, códigos HTTP). Restricción estricta de longitud en extractos de texto (≤300 chars). |
| **DA-06** | **Reproducibilidad y DevOps** | Configuración de `/dev/shm` (`shm_size: '1gb'`) en Docker Compose para estabilidad de Chromium headless y pipeline de CI/CD reproducible. |

---

## 3. Arquitectura del Incremento y Estructura de Módulos

```
.
├── docker-compose.yml                  # Orquestación con PostgreSQL 16 y optimización de shm_size
├── Dockerfile                          # Playwright + Python 3.12 + dependencias de sistema
├── requirements.txt                    # FastAPI, Playwright, SQLAlchemy, asyncpg, Pydantic v2, pytest-asyncio
├── .github/
│   └── workflows/
│       └── ci.yml                      # Pipeline CI/CD: Linting, validación Pydantic y pruebas unitarias
├── src/
│   ├── api/
│   │   ├── __init__.py
│   │   ├── main.py                     # Entrypoint FastAPI, CORS, middlewares y ciclo de vida
│   │   ├── middlewares.py              # Middleware de sanitización de URLs y captura de excepciones
│   │   ├── schemas.py                  # Modelos Pydantic V2 (ScanRequest, ScanResponse, Findings, Pillars)
│   │   └── routes/
│   │       ├── scan.py                 # Endpoints C-01 (POST /api/v1/scan) y C-02 (GET /api/v1/scan)
│   │       └── health.py               # Endpoint C-03 (GET /api/v1/health)
│   ├── core/
│   │   ├── config.py                   # Pydantic Settings (variables de entorno, timeouts, DB URL)
│   │   └── exceptions.py               # Excepciones de dominio (TimeoutException, WafBlockedException)
│   ├── db/
│   │   ├── session.py                  # Motor asíncrono SQLAlchemy + asyncpg
│   │   └── models.py                   # Esquema relacional: Sitio, Auditoria, Pilares, Hallazgos, Evidencias
│   ├── scanner/
│   │   ├── inspector.py                # Wrapper Playwright con timeout de 25 s y rotación de User-Agent
│   │   ├── rules_engine.py             # Evaluador ponderado (100 pts) y generador de tickets técnicos
│   │   └── trackers_db.py              # Diccionario clasificado de trackers (Meta, Google, TikTok, etc.)
│   └── services/
│       └── audit_service.py            # Orquestador: Normalización -> Inspección -> Reglas -> Persistencia
└── tests/
    ├── test_sanitization.py            # Verificación de exclusión de tokens/credenciales en URL
    ├── test_rules.py                   # Pruebas unitarias de puntajes y condiciones de veredicto
    ├── test_timeout_resilience.py      # Validación de corte estricto en <25 s ante sitios lentos
    └── test_api.py                     # Pruebas de integración sobre endpoints REST
```

---

## 4. Contratos de Datos y Modelo Relacional

### 4.1. Contrato OpenAPI (C-01 / C-04)
- **Endpoint:** `POST /api/v1/scan`
- **Request Body:**
  ```json
  {
    "url": "https://tienda-ejemplo.cl"
  }
  ```
- **Response Body (`200 OK`):**
  ```json
  {
    "target_url": "https://tienda-ejemplo.cl/",
    "page_load_status": 1,
    "verdict": "RECHAZADO",
    "score": 65,
    "verdict_summary": "Incumplimiento crítico: Se detectaron rastreadores de terceros activos previo al consentimiento.",
    "pilares": {
      "politica_privacidad": { "status": "CUMPLE", "score": 35, "max_score": 35 },
      "canales_arco": { "status": "CUMPLE", "score": 30, "max_score": 30 },
      "consentimiento_cookies": { "status": "FALLA", "score": 0, "max_score": 35 }
    },
    "findings": [
      {
        "pilar": "CONSENTIMIENTO_COOKIES",
        "status": "FAIL",
        "title": "Inyección no autorizada de rastreador externo",
        "detail": "Cookie '_ga' y petición saliente a 'google-analytics.com' detectadas al cargar el DOM.",
        "technical_raw": "google-analytics.com",
        "remediation_ticket": "Condicionar la inyección de la etiqueta de Google Analytics en Google Tag Manager (GTM) al evento personalizado de aceptación del banner de cookies."
      }
    ],
    "legal_disclaimer": "DataCheck.cl es una herramienta de auditoría técnica académica de apoyo. Este reporte no constituye asesoría jurídica formal ni certificación vinculante de la Agencia de Protección de Datos Personales."
  }
  ```

### 4.2. Esquema Relacional Inmutable (PostgreSQL)
- **`sitios_analizados`**: `id (UUID PK)`, `url_normalizada (UNIQUE)`, `dominio`, `creado_en`.
- **`auditorias`**: `id (UUID PK)`, `sitio_id (FK)`, `ejecutada_en`, `page_load_status`, `verdict`, `score (0-100)`, `duracion_ms`, `resumen`.
- **`resultados_pilares`**: `id (UUID PK)`, `auditoria_id (FK)`, `pilar (ENUM)`, `estado (ENUM)`, `puntaje`, `puntaje_max` (`UNIQUE(auditoria_id, pilar)`).
- **`hallazgos`**: `id (UUID PK)`, `resultado_pilar_id (FK)`, `severidad (OK|WARNING|FAIL)`, `titulo`, `detalle (max 300 chars)`, `recomendacion`.
- **`evidencias_rastreadores`**: `id (UUID PK)`, `auditoria_id (FK)`, `tipo (DOMINIO|COOKIE)`, `valor (nombre/host)`, `categoria`.

---

## 5. Plan de Tareas por Sprints (Semanas 7 a 9)

### Sprint 1: Semana 7 — Normalización, Robustecimiento del Motor y Desvíos
*Meta: Motor de escaneo pasivo funcional para el flujo principal F-01 y casos D-01, D-02 y D-03.*
1. **Middlewares y Sanitización de URL (Backend):**
   - Construir parser que remueva `user:pass@`, tokens de sesión y parámetros `?utm_`, `?token=` preservando únicamente esquema y host.
2. **Inspector Playwright Asíncrono con Timeout Forzado (Scraping/Backend):**
   - Envolver la llamada de navegación en `asyncio.wait_for(timeout=25.0)`.
   - Implementar bloque `try/finally` para asegurar el cierre de contextos de Chromium (`browser_context.close()`).
   - Gestión de errores de carga: Capturar `net::ERR_NAME_NOT_RESOLVED`, HTTP 403/503 (WAF) y responder con estado descriptivo sin lanzar `HTTP 500`.
3. **Calibración de Reglas y Generación de Tickets de Remediación (Legal/Backend):**
   - Implementar matriz de ponderación (35 / 30 / 35).
   - Redactar catálogo estandarizado de `remediation_tickets` técnicos para desarrolladores.

### Sprint 2: Semana 8 — Persistencia Relacional, Gestión de Estados y CI/CD
*Meta: Base de datos integrada, historial auditable y pipeline de verificación continua.*
1. **Capa de Persistencia Async con SQLAlchemy (Backend):**
   - Configurar migraciones o inicialización declarativa de tablas PostgreSQL.
   - Implementar repositorio de guardado inmutable post-escaneo.
2. **Optimización de Contenedores y DevOps (DevOps):**
   - Ajustar `docker-compose.yml` incorporando `shm_size: '1gb'` en el servicio de escaneo.
   - Configurar healthcheck en Docker y endpoint `GET /api/v1/health` para auto-recuperación (`restart: unless-stopped`).
3. **Pipeline de Integración Continua (DevOps):**
   - Configurar GitHub Actions para ejecutar pruebas de cobertura, linting (`flake8`/`black`) y verificación de tipos (`mypy`).

### Sprint 3: Semana 9 — Calibración, Benchmark de Validación y Pruebas E2E
*Meta: Validación empírica de métricas de calidad y preparación para la defensa final.*
1. **Suite de Pruebas de Calidad Automatizadas (QA/DevOps):**
   - Ejecutar `pytest` sobre los escenarios `EC-01` a `EC-06`:
     - Rendimiento ($< 15$ s en sitios estándar, $< 30$ s en concurrencia).
     - Resiliencia (servidor con delay de 40 s debe abortar limpiamente en 25 s).
     - Seguridad (verificar en logs la ausencia de llamadas POST/PUT/DELETE hacia sitios remotos).
2. **Evaluación de Muestra de 10 Sitios Reales (Scraping/Legal):**
   - Comparar resultados automatizados vs. inspección manual de los 3 pilares.
   - Ajustar umbrales para garantizar falsos positivos $< 15\%$.

---

## 6. Plan de Verificación y Criterios de Aceptación Técnicos

| Identificador | Prueba / Verificación | Criterio de Aprobación Inmediato |
| :--- | :--- | :--- |
| **TEST-SAN-01** | Envío de URL con credenciales (`https://user:pass@sitio.cl/?token=secret`) | La base de datos almacena exclusivamente `https://sitio.cl/`. Cero cadenas sensibles en DB. |
| **TEST-TO-02** | Escaneo contra servidor mockup con respuesta en 40 segundos | El proceso aborta a los 25 s, retorna código amigable y no deja procesos Chromium activos. |
| **TEST-WAF-03** | Escaneo contra sitio protegido que retorna HTTP 403 | El sistema reporta `page_load_status: 0` y mensaje "Sitio no accesible para análisis" sin error 500. |
| **TEST-RULE-04** | Detección de rastreador previo a interacción | El pilar de cookies recibe estado `FALLA`, puntaje 0/35 y el veredicto general es `RECHAZADO`. |
| **TEST-DEP-05** | Inicialización limpia desde cero con `docker compose up --build` | Contenedores operativos en $< 5$ minutos y `/api/v1/health` respondiendo `200 OK`. |
