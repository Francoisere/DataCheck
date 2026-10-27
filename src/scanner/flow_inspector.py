"""
Motor de Inspección de Flujo Multietapa Pasivo (DA-01, DA-04).
Recorre secuencialmente hasta 3 etapas (catálogo → registro → carrito/checkout)
usando exclusivamente peticiones HTTP GET públicas (page.goto).

Garantías operativas Nivel 0:
- Cero interacción activa: no hay click, fill ni submit.
- Navegación confinada al mismo dominio base auditado.
- Detección de pasarelas de pago externas (Webpay, Flow, Mercado Pago, etc.): detiene el flujo y marca la etapa como 'NO_ALCANZADA'.
- Almacenamiento continuo de cookies (un solo contexto Chromium para conservar la cookie jar).
- Declaración explícita de limitaciones (carrito vacío, trackers dependientes de evento marcados como 'NO_VERIFICABLE').
- Presupuesto de tiempo global (~60-75s) y timeout por etapa (20s) con cierre garantizado en bloque try/finally.
"""

import asyncio
import urllib.parse
from typing import Dict, List, Any, Optional, Set

from playwright.async_api import (
    async_playwright,
    Page,
    BrowserContext,
    Error as PlaywrightError,
)
from bs4 import BeautifulSoup

from src.core.sanitizer import sanitize_url
from .trackers_db import KNOWN_TRACKER_DOMAINS, is_tracker_cookie
from .stage_patterns import FLOW_STAGES, PAYMENT_GATEWAY_DOMAINS


class StageCapture:
    """Captura pasiva de peticiones y dominios de rastreo para una etapa específica."""

    def __init__(self, stage_name: str):
        self.stage_name = stage_name
        self.requests: List[Dict[str, str]] = []
        self.tracker_domains: List[str] = []

    def handle_request(self, request) -> None:
        """Listener pasivo de Playwright: almacena método, URL y dominios de rastreo."""
        url = request.url
        method = request.method
        self.requests.append({
            "url": url,
            "method": method,
            "stage": self.stage_name,
        })
        for domain in KNOWN_TRACKER_DOMAINS:
            if domain in url and domain not in self.tracker_domains:
                self.tracker_domains.append(domain)


class FlowInspector:
    """
    Inspector pasivo de flujos multietapa de compra/registro.
    Descubre y visita enlaces secuenciales dentro del mismo dominio.
    """

    def __init__(
        self,
        total_timeout_seconds: float = 75.0,
        stage_timeout_ms: int = 20000,
    ):
        self.total_timeout_seconds = total_timeout_seconds
        self.stage_timeout_ms = stage_timeout_ms

    async def audit_flow(self, raw_url: str) -> Dict[str, Any]:
        """
        Punto de entrada principal con garantía de timeout global.
        """
        try:
            return await asyncio.wait_for(
                self._execute_flow(raw_url),
                timeout=self.total_timeout_seconds,
            )
        except asyncio.TimeoutError:
            normalized_url, _ = sanitize_url(raw_url)
            return self._build_timeout_result(normalized_url)

    async def _execute_flow(self, raw_url: str) -> Dict[str, Any]:
        """
        Ejecuta el recorrido multietapa en un único contexto de navegador.
        """
        normalized_url, base_domain = sanitize_url(raw_url)

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-accelerated-2d-canvas",
                    "--disable-gpu",
                ],
            )
            context: Optional[BrowserContext] = None
            try:
                # Un solo contexto para preservar la jar de cookies entre etapas
                context = await browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/124.0.0.0 Safari/537.36 (DataCheck.cl/2.0; Academic Flow Audit)"
                    ),
                    viewport={"width": 1280, "height": 800},
                    ignore_https_errors=True,
                )

                # FB-01: Intercepción estricta para bloquear peticiones no-GET en flujos
                async def block_non_get(route, request):
                    if request.method != "GET":
                        await route.abort("blockedbyclient")
                    else:
                        await route.continue_()

                await context.route("**/*", block_non_get)

                page: Page = await context.new_page()
                await page.route("**/*", block_non_get)

                stages_results: List[Dict[str, Any]] = []
                cookies_seen_so_far: Set[str] = set()
                domains_seen_so_far: Set[str] = set()

                # Etapa 0: Página inicial
                base_result = await self._inspect_stage(
                    page=page,
                    context=context,
                    url=normalized_url,
                    stage_name="inicio",
                    stage_label="Página de Inicio",
                    cookies_seen_so_far=cookies_seen_so_far,
                    domains_seen_so_far=domains_seen_so_far,
                )
                stages_results.append(base_result)

                if base_result["status"] == "error":
                    return self._build_result(
                        normalized_url, base_domain, stages_results,
                        flow_detected=False,
                        reason="No se pudo cargar la página de inicio para iniciar el descubrimiento del flujo.",
                    )

                # Descubrir etapas navegables en el DOM
                html_content = ""
                try:
                    html_content = await page.content()
                except Exception:
                    pass

                discovered_stages = self._discover_stages(
                    html_content, normalized_url, base_domain
                )

                if not discovered_stages:
                    return self._build_result(
                        normalized_url, base_domain, stages_results,
                        flow_detected=False,
                        reason="Flujo no detectado en este sitio. No se encontraron enlaces hacia catálogo, registro o carrito en el mismo dominio.",
                    )

                # Recorrer hasta 3 etapas secuenciales
                for stage_info in discovered_stages[:3]:
                    stage_url = stage_info["url"]
                    stage_name = stage_info["stage_name"]
                    stage_label = stage_info["stage_label"]

                    # Comprobar si apunta a una pasarela de pago externa
                    if self._is_payment_gateway(stage_url):
                        stages_results.append({
                            "stage_name": stage_name,
                            "stage_label": stage_label,
                            "url": stage_url,
                            "status": "pasarela_externa",
                            "status_label": "No alcanzada: pasarela externa",
                            "verdict": "NO_ALCANZADA",
                            "new_tracker_domains": [],
                            "new_tracker_cookies": [],
                            "all_cookies_snapshot": [],
                            "requests_count": 0,
                            "http_status": 0,
                            "verification_note": "La navegación se detuvo al detectar una pasarela de pago de terceros.",
                        })
                        break

                    stage_result = await self._inspect_stage(
                        page=page,
                        context=context,
                        url=stage_url,
                        stage_name=stage_name,
                        stage_label=stage_label,
                        cookies_seen_so_far=cookies_seen_so_far,
                        domains_seen_so_far=domains_seen_so_far,
                    )
                    stages_results.append(stage_result)

                    # Buscar nuevos enlaces desde la etapa actual si faltan etapas
                    if len(stages_results) < 4:
                        try:
                            stage_html = await page.content()
                            sub_discovered = self._discover_stages(
                                stage_html, stage_url, base_domain
                            )
                            for sub in sub_discovered:
                                if not any(s["stage_name"] == sub["stage_name"] for s in stages_results):
                                    if not any(d["stage_name"] == sub["stage_name"] for d in discovered_stages):
                                        discovered_stages.append(sub)
                        except Exception:
                            pass

                return self._build_result(
                    normalized_url, base_domain, stages_results,
                    flow_detected=True,
                )

            finally:
                if context:
                    try:
                        await context.close()
                    except Exception:
                        pass
                await browser.close()

    async def _inspect_stage(
        self,
        page: Page,
        context: BrowserContext,
        url: str,
        stage_name: str,
        stage_label: str,
        cookies_seen_so_far: Set[str],
        domains_seen_so_far: Set[str],
    ) -> Dict[str, Any]:
        """
        Navega pasivamente a una etapa, recolecta peticiones y calcula diferencias de rastreadores.
        """
        capture = StageCapture(stage_name)
        page.on("request", capture.handle_request)

        http_status = 0
        error_message = None

        try:
            response = await page.goto(
                url,
                timeout=self.stage_timeout_ms,
                wait_until="domcontentloaded",
            )
            if response:
                http_status = response.status
        except PlaywrightError as pe:
            error_str = str(pe)
            if "ERR_NAME_NOT_RESOLVED" in error_str:
                error_message = "Host no resuelto"
            elif "Timeout" in error_str:
                error_message = "Tiempo de carga de etapa agotado"
            else:
                error_message = f"Error al cargar etapa: {error_str[:120]}"
        except Exception as ex:
            error_message = f"Error inesperado: {str(ex)[:120]}"

        # Breve espera no invasiva para completar peticiones asíncronas
        try:
            await page.wait_for_load_state("networkidle", timeout=3000)
        except Exception:
            await asyncio.sleep(0.8)

        # Desvincular listener de peticiones
        page.remove_listener("request", capture.handle_request)

        # Snapshot de cookies en esta etapa
        cookies = await context.cookies()
        current_cookie_names = {c["name"] for c in cookies}
        current_tracker_cookies = [
            c["name"] for c in cookies if is_tracker_cookie(c["name"])
        ]

        # Calcular diferencias respecto a etapas previas
        new_tracker_domains = [
            d for d in capture.tracker_domains if d not in domains_seen_so_far
        ]
        new_tracker_cookies = [
            name for name in current_tracker_cookies
            if name not in cookies_seen_so_far
        ]

        # Actualizar acumuladores
        cookies_seen_so_far.update(current_cookie_names)
        domains_seen_so_far.update(capture.tracker_domains)

        # Metadatos de cookies (Privacy by Design: no se almacenan valores)
        cookie_details = [
            {
                "name": c["name"],
                "domain": c.get("domain", ""),
                "secure": c.get("secure", False),
                "sameSite": c.get("sameSite", "None"),
            }
            for c in cookies
        ]

        status = "ok" if (http_status and 200 <= http_status < 400) else "error"
        if error_message:
            status = "error"

        # Determinación de veredicto por etapa
        if status == "error":
            verdict = "NO_VERIFICABLE"
        elif stage_name == "carrito":
            # El carrito se visita vacío sin mutaciones (DA-01); no se puede certificar cumplimiento total
            verdict = "NO_CUMPLE" if (new_tracker_domains or new_tracker_cookies) else "NO_VERIFICABLE"
        elif new_tracker_domains or new_tracker_cookies:
            verdict = "NO_CUMPLE"
        else:
            verdict = "CUMPLE"

        verification_note = None
        if stage_name == "carrito" and verdict == "NO_VERIFICABLE":
            verification_note = (
                "Limitación Nivel 0: El carrito se visitó vacío para evitar mutaciones activas (DA-01). "
                "Los rastreadores que se disparan al agregar productos no son observables de forma pasiva."
            )

        return {
            "stage_name": stage_name,
            "stage_label": stage_label,
            "url": url,
            "status": status,
            "status_label": "Verificada" if status == "ok" else f"Error: {error_message or http_status}",
            "verdict": verdict,
            "http_status": http_status,
            "error_message": error_message,
            "new_tracker_domains": new_tracker_domains,
            "new_tracker_cookies": new_tracker_cookies,
            "all_tracker_domains_cumulative": list(domains_seen_so_far),
            "all_tracker_cookies_cumulative": list(
                name for name in cookies_seen_so_far if is_tracker_cookie(name)
            ),
            "all_cookies_snapshot": cookie_details,
            "requests_count": len(capture.requests),
            "verification_note": verification_note,
        }

    def _discover_stages(
        self,
        html_content: str,
        current_url: str,
        base_domain: str,
    ) -> List[Dict[str, str]]:
        """
        Inspecciona el DOM en busca de enlaces a etapas del flujo (catálogo, registro, carrito).
        """
        if not html_content:
            return []

        soup = BeautifulSoup(html_content, "html.parser")
        discovered: List[Dict[str, str]] = []
        seen_stages: Set[str] = set()

        for stage_def in FLOW_STAGES:
            stage_name = stage_def["name"]
            if stage_name in seen_stages:
                continue

            link = self._find_stage_link(
                soup, stage_def, current_url, base_domain
            )
            if link:
                seen_stages.add(stage_name)
                discovered.append({
                    "stage_name": stage_name,
                    "stage_label": stage_def["label"],
                    "url": link,
                })

        return discovered

    def _find_stage_link(
        self,
        soup: BeautifulSoup,
        stage_def: Dict[str, Any],
        current_url: str,
        base_domain: str,
    ) -> Optional[str]:
        """
        Localiza el enlace más adecuado para la etapa dentro del mismo dominio, sanitizando con sanitize_url.
        """
        url_patterns = stage_def["url_patterns"]
        text_patterns = stage_def["text_patterns"]

        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith("#") or href.startswith("javascript:") or href.startswith("mailto:"):
                continue

            full_url = urllib.parse.urljoin(current_url, href)
            text = a.get_text(strip=True).lower()
            href_lower = href.lower()

            try:
                parsed = urllib.parse.urlsplit(full_url)
                link_host = (parsed.hostname or "").lower()
            except Exception:
                continue

            # Confinamiento estricto al mismo dominio (o subdominios)
            if not (link_host == base_domain or link_host.endswith(f".{base_domain}")):
                # Si es una pasarela de pago conocida externa, devolverla para detección de corte
                if any(gw in link_host for gw in PAYMENT_GATEWAY_DOMAINS):
                    return full_url
                continue

            # Coincidencia por path o query en la URL
            for pattern in url_patterns:
                if pattern in href_lower:
                    try:
                        sanitized, _ = sanitize_url(full_url)
                        return sanitized
                    except ValueError:
                        continue

            # Coincidencia por texto semántico del anchor
            for pattern in text_patterns:
                if pattern in text:
                    try:
                        sanitized, _ = sanitize_url(full_url)
                        return sanitized
                    except ValueError:
                        continue

        return None

    @staticmethod
    def _is_payment_gateway(url: str) -> bool:
        """
        Comprueba si la URL corresponde a un dominio de pasarela de pago externa.
        """
        try:
            parsed = urllib.parse.urlsplit(url)
            host = (parsed.hostname or "").lower()
            return any(gw in host for gw in PAYMENT_GATEWAY_DOMAINS)
        except Exception:
            return False

    def _build_result(
        self,
        target_url: str,
        domain: str,
        stages: List[Dict[str, Any]],
        flow_detected: bool,
        reason: str = "",
    ) -> Dict[str, Any]:
        """
        Construye el diccionario de resultado pasivo del flujo.
        """
        limitations = [
            "El carrito de compras se inspeccionó vacío para cumplir con la política de cero mutación (DA-01).",
            "Los rastreadores que requieren interacción explícita (e.g. agregar al carro) no son verificables pasivamente.",
            "Las etapas catalogadas como 'NO_VERIFICABLE' no constituyen certificación de cumplimiento normativo.",
        ]

        return {
            "target_url": target_url,
            "domain": domain,
            "flow_detected": flow_detected,
            "flow_not_detected_reason": reason if not flow_detected else None,
            "total_stages": len(stages),
            "stages": stages,
            "limitations": limitations,
        }

    def _build_timeout_result(self, normalized_url: str) -> Dict[str, Any]:
        """
        Respuesta de resiliencia ante agotamiento del presupuesto de tiempo global.
        """
        return {
            "target_url": normalized_url,
            "domain": "",
            "flow_detected": False,
            "flow_not_detected_reason": (
                f"Tiempo límite global de auditoría de flujo alcanzado ({self.total_timeout_seconds}s). "
                "El sitio objetivo no completó las etapas de navegación dentro de los márgenes previstos."
            ),
            "total_stages": 0,
            "stages": [],
            "limitations": [],
        }
