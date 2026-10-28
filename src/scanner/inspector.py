import logging
"""
Motor de Inspección Pasiva con Playwright (DA-01, DA-02, DA-04, FB-01, FB-02, FB-03).
Garantías operativas:
- Exclusivamente peticiones HTTP GET públicas: route interceptor aborta cualquier método no-GET (FB-01).
- Timeout global forzado de 25 segundos con asyncio.wait_for y force_close de procesos Chromium (FB-03).
- Manejo resiliente de caídas DNS y bloqueos WAF (HTTP 403/503 o antibot) asignando page_load_status=0 (FB-02).
- Cierre garantizado de contextos Chromium en bloque try/finally para evitar procesos zombies.
- Restricción estricta de longitud en snippets de texto (<= 300 caracteres).
"""

import asyncio
import re
import urllib.parse
from typing import Dict, List, Any, Optional
from playwright.async_api import async_playwright, Page, BrowserContext, Browser, Error as PlaywrightError
from bs4 import BeautifulSoup

from src.core.config import settings
from src.core.sanitizer import sanitize_url
from .trackers_db import (
    KNOWN_TRACKER_DOMAINS,
    KNOWN_TRACKER_COOKIES,
    is_tracker_cookie,
    MANDATORY_LEGAL_KEYWORDS,
    ARCO_KEYWORDS
)
from .consent_detector import ConsentDetector
from .responsible_detector import ResponsiblePartyDetector

PRIVACY_LINK_PATTERNS = [
    r"privacidad",
    r"privacy",
    r"terminos",
    r"terms",
    r"aviso-legal",
    r"legal",
    r"politica"
]

EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"


class TrafficCapture:
    """Clase reutilizable para captura pasiva de solicitudes de red y dominios de rastreo."""
    def __init__(self):
        self.captured_requests: List[str] = []
        self.detected_tracker_domains: List[str] = []

    def handle_request(self, request) -> None:
        url = request.url
        self.captured_requests.append(url)
        for domain in KNOWN_TRACKER_DOMAINS:
            if domain in url and domain not in self.detected_tracker_domains:
                self.detected_tracker_domains.append(domain)


logger = logging.getLogger(__name__)
_SSRF_HOST_CACHE: Dict[str, bool] = {}


def is_ssrf_safe_host(hostname: str) -> bool:
    """Valida y cachea resoluciones de host en O(1) para no bloquear el event loop (N3)."""
    cleaned = hostname.strip().lower()
    if cleaned in _SSRF_HOST_CACHE:
        return _SSRF_HOST_CACHE[cleaned]
    try:
        from src.core.sanitizer import validate_ssrf
        validate_ssrf(cleaned)
        _SSRF_HOST_CACHE[cleaned] = True
        return True
    except Exception:
        _SSRF_HOST_CACHE[cleaned] = False
        return False


async def block_non_get_route(route, request=None) -> None:
    """
    FB-01 / DA-01: Interceptor estricto de red.
    - Aborta inmediatamente cualquier método HTTP que no sea GET (POST, PUT, DELETE, PATCH).
    - Valida contra SSRF y puertos no permitidos cualquier destino solicitado con caché de host O(1).
    - Registra en logs cualquier petición bloqueada para trazabilidad técnica (N3).
    """
    req = request if request is not None else route.request
    if req.method != "GET":
        logger.debug(f"[Interceptor] Abortada petición no-GET ({req.method}): {req.url[:120]}")
        await route.abort("blockedbyclient")
        return

    try:
        url = req.url
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() in ("http", "https") and parsed.hostname:
            if not is_ssrf_safe_host(parsed.hostname):
                logger.warning(f"[Interceptor] Bloqueado destino restringido o SSRF: {parsed.hostname}")
                await route.abort("blockedbyclient")
                return
            if parsed.port and parsed.port not in (80, 443):
                logger.warning(f"[Interceptor] Bloqueado puerto no autorizado: {parsed.port}")
                await route.abort("blockedbyclient")
                return
    except Exception as e:
        logger.debug(f"[Interceptor] Excepción validando ruta {req.url[:120]}: {e}")
        await route.abort("blockedbyclient")
        return

    await route.continue_()


class WebInspector:
    block_non_get = staticmethod(block_non_get_route)
    def __init__(
        self,
        timeout_seconds: float = settings.SCAN_TIMEOUT_SECONDS,
        page_timeout_ms: int = settings.SCAN_PAGE_TIMEOUT_MS
    ):
        self.timeout_seconds = timeout_seconds
        self.page_timeout_ms = page_timeout_ms
        self._active_browser: Optional[Browser] = None
        self._active_context: Optional[BrowserContext] = None

    async def force_close(self) -> None:
        """
        Cierre forzoso de contextos y procesos Chromium para evitar procesos huérfanos (FB-03).
        """
        if self._active_context:
            try:
                await self._active_context.close()
            except Exception:
                pass
            finally:
                self._active_context = None

        if self._active_browser:
            try:
                await self._active_browser.close()
            except Exception:
                pass
            finally:
                self._active_browser = None

    async def scan_url(self, raw_url: str) -> Dict[str, Any]:
        """
        Punto de entrada principal con garantía estricta de timeout global (DA-02 / FB-03).
        Si el análisis supera los 25 segundos, se aborta forzosamente y limpia de forma segura.
        """
        try:
            return await asyncio.wait_for(
                self._execute_scan(raw_url),
                timeout=self.timeout_seconds
            )
        except asyncio.TimeoutError:
            await self.force_close()
            normalized_url, _ = sanitize_url(raw_url, check_ssrf=False)
            return self._build_timeout_fallback(normalized_url)

    async def _execute_scan(self, raw_url: str) -> Dict[str, Any]:
        """
        Ejecuta la inspección pasiva en un contexto aislado de Chromium.
        """
        normalized_url, _ = sanitize_url(raw_url)

        traffic_capture = TrafficCapture()

        async with async_playwright() as p:
            launch_args = [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-accelerated-2d-canvas",
                "--disable-gpu",
                "--disable-blink-features=AutomationControlled"
            ]
            try:
                browser = await p.chromium.launch(headless=True, args=launch_args)
            except Exception:
                try:
                    browser = await p.chromium.launch(channel="chrome", headless=True, args=launch_args)
                except Exception:
                    browser = await p.chromium.launch(channel="msedge", headless=True, args=launch_args)

            self._active_browser = browser
            context: Optional[BrowserContext] = None
            try:
                context = await browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/124.0.0.0 Safari/537.36 (DataCheck.cl/2.0; Academic Privacy Audit)"
                    ),
                    viewport={"width": 1280, "height": 800}
                )
                self._active_context = context

                # FB-01: Intercepcion estricta: abortar cualquier peticion que no sea HTTP GET
                await context.route("**/*", block_non_get_route)

                page: Page = await context.new_page()
                await page.route("**/*", block_non_get_route)

                # Listener pasivo de tráfico de red
                page.on("request", traffic_capture.handle_request)

                page_load_status = 200
                error_message = None

                try:
                    response = await page.goto(
                        normalized_url,
                        timeout=self.page_timeout_ms,
                        wait_until="domcontentloaded"
                    )
                    if response:
                        page_load_status = response.status
                        if page_load_status in (403, 503):
                            # FB-02: Bloqueo WAF / Cloudflare -> page_load_status=0
                            page_load_status = 0
                            error_message = "BLOQUEO_WAF_ANTIBOT"
                        else:
                            # Detección de Cloudflare Challenge o WAF en el título
                            try:
                                page_title = await page.title()
                                if any(w in page_title.lower() for w in (
                                    "just a moment...",
                                    "attention required! | cloudflare",
                                    "ddos protection by cloudflare",
                                    "access denied"
                                )):
                                    page_load_status = 0
                                    error_message = "BLOQUEO_WAF_ANTIBOT"
                            except Exception:
                                pass
                except PlaywrightError as pe:
                    error_str = str(pe)
                    if "ERR_NAME_NOT_RESOLVED" in error_str:
                        error_message = "No se pudo resolver el nombre de host (ERR_NAME_NOT_RESOLVED)"
                    elif "ERR_CONNECTION_REFUSED" in error_str:
                        error_message = "Conexión rechazada por el servidor destino"
                    elif "Timeout" in error_str:
                        error_message = "Tiempo de carga de página agotado"
                    else:
                        error_message = f"Error al cargar la página: {error_str[:120]}"
                    page_load_status = 0
                except Exception as ex:
                    error_message = f"Error inesperado al acceder: {str(ex)[:120]}"
                    page_load_status = 0

                # Si el sitio no es accesible o fue bloqueado por WAF, retornar inmediatamente sin esperas
                if page_load_status == 0:
                    return {
                        "target_url": normalized_url,
                        "page_load_status": 0,
                        "error_message": error_message or "Sitio no accesible para análisis técnico pasivo.",
                        "tracker_audit": {
                            "detected_tracker_domains": traffic_capture.detected_tracker_domains,
                            "detected_tracker_cookies": [],
                            "total_cookies": 0,
                            "raw_cookies": [],
                            "local_storage_keys_count": 0,
                            "has_unauthorized_trackers": len(traffic_capture.detected_tracker_domains) > 0
                        },
                        "privacy_policy_audit": {
                            "found": False,
                            "url": None,
                            "http_status": 0,
                            "policy_text_snippet": "",
                            "policy_text": "",
                            "found_keywords": [],
                            "missing_keywords": MANDATORY_LEGAL_KEYWORDS,
                            "has_mandatory_keywords": False
                        },
                        "arco_channels_audit": {
                            "found": False,
                            "detected_emails": [],
                            "detected_terms": [],
                            "has_explicit_arco_mention": False
                        },
                        "consent_banner_audit": {
                            "banner_detected": False,
                            "cmp_provider": None,
                            "has_reject_option": False,
                            "has_accept_option": False,
                            "has_settings_option": False,
                            "detected_buttons": [],
                            "banner_source_frame": None,
                            "buttons_verifiable": True,
                            "blocks_prior_to_consent": None
                        },
                        "frames_audit": {
                            "total_frames": 0,
                            "third_party_frames": 0,
                            "cmp_frames": 0,
                            "frames": []
                        },
                        "responsible_party_audit": {
                            "identified": False,
                            "representative_found": False,
                            "dpo_found": False,
                            "contact_channels_found": [],
                            "verdict": "NO_VERIFICABLE",
                            "notes": "No fue posible verificar información del responsable debido al bloqueo de acceso perimetral.",
                            "corporate_name": None,
                            "detected_rut": None,
                            "contact_email": None,
                            "postal_address": None,
                            "dpo_email": None
                        }
                    }

                # Pausa breve para capturar scripts asíncronos iniciales
                await asyncio.sleep(1.5)

                # Cookies depositadas pre-interacción (filtrado exacto y por prefijo sin falsos positivos)
                cookies = await context.cookies()
                raw_cookies = [c["name"] for c in cookies]
                detected_tracker_cookies = [
                    name for name in raw_cookies if is_tracker_cookie(name)
                ]
                captured_requests = traffic_capture.captured_requests
                detected_tracker_domains = traffic_capture.detected_tracker_domains

                # LocalStorage
                local_storage_keys = []
                try:
                    local_storage_keys = await page.evaluate("Object.keys(localStorage)")
                except Exception:
                    pass

                # DOM Content
                html_content = ""
                try:
                    html_content = await page.content()
                except Exception:
                    pass

                soup = BeautifulSoup(html_content, "html.parser")

                # Búsqueda e inspección de Política de Privacidad
                privacy_links = self._find_privacy_links(soup, normalized_url)
                privacy_audit = await self._inspect_privacy_policy(context, privacy_links, normalized_url)

                # Canales ARCO
                arco_channels = self._extract_arco_channels(
                    soup,
                    html_content,
                    privacy_audit.get("policy_text", "")
                )

                # Auditoría de Banners de Consentimiento e iframes (Paso 10 / Fase 2)
                consent_detection = await ConsentDetector.detect_consent(page, normalized_url)
                consent_banner_audit = consent_detection.get("consent_banner_audit", {})
                frames_audit = consent_detection.get("frames_audit", {})

                # Auditoría de Transparencia del Responsable (Art. 14 ter b y c - Ley 21.719)
                responsible_audit = ResponsiblePartyDetector.detect(
                    soup=soup,
                    html_content=html_content,
                    policy_text=privacy_audit.get("policy_text", ""),
                    policy_found=privacy_audit.get("found", False)
                )

                return {
                    "target_url": normalized_url,
                    "page_load_status": page_load_status,
                    "error_message": error_message,
                    "tracker_audit": {
                        "detected_tracker_domains": detected_tracker_domains,
                        "detected_tracker_cookies": detected_tracker_cookies,
                        "total_cookies": len(raw_cookies),
                        "raw_cookies": raw_cookies,
                        "local_storage_keys_count": len(local_storage_keys),
                        "has_unauthorized_trackers": len(detected_tracker_domains) > 0 or len(detected_tracker_cookies) > 0
                    },
                    "privacy_policy_audit": privacy_audit,
                    "arco_channels_audit": arco_channels,
                    "consent_banner_audit": consent_banner_audit,
                    "frames_audit": frames_audit,
                    "responsible_party_audit": responsible_audit
                }

            finally:
                # Cierre garantizado del contexto para prevenir fugas de memoria y zombies (FB-03)
                if context:
                    try:
                        await context.close()
                    except Exception:
                        pass
                await browser.close()
                self._active_context = None
                self._active_browser = None

    def _find_privacy_links(self, soup: BeautifulSoup, base_url: str) -> List[Dict[str, str]]:
        found_links = []
        seen_hrefs = set()

        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            text = a.get_text(strip=True).lower()
            href_lower = href.lower()

            matches = any(re.search(pat, href_lower) or re.search(pat, text) for pat in PRIVACY_LINK_PATTERNS)
            if matches:
                full_url = urllib.parse.urljoin(base_url, href)
                if full_url not in seen_hrefs and (full_url.startswith("http://") or full_url.startswith("https://")):
                    seen_hrefs.add(full_url)
                    found_links.append({
                        "url": full_url,
                        "anchor_text": a.get_text(strip=True)[:60]
                    })

        return found_links

    async def _inspect_privacy_policy(
        self,
        context: BrowserContext,
        privacy_links: List[Dict[str, str]],
        base_url: str
    ) -> Dict[str, Any]:
        if not privacy_links:
            return {
                "found": False,
                "url": None,
                "http_status": 404,
                "policy_text_snippet": "",
                "policy_text": "",
                "found_keywords": [],
                "missing_keywords": MANDATORY_LEGAL_KEYWORDS,
                "has_mandatory_keywords": False
            }

        target_policy_url = privacy_links[0]["url"]
        for link in privacy_links:
            url_lower = link["url"].lower()
            if "privacidad" in url_lower or "privacy" in url_lower:
                target_policy_url = link["url"]
                break

        page = await context.new_page()
        http_status = 0
        policy_text = ""

        try:
            res = await page.goto(target_policy_url, timeout=10000, wait_until="domcontentloaded")
            if res:
                http_status = res.status
            policy_text = await page.evaluate("document.body ? document.body.innerText : ''")
        except Exception:
            http_status = 500
        finally:
            await page.close()

        policy_text_lower = policy_text.lower()
        found_keywords = [kw for kw in MANDATORY_LEGAL_KEYWORDS if kw in policy_text_lower]
        missing_keywords = [kw for kw in MANDATORY_LEGAL_KEYWORDS if kw not in policy_text_lower]
        has_mandatory_keywords = len(found_keywords) >= 4

        # Privacy by Design (DA-04): snippet restringido a max 300 caracteres
        snippet = (policy_text[:settings.MAX_SNIPPET_LENGTH] + "...") if len(policy_text) > settings.MAX_SNIPPET_LENGTH else policy_text

        return {
            "found": http_status == 200,
            "url": target_policy_url,
            "all_detected_links": [l["url"] for l in privacy_links],
            "http_status": http_status,
            "policy_text_snippet": snippet,
            "policy_text": policy_text,
            "found_keywords": found_keywords,
            "missing_keywords": missing_keywords,
            "has_mandatory_keywords": has_mandatory_keywords
        }

    def _extract_arco_channels(self, soup: BeautifulSoup, main_html: str, policy_text: str) -> Dict[str, Any]:
        all_text = soup.get_text() + " " + policy_text
        found_emails = list(set(re.findall(EMAIL_REGEX, all_text)))

        valid_emails = [
            e for e in found_emails
            if not e.endswith((".png", ".jpg", ".svg", ".webp", ".gif"))
            and "example" not in e.lower()
            and "domain" not in e.lower()
        ][:5]

        all_text_lower = all_text.lower()
        found_arco_terms = [kw for kw in ARCO_KEYWORDS if kw in all_text_lower]

        has_arco_channel = len(valid_emails) > 0 or len(found_arco_terms) > 0

        return {
            "found": has_arco_channel,
            "detected_emails": valid_emails,
            "detected_terms": list(set(found_arco_terms)),
            "has_explicit_arco_mention": any("arco" in term for term in found_arco_terms)
        }

    def _build_timeout_fallback(self, normalized_url: str) -> Dict[str, Any]:
        """
        Respuesta estructurada para cuando el sitio agota el timeout forzado de 25s (TEST-TO-02 / FB-03).
        """
        return {
            "target_url": normalized_url,
            "page_load_status": 0,
            "error_message": f"Tiempo límite global de inspección superado ({self.timeout_seconds}s).",
            "tracker_audit": {
                "detected_tracker_domains": [],
                "detected_tracker_cookies": [],
                "total_cookies": 0,
                "raw_cookies": [],
                "local_storage_keys_count": 0,
                "has_unauthorized_trackers": False
            },
            "privacy_policy_audit": {
                "found": False,
                "url": None,
                "http_status": 408,
                "policy_text_snippet": "",
                "policy_text": "",
                "found_keywords": [],
                "missing_keywords": MANDATORY_LEGAL_KEYWORDS,
                "has_mandatory_keywords": False
            },
            "arco_channels_audit": {
                "found": False,
                "detected_emails": [],
                "detected_terms": [],
                "has_explicit_arco_mention": False
            },
            "consent_banner_audit": {
                "banner_detected": False,
                "cmp_provider": None,
                "has_reject_option": False,
                "has_accept_option": False,
                "has_settings_option": False,
                "detected_buttons": [],
                "banner_source_frame": None,
                "buttons_verifiable": True,
                "blocks_prior_to_consent": None
            },
            "frames_audit": {
                "total_frames": 0,
                "third_party_frames": 0,
                "cmp_frames": 0,
                "frames": []
            },
            "responsible_party_audit": {
                "identified": False,
                "representative_found": False,
                "dpo_found": False,
                "contact_channels_found": [],
                "verdict": "NO_VERIFICABLE",
                "notes": "No fue posible verificar información del responsable por agotamiento de tiempo de escaneo.",
                "corporate_name": None,
                "detected_rut": None,
                "contact_email": None,
                "postal_address": None,
                "dpo_email": None
            }
        }
