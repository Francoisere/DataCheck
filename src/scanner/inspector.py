"""
Motor de Inspección Pasiva con Playwright (DA-01, DA-02, DA-04).
Garantías operativas:
- Exclusivamente peticiones HTTP GET públicas (sin fill, click en forms, ni mutaciones).
- Timeout global forzado de 25 segundos con asyncio.wait_for.
- Manejo resiliente de caídas DNS (net::ERR_NAME_NOT_RESOLVED) y bloqueos WAF (HTTP 403/503).
- Cierre garantizado de contextos Chromium en bloque try/finally para evitar procesos zombies.
- Restricción estricta de longitud en snippets de texto (<= 300 caracteres).
"""

import asyncio
import re
import urllib.parse
from typing import Dict, List, Any, Optional
from playwright.async_api import async_playwright, Page, BrowserContext, Error as PlaywrightError
from bs4 import BeautifulSoup

from src.core.config import settings
from src.core.sanitizer import sanitize_url
from .trackers_db import (
    KNOWN_TRACKER_DOMAINS,
    KNOWN_TRACKER_COOKIES,
    MANDATORY_LEGAL_KEYWORDS,
    ARCO_KEYWORDS
)

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


class WebInspector:
    def __init__(
        self,
        timeout_seconds: float = settings.SCAN_TIMEOUT_SECONDS,
        page_timeout_ms: int = settings.SCAN_PAGE_TIMEOUT_MS
    ):
        self.timeout_seconds = timeout_seconds
        self.page_timeout_ms = page_timeout_ms

    async def scan_url(self, raw_url: str) -> Dict[str, Any]:
        """
        Punto de entrada principal con garantía estricta de timeout global (DA-02).
        Si el análisis supera los 25 segundos, se aborta y limpia de forma segura.
        """
        try:
            return await asyncio.wait_for(
                self._execute_scan(raw_url),
                timeout=self.timeout_seconds
            )
        except asyncio.TimeoutError:
            normalized_url, _ = sanitize_url(raw_url)
            return self._build_timeout_fallback(normalized_url)

    async def _execute_scan(self, raw_url: str) -> Dict[str, Any]:
        """
        Ejecuta la inspección pasiva en un contexto aislado de Chromium.
        """
        normalized_url, _ = sanitize_url(raw_url)

        captured_requests: List[str] = []
        detected_tracker_domains: List[str] = []

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-accelerated-2d-canvas",
                    "--disable-gpu"
                ]
            )

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

                page: Page = await context.new_page()

                # Listener pasivo de tráfico de red
                def handle_request(request):
                    url = request.url
                    captured_requests.append(url)
                    for domain in KNOWN_TRACKER_DOMAINS:
                        if domain in url and domain not in detected_tracker_domains:
                            detected_tracker_domains.append(domain)

                page.on("request", handle_request)

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
                            error_message = f"Sitio no accesible para análisis (HTTP {page_load_status} - posible bloqueo WAF)"
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

                # Pausa breve para capturar scripts asíncronos iniciales
                await asyncio.sleep(1.5)

                # Cookies depositadas pre-interacción
                cookies = await context.cookies()
                raw_cookies = [c["name"] for c in cookies]
                detected_tracker_cookies = [
                    name for name in raw_cookies if any(tk in name for tk in KNOWN_TRACKER_COOKIES)
                ]

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
                    "arco_channels_audit": arco_channels
                }

            finally:
                # Cierre garantizado del contexto para prevenir fugas de memoria y zombies
                if context:
                    try:
                        await context.close()
                    except Exception:
                        pass
                await browser.close()

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
        Respuesta estructurada para cuando el sitio agota el timeout forzado de 25s (TEST-TO-02).
        """
        return {
            "target_url": normalized_url,
            "page_load_status": 0,
            "error_message": "Tiempo límite de escaneo alcanzado (25 segundos). El sitio objetivo no respondió dentro de los márgenes de auditoría.",
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
            }
        }
