"""
Módulo de Detección Pasiva de Consentimiento y Marcos Embebidos (DA-01 / EC-04).

Este módulo implementa la inspección en modo solo lectura de plataformas de gestión
de consentimiento (CMPs) y banners de cookies desplegados en el DOM principal,
Shadow DOM (abierto y cerrado) o en marcos embebidos (iframes).

Garantías de diseño (Privacy & Security by Design):
- DA-01: Exclusivamente operaciones de lectura (frame.evaluate / DOM inspection).
  Cero mutaciones, cero clics (click), cero llenado de formularios (fill) y cero envíos (submit).
- EC-04: Total ausencia de métodos de interacción activa.
- Resiliencia: Timeout acotado por frame (2.5 s) y sondeo asíncrono no bloqueante
  limitado a máximo 3.0 segundos, respetando el SLA global de 25 segundos (EC-01).
- Tratamiento de Shadow DOM cerrado: Detección sin penalización de puntaje y catalogación
  como controles no verificables pasivamente.
"""

import asyncio
import urllib.parse
from typing import Dict, List, Any, Optional
from playwright.async_api import Page, Frame

from .trackers_db import (
    CMP_SIGNATURES,
    CMP_FRAME_DOMAINS,
    BANNER_BUTTON_TEXTS
)

REJECT_KEYWORDS = [
    "rechazar", "rechazar todas", "rechazar todo", "rechaza", "denegar", "no acepto",
    "continuar sin aceptar", "solo necesarias", "solo las necesarias", "cookies necesarias",
    "necesarias solamente", "solo esenciales", "reject", "reject all", "decline", "decline all",
    "necessary only", "essential only", "disagree"
]

ACCEPT_KEYWORDS = [
    "aceptar", "aceptar todas", "aceptar todo", "aceptar cookies", "acepta", "acepto",
    "permitir", "permitir todas", "permitir todo", "entendido", "de acuerdo",
    "accept", "accept all", "allow all", "agree"
]

SETTINGS_KEYWORDS = [
    "configurar", "configurar cookies", "configuración", "personalizar", "preferencias",
    "gestionar", "gestionar preferencias", "opciones", "settings", "cookie settings",
    "manage preferences", "more options", "más información"
]

JS_INSPECTION_SCRIPT = """
(data) => {
    const cmpSignatures = data.cmp_signatures || {};
    const buttonTexts = data.button_texts || [];

    function queryAllDeep(selector, root = document) {
        const found = [];
        const queue = [root];
        while (queue.length > 0) {
            const current = queue.shift();
            try {
                if (current.querySelectorAll) {
                    const matches = current.querySelectorAll(selector);
                    for (let el of matches) {
                        found.push(el);
                    }
                }
            } catch (e) {}

            try {
                const all = current.querySelectorAll ? current.querySelectorAll('*') : [];
                for (let el of all) {
                    if (el.shadowRoot) {
                        queue.push(el.shadowRoot);
                    }
                }
            } catch (e) {}
        }
        return found;
    }

    function isVisible(el) {
        if (!el) return false;
        try {
            const style = window.getComputedStyle(el);
            if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
                return false;
            }
            const rect = el.getBoundingClientRect();
            return (rect.width > 0 && rect.height > 0) || (el.clientWidth > 0 && el.clientHeight > 0);
        } catch (e) {
            return false;
        }
    }

    function extractButtons(container) {
        const buttons = [];
        const queue = [container];
        while (queue.length > 0) {
            const cur = queue.shift();
            try {
                if (cur.querySelectorAll) {
                    const candidateNodes = cur.querySelectorAll('button, [role="button"], a[role="button"], input[type="button"], input[type="submit"], a.btn, a.button, a');
                    for (let el of candidateNodes) {
                        const txt = (el.innerText || el.textContent || el.value || '').trim();
                        if (!txt || txt.length > 80) continue;

                        const isBtnRole = el.tagName === 'BUTTON' || el.tagName === 'INPUT' ||
                                         el.getAttribute('role') === 'button' ||
                                         el.classList.contains('button') || el.classList.contains('btn');
                        const matchesCmpText = buttonTexts.some(kw => txt.toLowerCase().includes(kw.toLowerCase()));

                        if (isBtnRole || matchesCmpText) {
                            if (isVisible(el) && !buttons.includes(txt)) {
                                buttons.push(txt);
                            }
                        }
                    }
                }
                const all = cur.querySelectorAll ? cur.querySelectorAll('*') : [];
                for (let el of all) {
                    if (el.shadowRoot) {
                        queue.push(el.shadowRoot);
                    }
                }
            } catch (e) {}
        }
        return buttons;
    }

    // Estrategia 1: Firmas de CMPs conocidos
    for (const [cmpName, info] of Object.entries(cmpSignatures)) {
        const selectors = info.selectors || [];
        for (const sel of selectors) {
            const matches = queryAllDeep(sel);
            for (const el of matches) {
                if (isVisible(el)) {
                    const isClosedShadow = (
                        el.shadowRoot === null &&
                        el.children.length === 0 &&
                        (el.tagName.includes('-') || el.getAttribute('data-shadow') === 'closed')
                    );
                    const buttons = isClosedShadow ? [] : extractButtons(el);
                    return {
                        banner_detected: true,
                        cmp_provider: cmpName,
                        buttons_verifiable: !isClosedShadow,
                        detected_buttons: buttons,
                        container_selector: sel
                    };
                }
            }
        }
        if (info.container_id) {
            const matches = queryAllDeep('#' + info.container_id);
            for (const el of matches) {
                if (isVisible(el)) {
                    const isClosedShadow = (
                        el.shadowRoot === null &&
                        el.children.length === 0 &&
                        (el.tagName.includes('-') || el.getAttribute('data-shadow') === 'closed')
                    );
                    const buttons = isClosedShadow ? [] : extractButtons(el);
                    return {
                        banner_detected: true,
                        cmp_provider: cmpName,
                        buttons_verifiable: !isClosedShadow,
                        detected_buttons: buttons,
                        container_selector: '#' + info.container_id
                    };
                }
            }
        }
    }

    // Estrategia 3: Heurística genérica en contenedores visibles
    const genericCandidates = queryAllDeep('div, section, aside, dialog');
    for (const el of genericCandidates) {
        if (!isVisible(el)) continue;

        const text = (el.innerText || el.textContent || '').toLowerCase();
        if (text.length > 20 && text.length < 4000 && (
            text.includes('cookie') || text.includes('cookies') ||
            text.includes('consentimiento') || text.includes('privacidad') ||
            text.includes('consent')
        )) {
            const style = window.getComputedStyle(el);
            const pos = style.position;
            const isModal = el.getAttribute('role') === 'dialog' || el.getAttribute('role') === 'alertdialog' || el.tagName === 'DIALOG';
            const isFloating = pos === 'fixed' || pos === 'sticky' ||
                              (pos === 'absolute' && (parseInt(style.zIndex, 10) > 100 || style.bottom === '0px' || style.top === '0px'));

            const hasCmpClassOrId = (
                el.id.toLowerCase().includes('cookie') || el.id.toLowerCase().includes('consent') ||
                el.className.toLowerCase().includes('cookie') || el.className.toLowerCase().includes('consent')
            );

            if (isFloating || isModal || hasCmpClassOrId) {
                const buttons = extractButtons(el);
                const hasMatchingBtn = buttons.some(b => buttonTexts.some(kw => b.toLowerCase().includes(kw.toLowerCase())));
                if (buttons.length > 0 && (hasMatchingBtn || isFloating || isModal)) {
                    return {
                        banner_detected: true,
                        cmp_provider: null,
                        buttons_verifiable: true,
                        detected_buttons: buttons,
                        container_selector: 'generic'
                    };
                }
            }
        }
    }

    return {
        banner_detected: false,
        cmp_provider: null,
        buttons_verifiable: true,
        detected_buttons: [],
        container_selector: null
    };
}
"""

JS_FRAME_EXTRACT_ALL_BUTTONS = """
() => {
    function isVisible(el) {
        if (!el) return false;
        try {
            const style = window.getComputedStyle(el);
            if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
                return false;
            }
            const rect = el.getBoundingClientRect();
            return (rect.width > 0 && rect.height > 0) || (el.clientWidth > 0 && el.clientHeight > 0);
        } catch (e) {
            return false;
        }
    }

    const buttons = [];
    try {
        const candidateNodes = document.querySelectorAll('button, [role="button"], a[role="button"], input[type="button"], input[type="submit"], a.btn, a.button');
        for (let el of candidateNodes) {
            if (isVisible(el)) {
                const txt = (el.innerText || el.textContent || el.value || '').trim();
                if (txt && txt.length < 80 && !buttons.includes(txt)) {
                    buttons.push(txt);
                }
            }
        }
    } catch (e) {}
    return buttons;
}
"""


class ConsentDetector:
    """
    Detector pasivo de banners de consentimiento y gestores CMP.
    Cumple estrictamente DA-01 al no ejecutar métodos de mutación ni clics.
    """

    @classmethod
    async def detect_consent(
        cls,
        page: Page,
        target_url: str,
        max_poll_seconds: float = 3.0
    ) -> Dict[str, Any]:
        """
        Ejecuta la auditoría pasiva de frames y detección de banner con sondeo acotado.
        """
        parsed_target = urllib.parse.urlparse(target_url)
        target_domain = parsed_target.netloc.lower()

        # Sondeo acotado en intervalos de 0.5s hasta un máximo de max_poll_seconds
        start_time = asyncio.get_event_loop().time()
        elapsed = 0.0

        banner_result: Optional[Dict[str, Any]] = None
        frames_audit_result: Optional[Dict[str, Any]] = None

        while elapsed <= max_poll_seconds:
            frames_audit_result, banner_result = await cls._inspect_frames_and_dom(
                page, target_domain
            )
            if banner_result and banner_result.get("banner_detected"):
                break

            await asyncio.sleep(0.5)
            elapsed = asyncio.get_event_loop().time() - start_time

        if not banner_result:
            banner_result = {
                "banner_detected": False,
                "cmp_provider": None,
                "has_reject_option": False,
                "has_accept_option": False,
                "has_settings_option": False,
                "detected_buttons": [],
                "banner_source_frame": None,
                "buttons_verifiable": True,
                "blocks_prior_to_consent": None
            }

        if not frames_audit_result:
            frames_audit_result = {
                "total_frames": 1,
                "third_party_frames": 0,
                "cmp_frames": 0,
                "frames": []
            }

        return {
            "consent_banner_audit": banner_result,
            "frames_audit": frames_audit_result
        }

    @classmethod
    async def _inspect_frames_and_dom(
        cls,
        page: Page,
        target_domain: str
    ) -> tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Inspecciona hasta 15 frames concurrentes con evaluación aislada.
        """
        frames = page.frames[:15]
        total_frames = len(frames)
        third_party_count = 0
        cmp_frames_count = 0
        frames_info_list: List[Dict[str, Any]] = []

        detected_banner_data: Optional[Dict[str, Any]] = None

        eval_payload = {
            "cmp_signatures": CMP_SIGNATURES,
            "button_texts": BANNER_BUTTON_TEXTS
        }

        for frame in frames:
            frame_url = frame.url or ""
            origin = "about:blank"
            frame_domain = ""

            if frame_url and frame_url != "about:blank":
                try:
                    parsed = urllib.parse.urlparse(frame_url)
                    origin = f"{parsed.scheme}://{parsed.netloc}"
                    frame_domain = parsed.netloc.lower()
                except Exception:
                    origin = frame_url

            # Determinar si es de terceros
            is_third_party = False
            if frame_domain and target_domain:
                is_third_party = (
                    frame_domain != target_domain and
                    not frame_domain.endswith("." + target_domain)
                )
                if is_third_party:
                    third_party_count += 1

            # Determinar si el frame pertenece a un CMP conocido (Estrategia 2)
            is_cmp_frame = False
            detected_cmp_name = None

            for cmp_name, cmp_info in CMP_SIGNATURES.items():
                domains = cmp_info.get("frame_domains", [])
                if any(dom in frame_domain for dom in domains):
                    is_cmp_frame = True
                    detected_cmp_name = cmp_name
                    break

            if not is_cmp_frame and any(dom in frame_domain for dom in CMP_FRAME_DOMAINS):
                is_cmp_frame = True

            if is_cmp_frame:
                cmp_frames_count += 1

            frames_info_list.append({
                "url": frame_url,
                "origin": origin,
                "is_third_party": is_third_party,
                "is_cmp_frame": is_cmp_frame,
                "detected_cmp": detected_cmp_name
            })

            # Si aún no hemos detectado el banner, evaluamos este frame con timeout acotado
            if not detected_banner_data:
                try:
                    res = await asyncio.wait_for(
                        frame.evaluate(JS_INSPECTION_SCRIPT, eval_payload),
                        timeout=2.5
                    )
                    if res and res.get("banner_detected"):
                        detected_banner_data = res
                        detected_banner_data["banner_source_frame"] = frame_url
                        if is_cmp_frame and not detected_banner_data.get("cmp_provider"):
                            detected_banner_data["cmp_provider"] = detected_cmp_name
                except Exception:
                    pass

                # Si es un frame de un CMP conocido y no se detectó por script anterior,
                # intentar extraer botones directamente dentro del frame
                if not detected_banner_data and is_cmp_frame:
                    try:
                        frame_buttons = await asyncio.wait_for(
                            frame.evaluate(JS_FRAME_EXTRACT_ALL_BUTTONS),
                            timeout=2.5
                        )
                        detected_banner_data = {
                            "banner_detected": True,
                            "cmp_provider": detected_cmp_name,
                            "buttons_verifiable": True,
                            "detected_buttons": frame_buttons or [],
                            "banner_source_frame": frame_url
                        }
                    except Exception:
                        pass

        # Procesar botones y opciones si se detectó banner
        if detected_banner_data and detected_banner_data.get("banner_detected"):
            buttons = detected_banner_data.get("detected_buttons", [])
            buttons_verifiable = detected_banner_data.get("buttons_verifiable", True)

            has_reject = False
            has_accept = False
            has_settings = False

            if buttons_verifiable and buttons:
                has_reject = any(
                    any(kw in btn.lower() for kw in REJECT_KEYWORDS)
                    for btn in buttons
                )
                has_accept = any(
                    any(kw in btn.lower() for kw in ACCEPT_KEYWORDS)
                    for btn in buttons
                )
                has_settings = any(
                    any(kw in btn.lower() for kw in SETTINGS_KEYWORDS)
                    for btn in buttons
                )

            final_banner_audit = {
                "banner_detected": True,
                "cmp_provider": detected_banner_data.get("cmp_provider"),
                "has_reject_option": has_reject,
                "has_accept_option": has_accept,
                "has_settings_option": has_settings,
                "detected_buttons": buttons,
                "banner_source_frame": detected_banner_data.get("banner_source_frame"),
                "buttons_verifiable": buttons_verifiable,
                "blocks_prior_to_consent": None  # Se evalúa en rules_engine según presencia de trackers
            }
        else:
            final_banner_audit = {
                "banner_detected": False,
                "cmp_provider": None,
                "has_reject_option": False,
                "has_accept_option": False,
                "has_settings_option": False,
                "detected_buttons": [],
                "banner_source_frame": None,
                "buttons_verifiable": True,
                "blocks_prior_to_consent": None
            }

        frames_audit = {
            "total_frames": total_frames,
            "third_party_frames": third_party_count,
            "cmp_frames": cmp_frames_count,
            "frames": frames_info_list
        }

        return frames_audit, final_banner_audit
