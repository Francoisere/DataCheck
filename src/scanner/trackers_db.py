"""
Base de datos de firmas de dominios y cookies de rastreo no esenciales.
Utilizada para contrastar tráfico saliente y cookies depositadas antes del consentimiento.
"""

__all__ = [
    "KNOWN_TRACKER_DOMAINS",
    "KNOWN_TRACKER_COOKIES",
    "TRACKER_COOKIES_EXACT",
    "TRACKER_COOKIES_PREFIX",
    "is_tracker_cookie",
    "MANDATORY_LEGAL_KEYWORDS",
    "ARCO_KEYWORDS",
    "CMP_SIGNATURES",
    "CMP_FRAME_DOMAINS",
    "BANNER_BUTTON_TEXTS",
    "TAG_MANAGER_DOMAINS",
    "LOW_INVASIVENESS_COOKIES",
    "INVASIVENESS_WEIGHTS",
    "get_tracker_category",
    "get_tracker_invasiveness",
    "calculate_trackers_penalty",
]

KNOWN_TRACKER_DOMAINS = [
    # Google Analytics / Tag Manager / Ads
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "googleadservices.com",
    "analytics.google.com",

    # Meta / Facebook
    "connect.facebook.net",
    "facebook.com/tr",
    "pixel.facebook.com",

    # Hotjar / UX Tracking
    "hotjar.com",
    "static.hotjar.com",
    "script.hotjar.com",

    # TikTok
    "analytics.tiktok.com",
    "analytics-sg.tiktok.com",

    # Twitter / X
    "static.ads-twitter.com",
    "analytics.twitter.com",

    # LinkedIn
    "snap.licdn.com",
    "px.ads.linkedin.com",

    # Criteo / Taboola / Outbrain / Adroll
    "criteo.com",
    "criteo.net",
    "taboola.com",
    "outbrain.com",
    "adroll.com",

    # Mixpanel / Amplitude / Clarity
    "cdn.mxpnl.com",
    "api.mixpanel.com",
    "amplitude.com",
    "api.amplitude.com",
    "clarity.ms",

    # Yandex / Matomo / Hubspot
    "mc.yandex.ru",
    "hs-scripts.com",
    "js.hs-analytics.net",

    # CrazyEgg / Mouseflow / Inspectlet
    "crazyegg.com",
    "mouseflow.com",
    "inspectlet.com"
]

# Cookies that must match exactly (case-sensitive)
TRACKER_COOKIES_EXACT = {
    "_ga", "_gid", "_gat", "AMP_TOKEN",
    "_fbp", "_fbc", "fr",
    "_hjid", "_hjFirstSeen", "_hjAbsoluteSessionInProgress",
    "_tt_enable_cookie", "_ttp",
    "hubspotutk", "__hssrc", "__hstc",
    "li_sugr", "bcookie", "bscookie",
    "_clck", "_clsk",
}

# Cookies that match by prefix (e.g. _gac_UA12345, _hjSession_12345)
TRACKER_COOKIES_PREFIX = [
    "_gac_", "_gcl_au",
    "_hjSession_",
    "_ga_",  # GA4 measurement ID cookies like _ga_XXXXXXX
]

# Keep backward-compatible KNOWN_TRACKER_COOKIES as a flat list for any code that imports it
KNOWN_TRACKER_COOKIES = list(TRACKER_COOKIES_EXACT) + TRACKER_COOKIES_PREFIX


def is_tracker_cookie(name: str) -> bool:
    """Determina si una cookie es de rastreo usando coincidencia exacta o por prefijo.
    
    Resuelve el problema de falsos positivos donde firmas cortas como 'fr'
    coincidían con nombres inocuos como 'lang_fr' mediante `any(tk in name ...)`.
    """
    if name in TRACKER_COOKIES_EXACT:
        return True
    return any(name.startswith(prefix) for prefix in TRACKER_COOKIES_PREFIX)


MANDATORY_LEGAL_KEYWORDS = [
    "titular",
    "responsable",
    "derechos",
    "tratamiento",
    "finalidad",
    "contacto",
    "datos personales"
]

ARCO_KEYWORDS = [
    "arco",
    "arcop",
    "acceso",
    "rectificacion",
    "rectificación",
    "cancelacion",
    "cancelación",
    "supresion",
    "supresión",
    "oposicion",
    "oposición",
    "portabilidad",
    "bloqueo",
    "derechos del titular",
    "ejercicio de derechos"
]

CMP_SIGNATURES = {
    "cookiebot": {
        "frame_domains": ["consentcdn.cookiebot.com", "consent.cookiebot.com"],
        "selectors": ["#CybotCookiebotDialog", "#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll"],
        "container_id": "CybotCookiebotDialog",
    },
    "onetrust": {
        "frame_domains": ["cdn.cookielaw.org", "optanon.blob.core.windows.net"],
        "selectors": ["#onetrust-banner-sdk", "#onetrust-accept-btn-handler", "#onetrust-reject-all-handler"],
        "container_id": "onetrust-banner-sdk",
    },
    "didomi": {
        "frame_domains": ["sdk.privacy-center.org", "privacy-center.org"],
        "selectors": ["#didomi-host", "#didomi-notice", ".didomi-popup-container"],
        "container_id": "didomi-host",
    },
    "usercentrics": {
        "frame_domains": ["app.usercentrics.eu", "usercentrics.eu"],
        "selectors": ["#usercentrics-root", "[data-testid='uc-banner']"],
        "container_id": "usercentrics-root",
    },
    "iubenda": {
        "frame_domains": ["cdn.iubenda.com", "cs.iubenda.com"],
        "selectors": [".iubenda-cs-container", "#iubenda-cs-banner"],
        "container_id": "iubenda-cs-banner",
    },
    "quantcast": {
        "frame_domains": ["quantcast.mgr.consensu.org", "cmp.quantcast.com"],
        "selectors": [".qc-cmp2-container", ".qc-cmp-ui-container"],
        "container_id": None,
    },
    "hubspot_cookie_banner": {
        "frame_domains": [],
        "selectors": ["#hs-eu-cookie-confirmation", "#hs-eu-confirmation-button"],
        "container_id": "hs-eu-cookie-confirmation",
    },
    "sourcepoint": {
        "frame_domains": ["sourcepoint.mgr.consensu.org", "cdn.privacy-mgmt.com", "sp-prod.net"],
        "selectors": ["[id^='sp_message_container']", ".sp_message_container", "iframe[id^='sp_message_iframe']"],
        "container_id": "sp_message_container",
    },
    "trustarc": {
        "frame_domains": ["consent.trustarc.com", "trustarc.com"],
        "selectors": ["#truste-consent-track", "#truste-consent-button", ".truste-banner", "#trustarc-banner-overlay"],
        "container_id": "truste-consent-track",
    },
}

# All CMP frame domains flattened for quick lookup
CMP_FRAME_DOMAINS = []
for _cmp in CMP_SIGNATURES.values():
    CMP_FRAME_DOMAINS.extend(_cmp["frame_domains"])

# Banner button text patterns in Spanish and English for read-only detection
BANNER_BUTTON_TEXTS = [
    # Spanish
    "aceptar", "aceptar todas", "aceptar todo", "aceptar cookies",
    "rechazar", "rechazar todas", "rechazar todo",
    "configurar", "configurar cookies", "personalizar",
    "solo necesarias", "solo las necesarias", "cookies necesarias",
    "gestionar preferencias", "más información",
    # English
    "accept", "accept all", "accept cookies",
    "reject", "reject all", "decline", "decline all",
    "settings", "cookie settings", "manage preferences",
    "necessary only", "essential only",
]

# Dominios y sufijos exactos para clasificación libre de falsos positivos (N2)
SOCIAL_DOMAINS = {
    "facebook.com", "connect.facebook.net", "pixel.facebook.com",
    "tiktok.com", "analytics.tiktok.com", "analytics-sg.tiktok.com",
    "twitter.com", "ads-twitter.com", "static.ads-twitter.com",
    "linkedin.com", "licdn.com", "snap.licdn.com", "px.ads.linkedin.com",
    "instagram.com", "pinterest.com"
}
SOCIAL_COOKIES = {
    "_fbp", "_fbc", "fr", "_tt_enable_cookie", "_ttp", "li_sugr", "bcookie", "bscookie"
}

ADS_DOMAINS = {
    "doubleclick.net", "googleadservices.com", "googlesyndication.com",
    "pagead2.googlesyndication.com", "adservice.google.com",
    "criteo.com", "criteo.net", "taboola.com", "outbrain.com", "adroll.com"
}
ADS_COOKIES = {"_gcl_au"}
ADS_COOKIES_PREFIX = ("_gac_",)

RECORDING_DOMAINS = {
    "hotjar.com", "static.hotjar.com", "script.hotjar.com",
    "clarity.ms", "crazyegg.com", "mouseflow.com", "inspectlet.com"
}
RECORDING_COOKIES_EXACT = {
    "_hjid", "_hjfirstseen", "_hjabsolutesessioninprogress", "_clck", "_clsk"
}
RECORDING_COOKIES_PREFIX = ("_hjsession_",)

# Nivel de invasividad y pesos de penalización sobre el pilar Consentimiento & Cookies (35 pts)
TAG_MANAGER_DOMAINS = {"googletagmanager.com"}
LOW_INVASIVENESS_COOKIES = {"_gat", "__hssrc", "_tt_enable_cookie"}

INVASIVENESS_WEIGHTS = {
    "BAJA": 3,
    "MEDIA": 5,
    "ALTA": 8,
    "CRITICA": 10,
}

_LEVEL_ORDER = {
    "NINGUNA": 0,
    "BAJA": 1,
    "MEDIA": 2,
    "ALTA": 3,
    "CRITICA": 4,
}

_LEVEL_DESCRIPTIONS = {
    "BAJA": "Gestor de etiquetas o cookie técnica de limitación de tasa/estado sin perfilamiento individual",
    "MEDIA": "Analítica estadística agregada o medición de audiencia",
    "ALTA": "Grabación de sesión, reproducción de interacciones o mapa de calor",
    "CRITICA": "Publicidad conductual, retargeting cross-site o píxel de red social",
}


def get_tracker_category(name_or_domain: str) -> str:
    """
    Clasifica un rastreador o cookie en categorías normativas:
    'analítica', 'publicidad', 'redes_sociales', 'grabación_sesión'.
    Usa coincidencia exacta de cookies y sufijos canónicos de dominio para evitar
    falsos positivos causados por subcadenas cortas (N2).
    """
    raw = name_or_domain.strip().lower()
    # Si viene con protocolo o ruta (ej. 'facebook.com/tr'), extraer dominio
    domain = raw.split("://")[-1].split("/")[0].split(":")[0]

    # 1. Redes sociales
    if raw in SOCIAL_COOKIES:
        return "redes_sociales"
    if any(domain == s or domain.endswith("." + s) for s in SOCIAL_DOMAINS):
        return "redes_sociales"

    # 2. Publicidad
    if raw in ADS_COOKIES or any(raw.startswith(p) for p in ADS_COOKIES_PREFIX):
        return "publicidad"
    if any(domain == a or domain.endswith("." + a) for a in ADS_DOMAINS):
        return "publicidad"

    # 3. Grabación de sesión / UX
    if raw in RECORDING_COOKIES_EXACT or any(raw.startswith(p) for p in RECORDING_COOKIES_PREFIX):
        return "grabación_sesión"
    if any(domain == r or domain.endswith("." + r) for r in RECORDING_DOMAINS):
        return "grabación_sesión"

    # 4. Analítica por defecto
    return "analítica"


def get_tracker_invasiveness(name_or_domain: str) -> dict:
    """
    Clasifica un dominio o cookie de rastreo según su nivel de invasividad
    y retorna el peso de penalización correspondiente en el pilar Consentimiento (35 pts):
    - BAJA (-3 pts): Gestores de etiquetas y cookies técnicas de control de tasa/estado.
    - MEDIA (-5 pts): Analítica estadística agregada.
    - ALTA (-8 pts): Grabación de sesión y mapas de calor.
    - CRITICA (-10 pts): Publicidad conductual, retargeting y píxeles de redes sociales.
    """
    raw = name_or_domain.strip().lower()
    domain = raw.split("://")[-1].split("/")[0].split(":")[0]

    if any(domain == t or domain.endswith("." + t) for t in TAG_MANAGER_DOMAINS):
        category = "gestor_etiquetas"
        level = "BAJA"
    elif raw in LOW_INVASIVENESS_COOKIES:
        category = get_tracker_category(name_or_domain)
        level = "BAJA"
    else:
        category = get_tracker_category(name_or_domain)
        if category in ("publicidad", "redes_sociales"):
            level = "CRITICA"
        elif category == "grabación_sesión":
            level = "ALTA"
        else:
            level = "MEDIA"

    return {
        "item": name_or_domain,
        "category": category,
        "level": level,
        "penalty": INVASIVENESS_WEIGHTS[level],
        "description": _LEVEL_DESCRIPTIONS[level],
    }


def calculate_trackers_penalty(domains: list, cookies: list) -> dict:
    """
    Calcula la penalización gradual acumulada para las listas de dominios
    y cookies detectadas pre-consentimiento.
    """
    domain_penalties = [get_tracker_invasiveness(d) for d in (domains or [])]
    cookie_penalties = [get_tracker_invasiveness(c) for c in (cookies or [])]

    domain_penalty_sum = sum(p["penalty"] for p in domain_penalties)
    cookie_penalty_sum = sum(p["penalty"] for p in cookie_penalties)
    total_penalty = domain_penalty_sum + cookie_penalty_sum

    all_levels = [p["level"] for p in domain_penalties + cookie_penalties]
    max_level = max(all_levels, key=lambda lvl: _LEVEL_ORDER[lvl]) if all_levels else "NINGUNA"

    return {
        "total_penalty": total_penalty,
        "domain_penalties": domain_penalties,
        "cookie_penalties": cookie_penalties,
        "domain_penalty_sum": domain_penalty_sum,
        "cookie_penalty_sum": cookie_penalty_sum,
        "max_level": max_level,
    }
