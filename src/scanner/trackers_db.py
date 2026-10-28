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
    "get_tracker_category",
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
    "acceso",
    "rectificacion",
    "rectificación",
    "cancelacion",
    "cancelación",
    "oposicion",
    "oposición",
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

def get_tracker_category(name_or_domain: str) -> str:
    """
    Clasifica un rastreador o cookie en categorías normativas:
    'analítica', 'publicidad', 'redes_sociales', 'grabación_sesión'.
    """
    target = name_or_domain.lower()
    if any(k in target for k in ["facebook", "meta", "tiktok", "twitter", "licdn", "linkedin", "_fbp", "_fbc", "fr", "_tt"]):
        return "redes_sociales"
    if any(k in target for k in ["doubleclick", "criteo", "googleadservices", "taboola", "outbrain", "adroll", "_gcl_au"]):
        return "publicidad"
    if any(k in target for k in ["hotjar", "clarity", "crazyegg", "mouseflow", "inspectlet", "_hj", "_clck", "_clsk"]):
        return "grabación_sesión"
    return "analítica"
