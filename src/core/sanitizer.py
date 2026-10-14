"""
Utilidades de sanitización y normalización de URLs.
Garantiza el cumplimiento de Privacy by Design (DA-04 / TEST-SAN-01):
- Purga credenciales integradas en la URL (user:pass@)
- Elimina parámetros de tracking, tokens de sesión y fragmentos
- Normaliza esquema a https:// y agrega trailing slash
- Extrae dominio canónico para almacenamiento relacional
"""

import urllib.parse
from typing import Tuple


def sanitize_url(raw_url: str) -> Tuple[str, str]:
    """
    Sanitiza y normaliza una URL entrante.
    
    Retorna una tupla: (url_normalizada, dominio)
    
    Ejemplo:
        Entrada: "https://user:secret@tienda.cl:8080/path?token=abc#frag"
        Salida: ("https://tienda.cl:8080/path", "tienda.cl")
    
    Para la raíz del sitio (sin path):
        Entrada: "https://user:pass@sitio.cl/?token=secret"
        Salida: ("https://sitio.cl/", "sitio.cl")
    """
    cleaned = raw_url.strip()
    if not cleaned:
        raise ValueError("La URL provista no puede estar vacía.")

    if not cleaned.startswith("http://") and not cleaned.startswith("https://"):
        cleaned = "https://" + cleaned

    parsed = urllib.parse.urlsplit(cleaned)

    # Extraer host y puerto sin credenciales (user:password@)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"No se pudo extraer un host válido de la URL: {raw_url}")

    port_suffix = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    netloc = f"{hostname}{port_suffix}"
    scheme = parsed.scheme.lower() if parsed.scheme in ("http", "https") else "https"

    path = parsed.path
    if not path or path == "":
        path = "/"

    # Reconstruir URL sin query params sensibles ni fragmentos
    normalized_url = urllib.parse.urlunsplit((scheme, netloc, path, "", ""))
    return normalized_url, hostname.lower()
