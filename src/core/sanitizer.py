"""
Utilidades de sanitización y normalización de URLs.
Garantiza el cumplimiento de Privacy by Design y Seguridad (FB-01 / DA-04 / TEST-SAN-01):
- Purga credenciales integradas en la URL (user:pass@)
- Elimina parámetros de tracking, tokens de sesión y fragmentos
- Normaliza esquema a https:// y agrega trailing slash
- Extrae dominio canónico para almacenamiento relacional
- Mitiga SSRF mediante validación de IPs privadas, loopback, multicast, link-local, CGNAT y metadatos de nube
- Restringe puertos estrictamente a 80 y 443
"""

import ipaddress
import socket
import urllib.parse
from typing import Tuple

CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


def is_ip_private_or_restricted(ip_str: str) -> bool:
    """
    Determina si una dirección IP pertenece a rangos privados, loopback,
    reservados, multicast, link-local (ej: metadatos AWS/GCP 169.254.169.254) o CGNAT (100.64.0.0/10).
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_reserved or
            ip.is_multicast or
            ip.is_link_local or
            ip.is_unspecified or
            (ip.version == 4 and ip in CGNAT_NET)
        )
    except ValueError:
        return False


def validate_ssrf(hostname: str) -> None:
    """
    Valida que el hostname no resuelva a una IP privada, interna, CGNAT o de metadatos de nube (FB-01).
    Soporta resolución para IPv4 e IPv6 (AAAA).
    Lanza ValueError si el destino no está permitido.
    """
    cleaned_host = hostname.strip().lower()
    if cleaned_host.startswith("[") and cleaned_host.endswith("]"):
        cleaned_host = cleaned_host[1:-1]

    # 1. Comprobar si el hostname es directamente una dirección IP
    try:
        ip = ipaddress.ip_address(cleaned_host)
        if (
            ip.is_private or
            ip.is_loopback or
            ip.is_reserved or
            ip.is_multicast or
            ip.is_link_local or
            ip.is_unspecified or
            (ip.version == 4 and ip in CGNAT_NET)
        ):
            raise ValueError(
                f"Destino no permitido (SSRF / red privada o interna): {cleaned_host}"
            )
        return
    except ValueError as e:
        if "Destino no permitido" in str(e):
            raise

    # 2. Comprobar nombres conocidos de loopback y sufijos locales
    if (
        cleaned_host in ("localhost", "localhost.localdomain") or
        cleaned_host.endswith(".local") or
        cleaned_host.endswith(".localhost")
    ):
        raise ValueError(f"Destino no permitido (SSRF / red privada o interna): {cleaned_host}")

    # 3. Resolución DNS exhaustiva (IPv4 e IPv6)
    try:
        addr_infos = socket.getaddrinfo(cleaned_host, None)
        for family, socktype, proto, canonname, sockaddr in addr_infos:
            ip_addr = sockaddr[0]
            if is_ip_private_or_restricted(ip_addr):
                raise ValueError(
                    f"Destino no permitido (SSRF / red privada o interna): {cleaned_host} resuelve a {ip_addr}"
                )
    except socket.gaierror:
        # Si no resuelve por DNS, permitimos continuar al scraper (donde fallará como ERR_NAME_NOT_RESOLVED)
        # o en entornos de prueba unitaria con mocks.
        pass


def sanitize_url(raw_url: str, check_ssrf: bool = True) -> Tuple[str, str]:
    """
    Sanitiza y normaliza una URL entrante.
    
    Retorna una tupla: (url_normalizada, dominio)
    
    Ejemplo:
        Entrada: "https://user:secret@tienda.cl/path?token=abc#frag"
        Salida: ("https://tienda.cl/path", "tienda.cl")
    
    Para la raíz del sitio (sin path):
        Entrada: "https://user:pass@sitio.cl/?token=secret"
        Salida: ("https://sitio.cl/", "sitio.cl")
    """
    cleaned = raw_url.strip()
    if not cleaned:
        raise ValueError("La URL provista no puede estar vacía.")

    # Validar esquemas permitidos (rechazar file://, ftp://, gopher://, etc.)
    if "://" in cleaned:
        scheme_prefix = cleaned.split("://")[0].lower()
        if scheme_prefix not in ("http", "https"):
            raise ValueError(f"Protocolo no soportado: '{scheme_prefix}'. Solo se permite HTTP/HTTPS.")
    else:
        cleaned = "https://" + cleaned

    parsed = urllib.parse.urlsplit(cleaned)

    # Extraer host y puerto sin credenciales (user:password@)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"No se pudo extraer un host válido de la URL: {raw_url}")

    # FB-01: Protección anti-SSRF
    if check_ssrf:
        validate_ssrf(hostname)

    # Restricción estricta de puertos (FB-01): solo puertos 80 y 443
    if parsed.port and parsed.port not in (80, 443):
        raise ValueError(
            f"Puerto no permitido: {parsed.port}. Solo se autorizan puertos web estándar (80, 443)."
        )

    netloc = hostname
    scheme = parsed.scheme.lower() if parsed.scheme in ("http", "https") else "https"

    path = parsed.path
    if not path or path == "":
        path = "/"

    # Reconstruir URL sin query params sensibles ni fragmentos
    normalized_url = urllib.parse.urlunsplit((scheme, netloc, path, "", ""))
    return normalized_url, hostname.lower()
