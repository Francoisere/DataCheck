"""
Pruebas de Sanitización y Normalización de URLs (FB-01 / FB-06 / PBI-05).
"""

import pytest
from src.core.sanitizer import sanitize_url


def test_sanitizer_strips_query_and_fragment():
    """Caso 1: Eliminar query parameters y fragmentos identificadores."""
    raw = "https://tienda.cl/checkout?session_id=abc123xyz&ref=promo#payment"
    normalized, domain = sanitize_url(raw)
    assert normalized == "https://tienda.cl/checkout"
    assert domain == "tienda.cl"
    assert "session_id" not in normalized
    assert "abc123xyz" not in normalized
    assert "payment" not in normalized


def test_sanitizer_strips_embedded_credentials():
    """Caso 2: Remover credenciales de autenticación básica (user:pass)."""
    raw = "https://admin:super_secret_pwd@portal.empresa.cl/dashboard"
    normalized, domain = sanitize_url(raw)
    assert normalized == "https://portal.empresa.cl/dashboard"
    assert "admin" not in normalized
    assert "super_secret_pwd" not in normalized
    assert domain == "portal.empresa.cl"


def test_sanitizer_prepends_https_when_missing_scheme():
    """Caso 3: Anteponer esquema seguro https:// si la URL no incluye protocolo."""
    raw = "gob.cl"
    normalized, domain = sanitize_url(raw)
    assert normalized == "https://gob.cl/"
    assert domain == "gob.cl"


def test_sanitizer_rejects_non_http_schemes():
    """Caso 4: Rechazar estrictamente esquemas no autorizados (file, ftp, javascript, data)."""
    invalid_urls = [
        "file:///etc/passwd",
        "ftp://ftp.servidor.cl/datos",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "gopher://antiguo.cl"
    ]
    for url in invalid_urls:
        with pytest.raises(ValueError):
            sanitize_url(url)


def test_sanitizer_rejects_empty_or_whitespace_urls():
    """Caso 5: Rechazar cadenas vacías o compuestas exclusivamente de espacios."""
    for empty in ["", "   ", "\t\n"]:
        with pytest.raises(ValueError):
            sanitize_url(empty)
