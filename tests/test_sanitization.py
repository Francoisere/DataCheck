import pytest
from src.core.sanitizer import sanitize_url


def test_sanitize_url_strips_credentials():
    raw = "https://user:pass@sitio.cl/?token=secret#top"
    normalized, domain = sanitize_url(raw)
    assert normalized == "https://sitio.cl/"
    assert domain == "sitio.cl"
    assert "user" not in normalized
    assert "pass" not in normalized
    assert "secret" not in normalized


def test_sanitize_url_preserves_path_without_query():
    raw = "http://tienda.cl/productos/detalle?utm_source=fb&gclid=123"
    normalized, domain = sanitize_url(raw)
    assert normalized == "http://tienda.cl/productos/detalle"
    assert domain == "tienda.cl"
    assert "utm_source" not in normalized


def test_sanitize_url_prepends_https():
    raw = "bancochile.cl"
    normalized, domain = sanitize_url(raw)
    assert normalized == "https://bancochile.cl/"
    assert domain == "bancochile.cl"


def test_sanitize_url_invalid_empty():
    with pytest.raises(ValueError):
        sanitize_url("   ")
