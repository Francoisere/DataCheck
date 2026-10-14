import pytest
from src.core.legal_catalog import get_legal_basis, LEGAL_CATALOG


def test_legal_catalog_contains_all_pillars():
    pillars = ["CONSENTIMIENTO_COOKIES", "POLITICA_PRIVACIDAD", "CANALES_ARCO"]
    for p in pillars:
        assert f"{p}_FAIL" in LEGAL_CATALOG
        assert f"{p}_OK" in LEGAL_CATALOG


def test_legal_citation_cookies_fail_references_ley_21719():
    citation = get_legal_basis("CONSENTIMIENTO_COOKIES", "FAIL")
    assert "Art. 12" in citation.articulo_ley or "Art. 14" in citation.articulo_ley
    assert "20.000 UTM" in citation.sancion_estimada
    assert "Licitud" in citation.principio_vulnerado


def test_legal_citation_privacy_fail_references_transparency():
    citation = get_legal_basis("POLITICA_PRIVACIDAD", "FAIL")
    assert "Art. 11" in citation.articulo_ley
    assert "Transparencia" in citation.principio_vulnerado
    assert "5.000 UTM" in citation.sancion_estimada


def test_legal_citation_arco_fail_references_arco_articles():
    citation = get_legal_basis("CANALES_ARCO", "FAIL")
    assert "19 a 24" in citation.articulo_ley
    assert "10.000 UTM" in citation.sancion_estimada
