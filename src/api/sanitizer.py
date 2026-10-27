"""
Alias de compatibilidad para el módulo de sanitización y protección SSRF (FB-01).
Re-exporta desde src.core.sanitizer.
"""

from src.core.sanitizer import (
    sanitize_url,
    validate_ssrf,
    is_ip_private_or_restricted
)

__all__ = ["sanitize_url", "validate_ssrf", "is_ip_private_or_restricted"]
