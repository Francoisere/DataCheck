"""
Alias de compatibilidad para el catálogo de tickets de remediación (FB-04).
Re-exporta desde src.scanner.remediation_catalog.
"""

from src.scanner.remediation_catalog import (
    REMEDIATION_TICKETS,
    get_remediation_ticket
)

__all__ = ["REMEDIATION_TICKETS", "get_remediation_ticket"]
