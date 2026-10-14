"""
Excepciones de dominio para el motor de inspección y auditoría.
"""

class AuditException(Exception):
    """Excepción base del sistema de auditoría."""
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class ScanTimeoutException(AuditException):
    """Se supera el límite estricto de tiempo (DA-02)."""
    def __init__(self, message: str = "Tiempo de escaneo excedido (límite de 25 segundos alcanzado)"):
        super().__init__(message=message, status_code=408)


class WafBlockedException(AuditException):
    """El sitio objetivo bloquea la inspección pasiva mediante WAF o código 403/503."""
    def __init__(self, message: str = "Sitio no accesible para análisis (bloqueo por WAF o cortafuegos de aplicación)"):
        super().__init__(message=message, status_code=403)


class TargetUnreachableException(AuditException):
    """El host objetivo no se resuelve o está inalcanzable (DNS / conexión)."""
    def __init__(self, message: str = "No se pudo resolver el nombre de host o establecer conexión con el sitio objetivo"):
        super().__init__(message=message, status_code=502)
