"""
Catálogo Legal y Sustento Normativo (Ley 21.719 / Ley 19.628 de Chile).
Mapea evidencias técnicas empíricas a su base jurídica formal,
principios vulnerados, rangos sancionatorios de la Agencia de Protección de Datos Personales (APDP)
y guías de remediación normativa.
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel


class LegalCitation(BaseModel):
    pilar: str
    articulo_ley: str
    principio_vulnerado: str
    descripcion_normativa: str
    severidad_apdp: str
    sancion_estimada: str
    remediation_guide: str


# Catálogo determinista indexado por pilar y condición
LEGAL_CATALOG: Dict[str, LegalCitation] = {
    "ACCESIBILIDAD_PERIMETRAL_WARNING": LegalCitation(
        pilar="ACCESIBILIDAD_PERIMETRAL",
        articulo_ley="Art. 11 (Principio de Transparencia y Accesibilidad) - Ley 21.719",
        principio_vulnerado="Principio de Transparencia y Cooperación Técnica",
        descripcion_normativa=(
            "El sitio web dispone de medidas perimetrales (WAF/Anti-bot) o latencia de red que limitan "
            "la inspección técnica pasiva automatizada. No constituye infracción directa de privacidad."
        ),
        severidad_apdp="Informativa / Neutra",
        sancion_estimada="Sin sanción aplicable (Dictamen Neutro NO_ACCESIBLE).",
        remediation_guide="Habilitar el User-Agent institucional de DataCheck o verificar en entorno asistido."
    ),
    "CONSENTIMIENTO_COOKIES_FAIL": LegalCitation(
        pilar="CONSENTIMIENTO_COOKIES",
        articulo_ley="Art. 12 (Bases de Licitud del Tratamiento) - Ley 21.719",
        principio_vulnerado="Principio de Licitud y Autodeterminación Informativa",
        descripcion_normativa=(
            "Todo tratamiento de datos personales obtenido mediante identificadores de navegación "
            "o tecnologías de rastreo exige una manifestación de voluntad previa, libre, específica, "
            "informada e inequívoca del titular. La activación sin consentimiento vicia la licitud del tratamiento."
        ),
        severidad_apdp="Grave a Gravísima",
        sancion_estimada="Multas de hasta 20.000 UTM (~$1.400M CLP) o suspensión de operaciones de tratamiento.",
        remediation_guide=(
            "Implementar bloqueo preventivo absoluto (opt-in estricto) de todas las cookies analíticas y publicitarias "
            "(Google Analytics, Meta Pixel, etc.) antes de recibir la acción afirmativa del usuario en el CMP."
        )
    ),
    "CONSENTIMIENTO_COOKIES_OK": LegalCitation(
        pilar="CONSENTIMIENTO_COOKIES",
        articulo_ley="Art. 12 (Bases de Licitud del Tratamiento) - Ley 21.719",
        principio_vulnerado="Ninguno (Conforme)",
        descripcion_normativa=(
            "El sitio respeta el consentimiento previo, no activando rastreadores de terceros "
            "ni almacenando cookies no esenciales previo a la interacción del usuario."
        ),
        severidad_apdp="Conforme",
        sancion_estimada="Sin sanción aplicable.",
        remediation_guide="Mantener la arquitectura de carga diferida y auditorías periódicas de scripts de terceros."
    ),
    "POLITICA_PRIVACIDAD_FAIL": LegalCitation(
        pilar="POLITICA_PRIVACIDAD",
        articulo_ley="Art. 14 ter (Obligación de Transparencia e Información) y Art. 11 (Principio de Transparencia) - Ley 21.719 / Art. 19 N° 4 Const.",
        principio_vulnerado="Principio de Transparencia y Lealtad",
        descripcion_normativa=(
            "El responsable del tratamiento tiene la obligación legal de proporcionar a los titulares información "
            "clara, accesible y comprensible sobre la identidad del responsable, finalidades del tratamiento, "
            "destinatarios y plazos de conservación. La inaccesibilidad del aviso constituye infracción directa."
        ),
        severidad_apdp="Leve a Grave",
        sancion_estimada="Multas de hasta 5.000 UTM o apercibimiento administrativo de cese de tratamiento.",
        remediation_guide=(
            "Publicar la Política de Privacidad en una URL pública permanente (HTTP 200) y enlazarla de forma destacada "
            "en el pie de página (footer) de todas las vistas del sitio."
        )
    ),
    "POLITICA_PRIVACIDAD_WARNING": LegalCitation(
        pilar="POLITICA_PRIVACIDAD",
        articulo_ley="Art. 14 ter (Obligación de Transparencia e Información) y Art. 11 (Deber de Información Detallada) - Ley 21.719",
        principio_vulnerado="Principio de Transparencia Cualificada",
        descripcion_normativa=(
            "La política contiene formulaciones vagas o genéricas que omiten menciones obligatorias "
            "(responsable, finalidades concretas, transferencias internacionales o período de retención)."
        ),
        severidad_apdp="Leve",
        sancion_estimada="Requerimiento de subsanación obligatoria por parte de la autoridad fiscalizadora.",
        remediation_guide=(
            "Actualizar el texto de la política desglosando taxativamente: identificación del responsable con RUT/contacto, "
            "fines específicos del tratamiento y derechos del titular."
        )
    ),
    "POLITICA_PRIVACIDAD_OK": LegalCitation(
        pilar="POLITICA_PRIVACIDAD",
        articulo_ley="Art. 14 ter y Art. 11 - Ley 21.719",
        principio_vulnerado="Ninguno (Conforme)",
        descripcion_normativa="La política de privacidad se encuentra disponible, accesible públicamente y contiene cláusulas normativas esenciales.",
        severidad_apdp="Conforme",
        sancion_estimada="Sin sanción aplicable.",
        remediation_guide="Revisar anualmente las finalidades declaradas y actualizar ante nuevos tratamientos."
    ),
    "POLITICA_PRIVACIDAD_ART14TER_OK": LegalCitation(
        pilar="POLITICA_PRIVACIDAD",
        articulo_ley="Art. 14 ter literales b) y c) - Ley N° 21.719",
        principio_vulnerado="Principio de Transparencia e Información del Responsable",
        descripcion_normativa=(
            "El responsable del tratamiento individualiza adecuadamente su identidad, representante legal "
            "o DPO e informa canales directos e idóneos para la recepción y notificación de solicitudes de los titulares."
        ),
        severidad_apdp="Conforme",
        sancion_estimada="Sin sanción. Deber de transparencia activo cumplido.",
        remediation_guide="Mantener actualizados los datos de contacto y la designación del encargado de prevención (DPO)."
    ),
    "POLITICA_PRIVACIDAD_ART14TER_WARNING": LegalCitation(
        pilar="POLITICA_PRIVACIDAD",
        articulo_ley="Art. 14 ter literales b) y c) - Ley N° 21.719",
        principio_vulnerado="Principio de Transparencia e Información del Responsable",
        descripcion_normativa=(
            "Omisión o deficiencia en la individualización del responsable (Razón Social/RUT), representante legal, "
            "encargado de prevención (DPO) o en los canales formales de notificación de solicitudes de los titulares."
        ),
        severidad_apdp="Infracción Leve (Art. 34 bis letras b y c)",
        sancion_estimada="Amonestación escrita o multa de hasta 5.000 UTM (~$330M CLP).",
        remediation_guide=(
            "Incorporar en el pie de página (footer) o en la sección inicial de la Política de Privacidad la individualización legal "
            "del responsable (Razón Social y RUT), el nombre o cargo del Representante Legal/DPO, y un correo de contacto o formulario "
            "directo dedicado a la recepción de solicitudes de derechos titulares (Art. 14 ter Ley 21.719)."
        )
    ),
    "CANALES_ARCO_FAIL": LegalCitation(
        pilar="CANALES_ARCO",
        articulo_ley="Arts. 19 a 24 (Ejercicio de Derechos ARCOP + Bloqueo: Acceso, Rectificación, Supresión, Oposición, Portabilidad y Bloqueo) - Ley 21.719 / Ley 19.628",
        principio_vulnerado="Derecho a la Autodeterminación Informativa y Tutela Efectiva",
        descripcion_normativa=(
            "Todo responsable debe poner a disposición del titular canales expeditos, gratuitos y debidamente "
            "identificados para la atención y resolución de solicitudes de acceso, rectificación, supresión, "
            "oposición, portabilidad y bloqueo (derechos ARCOP + Bloqueo) dentro del plazo legal de 15 días hábiles."
        ),
        severidad_apdp="Grave",
        sancion_estimada="Multas de hasta 10.000 UTM por denegación u obstaculización al ejercicio de derechos ARCOP + Bloqueo.",
        remediation_guide=(
            "Habilitar una casilla de correo dedicada (ej: privacidad@dominio.cl o dpo@dominio.cl) y/o formulario web "
            "específico para recepcionar y tramitar peticiones de derechos ARCOP + Bloqueo."
        )
    ),
    "CANALES_ARCO_WARNING": LegalCitation(
        pilar="CANALES_ARCO",
        articulo_ley="Arts. 19 a 24 (Derechos ARCOP + Bloqueo) - Ley 21.719",
        principio_vulnerado="Efectividad en el Ejercicio de Derechos",
        descripcion_normativa=(
            "Existen canales genéricos de contacto pero no se especifican con claridad los plazos, requisitos "
            "ni los mecanismos diferenciados para la solicitud de derechos del titular (ARCOP + Bloqueo)."
        ),
        severidad_apdp="Leve a Grave",
        sancion_estimada="Instrucción de adecuación y multas de hasta 2.500 UTM en caso de reiteración.",
        remediation_guide="Incluir en la política un protocolo formal indicando requisitos de acreditación y plazo máximo de respuesta legal para los 6 derechos ARCOP + Bloqueo."
    ),
    "CANALES_ARCO_OK": LegalCitation(
        pilar="CANALES_ARCO",
        articulo_ley="Arts. 19 a 24 (Derechos ARCOP + Bloqueo) - Ley 21.719",
        principio_vulnerado="Ninguno (Conforme)",
        descripcion_normativa="Canales expeditos y mención explícita a la gestión de derechos del titular (ARCOP + Bloqueo: Acceso, Rectificación, Supresión, Oposición, Portabilidad y Bloqueo) verificados.",
        severidad_apdp="Conforme",
        sancion_estimada="Sin sanción aplicable.",
        remediation_guide="Capacitar al personal encargado para cumplir con el plazo de respuesta legal de 15 días hábiles."
    ),
}


def get_legal_basis(pilar: str, status: str, key_override: Optional[str] = None) -> LegalCitation:
    """
    Retorna la fundamentación jurídica exacta según el pilar y su severidad técnica,
    o una clave específica si key_override está definido.
    """
    if key_override and key_override in LEGAL_CATALOG:
        return LEGAL_CATALOG[key_override]

    norm_pilar = pilar.upper()
    norm_status = status.upper()

    key = f"{norm_pilar}_{norm_status}"
    if key in LEGAL_CATALOG:
        return LEGAL_CATALOG[key]

    # Fallback por pilar
    for catalog_key, citation in LEGAL_CATALOG.items():
        if catalog_key.startswith(norm_pilar):
            return citation

    # Fallback general
    return LegalCitation(
        pilar=pilar,
        articulo_ley="Ley N° 21.719 sobre Protección de Datos Personales de Chile",
        principio_vulnerado="Principio de Responsabilidad Proactiva",
        descripcion_normativa="Cumplimiento de las obligaciones de resguardo y tratamiento legítimo de datos personales.",
        severidad_apdp="Evaluación según impacto",
        sancion_estimada="Multas de hasta 10.000 UTM según la gravedad de la vulneración.",
        remediation_guide="Adecuar los procesos de recolección y tratamiento a los principios de la Ley 21.719."
    )
