# -*- coding: utf-8 -*-
"""
Módulo de Detección de Transparencia del Responsable (Art. 14 ter Ley N° 21.719).
Evalúa de manera pasiva (caja negra, DA-01) y sin persistir datos de personas naturales (DA-04):
- Literal b): Individualización del responsable (Razón Social / RUT), representante legal y DPO.
- Literal c): Canales idóneos de contacto y notificación (email, formulario, domicilio).
"""

import re
from typing import Dict, Any, List, Optional
from bs4 import BeautifulSoup


# Expresiones regulares y palabras clave para Art. 14 ter literal b)
RUT_REGEX = re.compile(r'\b\d{1,2}\.?\d{3}\.?\d{3}-[\dkK]\b')

CORPORATE_KEYWORDS = [
    "razón social",
    "razon social",
    "sociedad",
    "spa",
    "s.a.",
    "s.a",
    "ltda",
    "limitada",
    "eirl",
    "titular del sitio",
    "titular del tratamiento",
    "responsable del tratamiento",
    "responsable de datos",
    "propiedad de",
    "operado por",
]

REPRESENTATIVE_KEYWORDS = [
    "representante legal",
    "representacion legal",
    "representación legal",
    "apoderado",
    "representada por",
    "representado por",
]

DPO_KEYWORDS = [
    "encargado de prevención",
    "encargado de prevencion",
    "delegado de protección",
    "delegado de proteccion",
    "delegado de datos",
    "oficial de privacidad",
    "dpo",
    "data protection officer",
    "oficial de proteccion de datos",
]

# Expresiones regulares y palabras clave para Art. 14 ter literal c)
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

POSTAL_ADDRESS_KEYWORDS = [
    "domicilio",
    "dirección postal",
    "direccion postal",
    "domicilio postal",
    "comuna de",
    "santiago, chile",
    "valparaíso",
    "valparaiso",
    "concepción",
    "concepcion",
    "oficina central",
    "casa matriz",
    "avenida",
    "av.",
    "edificio",
]

CONTACT_LINK_PATTERNS = [
    r'/contacto',
    r'/contact',
    r'/derechos-arco',
    r'/arco',
    r'/privacidad/solicitud',
    r'/solicitudes',
    r'/formulario',
]


class ResponsiblePartyDetector:
    """
    Detector pasivo de información y canales del responsable de datos personales
    según las exigencias del Art. 14 ter literales b) y c) de la Ley N° 21.719.
    """

    @classmethod
    def detect(
        cls,
        soup: Optional[BeautifulSoup],
        html_content: str,
        policy_text: str = "",
        policy_found: bool = False
    ) -> Dict[str, Any]:
        """
        Analiza el DOM y el texto de la política de privacidad buscando evidencia
        de individualización y canales formales de atención.
        """
        combined_text = (policy_text or "") + " "
        if soup:
            combined_text += soup.get_text(separator=" ")
        else:
            combined_text += html_content

        text_lower = combined_text.lower()

        # 1. Literal b: Individualización de la empresa / RUT / Representante
        has_rut = bool(RUT_REGEX.search(combined_text))
        has_corp_term = any(kw in text_lower for kw in CORPORATE_KEYWORDS)
        identified = has_rut or has_corp_term

        representative_found = any(kw in text_lower for kw in REPRESENTATIVE_KEYWORDS)
        dpo_found = any(kw in text_lower for kw in DPO_KEYWORDS)

        # 2. Literal c: Canales de atención y notificación
        contact_channels: List[str] = []

        # Correo electrónico (detectar presencia sin almacenar identidades personales)
        emails = EMAIL_REGEX.findall(combined_text)
        valid_emails = [
            e for e in emails
            if not e.lower().endswith((".png", ".jpg", ".svg", ".webp", ".gif"))
            and "example" not in e.lower()
            and "domain" not in e.lower()
        ]
        if valid_emails:
            contact_channels.append("email")

        # Formulario de contacto en DOM o enlaces internos/externos
        has_form_or_link = False
        if soup:
            # Formularios
            for form in soup.find_all("form"):
                action = str(form.get("action", "")).lower()
                form_id = str(form.get("id", "")).lower()
                form_class = " ".join(form.get("class", [])).lower()
                has_inputs = bool(form.find("textarea") or form.find("input", {"type": ["email", "text"]}))
                if ("contact" in action or "contacto" in action or "arco" in action or
                    "contact" in form_id or "contacto" in form_id or
                    "contact" in form_class or "contacto" in form_class or has_inputs):
                    has_form_or_link = True
                    break

            # Enlaces hacia páginas de contacto o ejercicio de derechos
            if not has_form_or_link:
                for a in soup.find_all("a", href=True):
                    href = str(a["href"]).lower()
                    link_text = a.get_text(strip=True).lower()
                    if any(re.search(pat, href) for pat in CONTACT_LINK_PATTERNS) or "contacto" in link_text or "arco" in link_text:
                        has_form_or_link = True
                        break

        if has_form_or_link:
            contact_channels.append("formulario")

        # Domicilio postal
        has_postal = any(kw in text_lower for kw in POSTAL_ADDRESS_KEYWORDS)
        if has_postal:
            contact_channels.append("domicilio")

        # 3. Dictamen de cumplimiento del Art. 14 ter
        if not policy_found:
            verdict = "NO_VERIFICABLE"
            notes = "No fue posible verificar la información del responsable debido a la ausencia o inaccesibilidad de la política de privacidad."
        else:
            has_channel = len(contact_channels) > 0
            has_identification = identified or representative_found

            if has_identification and has_channel:
                verdict = "CUMPLE"
                notes = "El responsable individualiza su identidad o representante e informa canales idóneos para recepción de solicitudes conforme al Art. 14 ter."
            else:
                verdict = "OBSERVACION"
                notes = "Se detectó omisión en la individualización del responsable/representante legal o en los canales formales de notificación de solicitudes del Art. 14 ter."

        return {
            "identified": identified,
            "representative_found": representative_found,
            "dpo_found": dpo_found,
            "contact_channels_found": contact_channels,
            "verdict": verdict,
            "notes": notes
        }
