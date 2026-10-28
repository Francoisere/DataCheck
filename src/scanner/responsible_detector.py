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

CORP_NAME_PATTERN = re.compile(
    r'\b([A-ZÁÉÍÓÚÑ][A-Za-zÁÉÍÓÚáéíóúñ0-9\.\s&-]{1,40}?\s+(?:SpA|S\.A\.|S\.A|Ltda\.?|Limitada|EIRL))\b',
    re.IGNORECASE
)

PREFIX_CLEAN = re.compile(
    r'^(?:este sitio es\s+)?(?:servicio provisto por|operado por|propiedad de|razón social:?|razon social:?|titular del sitio:?|titular:?)\s*',
    re.IGNORECASE
)

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

ADDRESS_PATTERN = re.compile(
    r'(?:domicilio(?: postal)?|dirección(?: postal)?|direccion(?: postal)?|casa matriz|ubicada en|domiciliada en)[:\s]+([^;\n\r]{5,90}?)(?:\.|\n|$)',
    re.IGNORECASE
)

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
        rut_match = RUT_REGEX.search(combined_text)
        detected_rut = rut_match.group(0).strip() if rut_match else None
        has_rut = detected_rut is not None

        corp_match = CORP_NAME_PATTERN.search(combined_text)
        corporate_name = PREFIX_CLEAN.sub("", corp_match.group(1)).strip() if corp_match else None

        has_corp_term = any(kw in text_lower for kw in CORPORATE_KEYWORDS)
        identified = has_rut or (corporate_name is not None) or has_corp_term

        representative_found = any(kw in text_lower for kw in REPRESENTATIVE_KEYWORDS)
        dpo_found = any(kw in text_lower for kw in DPO_KEYWORDS)

        # 2. Literal c: Canales de atención y notificación
        contact_channels: List[str] = []

        # Correo electrónico general
        emails = EMAIL_REGEX.findall(combined_text)
        valid_emails = [
            e for e in emails
            if not e.lower().endswith((".png", ".jpg", ".svg", ".webp", ".gif"))
            and "example" not in e.lower()
            and "domain" not in e.lower()
        ]
        
        contact_email = None
        if valid_emails:
            contact_channels.append("email")
            prio_emails = [
                e for e in valid_emails
                if any(k in e.lower() for k in ["privacidad", "contacto", "dpo", "legal", "atencion", "info"])
            ]
            contact_email = prio_emails[0] if prio_emails else valid_emails[0]

        # Búsqueda de email asociado específicamente al contexto de DPO (ej. párrafo con "delegado" o "dpo" + email)
        dpo_email: Optional[str] = None

        def _is_valid_email(e: str) -> bool:
            e_lower = e.lower()
            return (
                not e_lower.endswith((".png", ".jpg", ".svg", ".webp", ".gif"))
                and "example" not in e_lower
                and "domain" not in e_lower
            )

        # a) Búsqueda en bloques de etiquetas del DOM (p, li, div, td, etc.)
        if soup:
            for elem in soup.find_all(["p", "li", "div", "td", "span", "dd", "section"]):
                elem_text = elem.get_text(separator=" ", strip=True)
                elem_lower = elem_text.lower()
                if any(kw in elem_lower for kw in DPO_KEYWORDS):
                    elem_emails = [e for e in EMAIL_REGEX.findall(elem_text) if _is_valid_email(e)]
                    if elem_emails:
                        dpo_email = elem_emails[0]
                        dpo_found = True
                        break

        # b) Búsqueda en párrafos o líneas del texto combinado
        if not dpo_email:
            text_blocks = [b.strip() for b in re.split(r'[\r\n]+', combined_text) if b.strip()]
            for block in text_blocks:
                block_lower = block.lower()
                if any(kw in block_lower for kw in DPO_KEYWORDS):
                    block_emails = [e for e in EMAIL_REGEX.findall(block) if _is_valid_email(e)]
                    if block_emails:
                        dpo_email = block_emails[0]
                        dpo_found = True
                        break

        # c) Búsqueda por proximidad (ventana de 250 caracteres alrededor de mención DPO)
        if not dpo_email and dpo_found:
            for kw in DPO_KEYWORDS:
                for match in re.finditer(re.escape(kw), text_lower):
                    start = max(0, match.start() - 250)
                    end = min(len(combined_text), match.end() + 250)
                    window_text = combined_text[start:end]
                    win_emails = [e for e in EMAIL_REGEX.findall(window_text) if _is_valid_email(e)]
                    if win_emails:
                        dpo_email = win_emails[0]
                        break
                if dpo_email:
                    break

        # d) Correo con identificador explícito de DPO (ej. dpo@empresa.cl, delegado@empresa.cl)
        if not dpo_email and valid_emails:
            dpo_named = [e for e in valid_emails if any(p in e.lower() for p in ["dpo@", "delegado@", "oficial.privacidad@"])]
            if dpo_named:
                dpo_email = dpo_named[0]
                dpo_found = True

        if dpo_email and "email" not in contact_channels:
            contact_channels.append("email")
            if not contact_email:
                contact_email = dpo_email

        # Formulario de contacto en DOM o enlaces internos/externos
        has_form_or_link = False
        if soup:
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
        addr_match = ADDRESS_PATTERN.search(combined_text)
        postal_address = addr_match.group(1).strip() if addr_match else None
        has_postal_kw = any(kw in text_lower for kw in POSTAL_ADDRESS_KEYWORDS)

        if postal_address or has_postal_kw:
            contact_channels.append("domicilio")
            if not postal_address:
                # Intento de rescate por ciudades comunes
                city_m = re.search(r'\b(?:Santiago|Valparaíso|Concepción|Las Condes|Providencia),\s*Chile\b', combined_text, re.IGNORECASE)
                if city_m:
                    postal_address = city_m.group(0).strip()

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
            "notes": notes,
            "corporate_name": corporate_name,
            "detected_rut": detected_rut,
            "contact_email": contact_email,
            "postal_address": postal_address,
            "dpo_email": dpo_email
        }
