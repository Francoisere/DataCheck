"""
Servicio de Generación de Informes de Auditoría en Formato PDF (DataCheck.cl).
Cumple con AC-REP-01, AC-REP-02, AC-LEG-01 y AC-SEC-01:
- Generación de informe formal de diagnóstico en buffer binario (io.BytesIO) en < 3.0 segundos.
- Soporte de sustento normativo Ley 21.719 / 19.628, principios y sanciones APDP.
- Desglose por los 3 pilares legales, hallazgos empíricos y tickets técnicos de remediación.
- Disclaimer formal de exención de patrocinio judicial.
"""

import io
import time
from typing import Dict, Any, List
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)

from src.core.legal_catalog import get_legal_basis


class NumberedCanvas:
    """Canvas auxiliar para agregar numeración de páginas y pie institucional."""
    pass


class PdfReportService:
    @staticmethod
    def generate_pdf_report(
        audit_data: Dict[str, Any]
    ) -> io.BytesIO:
        """
        Compila el documento PDF formal a partir de los datos estructurados de una auditoría.
        Retorna un buffer BytesIO listo para streaming HTTP.
        """
        start_time = time.perf_counter()

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        
        # Estilos tipográficos personalizados
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#0F172A")
        )
        
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748B")
        )

        h2_style = ParagraphStyle(
            "SectionH2",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#1E293B"),
            spaceBefore=12,
            spaceAfter=6
        )

        body_style = ParagraphStyle(
            "BodyDark",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155")
        )

        badge_style = ParagraphStyle(
            "BadgeStyle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            alignment=1
        )

        story = []

        # 1. ENCABEZADO INSTITUCIONAL
        target_url = audit_data.get("target_url", "https://ejemplo.cl")
        verdict = audit_data.get("verdict", "RECHAZADO")
        score = audit_data.get("score", 0)
        timestamp_str = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S UTC")

        header_table_data = [
            [
                Paragraph("<b>DataCheck.cl</b><br/><font size='8' color='#64748B'>Plataforma de Auditoría de Cumplimiento de Datos Personales (Chile)</font>", title_style),
                Paragraph(f"<b>INFORME TÉCNICO LEGAL</b><br/><font size='8'>Fecha: {timestamp_str}</font>", subtitle_style)
            ]
        ]
        t_header = Table(header_table_data, colWidths=[360, 180])
        t_header.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_header)
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284C7"), spaceAfter=10))

        # 2. RESUMEN EJECUTIVO Y DICTAMEN
        verdict_colors = {
            "APROBADO": ("#10B981", "#ECFDF5", "#065F46"),
            "CON_OBSERVACIONES": ("#F59E0B", "#FFFBEB", "#92400E"),
            "RECHAZADO": ("#EF4444", "#FEF2F2", "#991B1B"),
        }
        border_col, bg_col, text_col = verdict_colors.get(verdict, ("#64748B", "#F8FAFC", "#0F172A"))

        verdict_text = f"<font color='{text_col}'>DICTAMEN: <b>{verdict}</b> ({score}/100 pts)</font>"
        summary_text = audit_data.get("verdict_summary", "")

        resumen_box_data = [
            [
                Paragraph(verdict_text, badge_style),
                Paragraph(f"<b>Sitio Auditado:</b> {target_url}<br/>{summary_text}", body_style)
            ]
        ]
        t_resumen = Table(resumen_box_data, colWidths=[160, 380])
        t_resumen.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg_col)),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor(border_col)),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(t_resumen)
        story.append(Spacer(1, 10))

        # 3. TABLA DE EVALUACIÓN POR PILARES (Ley 21.719)
        story.append(Paragraph("1. Evaluación por Pilares Normativos Auditables", h2_style))
        
        pilares = audit_data.get("pilares", {})
        p_priv = pilares.get("politica_privacidad", {})
        p_arco = pilares.get("canales_arco", {})
        p_cook = pilares.get("consentimiento_cookies", {})

        pilares_table_data = [
            ["Pilar Normativo", "Estado", "Puntaje", "Fundamento Ley 21.719"],
            [
                "Política de Privacidad y Transparencia",
                p_priv.get("status", "FALLA"),
                f"{p_priv.get('score', 0)} / {p_priv.get('max_score', 35)} pts",
                "Art. 11 (Deber de Transparencia e Información)"
            ],
            [
                "Canales de Ejercicio de Derechos ARCO",
                p_arco.get("status", "FALLA"),
                f"{p_arco.get('score', 0)} / {p_arco.get('max_score', 30)} pts",
                "Arts. 19 a 24 (Acceso, Rectificación, Cancelación, Oposición)"
            ],
            [
                "Consentimiento Previo y Cookies de Rastreo",
                p_cook.get("status", "FALLA"),
                f"{p_cook.get('score', 0)} / {p_cook.get('max_score', 35)} pts",
                "Arts. 12 y 14 (Principio de Licitud y Opt-in estricto)"
            ],
        ]

        t_pilares = Table(pilares_table_data, colWidths=[180, 70, 70, 220])
        t_pilares.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(t_pilares)
        story.append(Spacer(1, 10))

        # 4. DESGLOSE DETALLADO DE HALLAZGOS Y SUSTENTO JURÍDICO
        story.append(Paragraph("2. Desglose de Hallazgos Empíricos, Sustento Legal y Tickets de Remediación", h2_style))

        findings = audit_data.get("findings", [])
        if not findings:
            story.append(Paragraph("No se registraron hallazgos técnicos en este escaneo.", body_style))
        else:
            for idx, f in enumerate(findings, 1):
                pilar_name = f.get("pilar", "")
                status = f.get("status", "OK")
                title = f.get("title", "")
                detail = f.get("detail", "")
                remediation = f.get("remediation_ticket", "")
                raw = f.get("technical_raw", "")
                pilar_name = escape(str(pilar_name))
                title = escape(str(title))
                detail = escape(str(detail))
                remediation = escape(str(remediation or ""))
                raw = escape(str(raw or ""))

                # Obtener sustento legal desde el catálogo
                citation = get_legal_basis(pilar_name, status)
                art_ley = f.get("articulo_ley") or citation.articulo_ley
                principio = f.get("principio_vulnerado") or citation.principio_vulnerado
                sancion = f.get("sancion_estimada") or citation.sancion_estimada
                art_ley = escape(str(art_ley))
                principio = escape(str(principio))
                sancion = escape(str(sancion))

                status_color = "#10B981" if status == "OK" else ("#F59E0B" if status == "WARNING" else "#EF4444")

                finding_table_data = [
                    [
                        Paragraph(f"<b>#{idx} [{status}] {title}</b>", ParagraphStyle("Hdr", parent=body_style, fontName="Helvetica-Bold", textColor=colors.HexColor(status_color))),
                        Paragraph(f"<b>Pilar:</b> {pilar_name}", subtitle_style)
                    ],
                    [
                        Paragraph(f"<b>Evidencia Técnica:</b> {detail}" + (f"<br/><font face='Courier'>Dato crudo: {raw}</font>" if raw else ""), body_style),
                        Paragraph(f"<b>Sustento Legal:</b> {art_ley}<br/><b>Principio:</b> {principio}<br/><b>Sanción APDP:</b> {sancion}", body_style)
                    ],
                    [
                        Paragraph(f"<b>Ticket Técnico de Remediación:</b> {remediation}", ParagraphStyle("Rem", parent=body_style, fontName="Helvetica", textColor=colors.HexColor("#0369A1"))),
                        ""
                    ]
                ]

                t_finding = Table(finding_table_data, colWidths=[340, 200])
                t_finding.setStyle(TableStyle([
                    ("SPAN", (0, 2), (1, 2)),
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ("LINELEFT", (0, 0), (0, -1), 3, colors.HexColor(status_color)),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                story.append(KeepTogether([t_finding, Spacer(1, 6)]))

        # 5. DESCARGO DE RESPONSABILIDAD LEGAL (AC-SEC-01)
        story.append(Spacer(1, 8))
        disclaimer_text = (
            "<b>AVISO LEGAL DE RESPONSABILIDAD ACADÉMICA (Ley 21.719 / 19.628):</b> "
            "DataCheck.cl es una herramienta de auditoría técnica y diagnóstico automatizado pasivo de caja negra desarrollada "
            "con fines académicos en la Universidad Católica del Maule. El presente reporte no constituye dictamen ni asesoría "
            "jurídica vinculante, ni sustituye una auditoría integral de cumplimiento de la Agencia de Protección de Datos Personales (APDP). "
            "Prohibida la reproducción con fines judiciales sin revisión previa de un abogado colegiado."
        )
        t_disc = Table([[Paragraph(disclaimer_text, ParagraphStyle("Disc", parent=body_style, fontSize=7, leading=9, textColor=colors.HexColor("#64748B")))]], colWidths=[540])
        t_disc.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94A3B8")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(KeepTogether(t_disc))

        doc.build(story)
        buffer.seek(0)
        return buffer
