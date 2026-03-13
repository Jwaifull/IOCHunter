from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER

# Color palette
C_BG = colors.HexColor("#0d1117")
C_CARD = colors.HexColor("#161b22")
C_ACCENT = colors.HexColor("#21d4fd")
C_TEXT = colors.HexColor("#c9d1d9")
C_MUTED = colors.HexColor("#8b949e")
C_CRITICAL = colors.HexColor("#ff4757")
C_HIGH = colors.HexColor("#ff6b35")
C_MEDIUM = colors.HexColor("#ffa502")
C_LOW = colors.HexColor("#7bed9f")
C_CLEAN = colors.HexColor("#2ed573")
C_WHITE = colors.HexColor("#e6edf3")

RISK_COLORS = {
    "Critical": C_CRITICAL,
    "High": C_HIGH,
    "Medium": C_MEDIUM,
    "Low": C_LOW,
    "Clean": C_CLEAN,
    "Unknown": C_MUTED,
}


def export_pdf(analyzed_iocs: list[dict], output_path: str) -> bool:
    try:
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            leftMargin=15*mm, rightMargin=15*mm,
            topMargin=15*mm, bottomMargin=15*mm,
        )

        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle("title", fontSize=22, textColor=C_ACCENT,
                                     spaceAfter=4, alignment=TA_LEFT, fontName="Helvetica-Bold")
        sub_style = ParagraphStyle("sub", fontSize=9, textColor=C_MUTED,
                                   spaceAfter=16, alignment=TA_LEFT)
        story.append(Paragraph("🔍 IOCHunter Report", title_style))
        story.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  IOCs analyzed: {len(analyzed_iocs)}",
            sub_style
        ))
        story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT))
        story.append(Spacer(1, 8*mm))

        # Summary table
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Clean": 0, "Unknown": 0}
        for ioc in analyzed_iocs:
            risk = ioc.get("overall_risk", "Unknown")
            counts[risk] = counts.get(risk, 0) + 1

        summary_data = [
            ["Total IOCs", "Critical", "High", "Medium", "Low/Clean"],
            [
                str(len(analyzed_iocs)),
                str(counts["Critical"]),
                str(counts["High"]),
                str(counts["Medium"]),
                str(counts["Low"] + counts["Clean"]),
            ]
        ]
        summary_table = Table(summary_data, colWidths=[35*mm]*5)
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_CARD),
            ("TEXTCOLOR", (0, 0), (-1, 0), C_MUTED),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#1c2333")),
            ("TEXTCOLOR", (1, 1), (1, 1), C_CRITICAL),
            ("TEXTCOLOR", (2, 1), (2, 1), C_HIGH),
            ("TEXTCOLOR", (3, 1), (3, 1), C_MEDIUM),
            ("TEXTCOLOR", (4, 1), (4, 1), C_CLEAN),
            ("TEXTCOLOR", (0, 1), (0, 1), C_ACCENT),
            ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 1), (-1, 1), 14),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_CARD, colors.HexColor("#1c2333")]),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#30363d")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#30363d")),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 8*mm))

        # IOC table header
        header_style = ParagraphStyle("ioc_header", fontSize=10, textColor=C_ACCENT,
                                      fontName="Helvetica-Bold", spaceAfter=4)
        cell_style = ParagraphStyle("cell", fontSize=8, textColor=C_TEXT, fontName="Courier")
        muted_style = ParagraphStyle("muted", fontSize=8, textColor=C_MUTED)

        col_widths = [55*mm, 18*mm, 20*mm, 22*mm, 25*mm, 30*mm]
        table_header = [["IOC Value", "Type", "Risk", "VT Score", "Abuse%", "Country / Org"]]

        rows = [table_header[0]]
        for ioc in analyzed_iocs:
            vt = ioc["results"].get("virustotal", {})
            abuse = ioc["results"].get("abuseipdb", {})
            ipinf = ioc["results"].get("ipinfo", {})
            otx = ioc["results"].get("alienvault", {})

            vt_score = vt.get("score", "-") if not vt.get("error") and not vt.get("skipped") else "-"
            abuse_score = f"{abuse.get('abuse_score', '-')}%" if not abuse.get("error") and not abuse.get("skipped") else "-"
            country = ipinf.get("country") or vt.get("country") or otx.get("country") or "-"
            org = ipinf.get("org", "")[:25] if ipinf.get("org") else ""

            rows.append([
                ioc["value"][:40],
                ioc["type"],
                ioc["overall_risk"],
                vt_score,
                abuse_score,
                f"{country} {org}".strip()[:28],
            ])

        ioc_table = Table(rows, colWidths=col_widths, repeatRows=1)

        ts = [
            ("BACKGROUND", (0, 0), (-1, 0), C_CARD),
            ("TEXTCOLOR", (0, 0), (-1, 0), C_ACCENT),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, -1), 7.5),
            ("FONTNAME", (0, 1), (0, -1), "Courier"),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("ALIGN", (1, 0), (4, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#30363d")),
            ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#21262d")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#161b22"), colors.HexColor("#1c2333")]),
            ("TEXTCOLOR", (0, 1), (-1, -1), C_TEXT),
        ]

        for i, ioc in enumerate(analyzed_iocs, start=1):
            risk = ioc.get("overall_risk", "Unknown")
            risk_color = RISK_COLORS.get(risk, C_MUTED)
            ts.append(("TEXTCOLOR", (2, i), (2, i), risk_color))
            ts.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))

        ioc_table.setStyle(TableStyle(ts))
        story.append(ioc_table)

        # Footer
        story.append(Spacer(1, 10*mm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=C_MUTED))
        footer_style = ParagraphStyle("footer", fontSize=7.5, textColor=C_MUTED,
                                      alignment=TA_CENTER, spaceBefore=4)
        story.append(Paragraph(
            "IOCHunter — Open Source Threat Intelligence Tool | github.com/yourusername/IOCHunter",
            footer_style
        ))

        doc.build(story)
        return True

    except Exception as e:
        print(f"PDF export error: {e}")
        return False
