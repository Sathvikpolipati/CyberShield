import os
import sys
import time
from typing import Optional
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table as RLTable, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from core.db import Database
from core.interface import NetworkInterfaceManager

class SecurityReportGenerator:
    @staticmethod
    def get_downloads_dir() -> str:
        # Check Android / Termux storage
        termux_downloads = "/sdcard/Download"
        if os.path.exists(termux_downloads):
            return termux_downloads
            
        # Standard user home Downloads
        home = os.path.expanduser("~")
        win_mac_linux_dl = os.path.join(home, "Downloads")
        if os.path.exists(win_mac_linux_dl):
            return win_mac_linux_dl
            
        return home

    @classmethod
    def generate_pdf_report(cls, output_path: Optional[str] = None) -> str:
        if not output_path:
            dl_dir = cls.get_downloads_dir()
            ts = time.strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(dl_dir, f"CyberShield_Security_Report_{ts}.pdf")

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=20, textColor=colors.HexColor('#0F172A'), spaceAfter=10)
        h2_style = ParagraphStyle('SectionH2', parent=styles['Heading2'], fontSize=13, textColor=colors.HexColor('#0284C7'), spaceBefore=12, spaceAfter=6)
        body_style = ParagraphStyle('DocBody', parent=styles['Normal'], fontSize=9, leading=12, textColor=colors.HexColor('#334155'))

        story = []
        net_info = NetworkInterfaceManager.get_primary_interface()

        story.append(Paragraph("CYBERSHIELD SOC | EXECUTIVE NETWORK AUDIT", title_style))
        story.append(Paragraph(f"<b>Generated:</b> {time.strftime('%Y-%m-%d %H:%M:%S')} | <b>NIC:</b> {net_info['iface_name']} | <b>Host IP:</b> {net_info['local_ip']} | <b>Subnet:</b> {net_info['subnet_cidr']}", body_style))
        story.append(Spacer(1, 14))

        # Discovered Devices Table
        story.append(Paragraph("1. Local Network Topology & Asset Inventory", h2_style))
        devices = Database.get_all_devices_sync()
        if devices:
            dev_data = [["IP Address", "Hostname", "MAC Address", "Hardware Vendor", "First Seen"]]
            for d in devices[:20]:
                dev_data.append([
                    d.get("ip", "--"),
                    d.get("hostname", "Host")[:16],
                    d.get("mac", "Unknown"),
                    d.get("vendor", "OEM Device")[:20],
                    str(d.get("first_seen", ""))[:19]
                ])
            t_dev = RLTable(dev_data, colWidths=[90, 110, 110, 130, 100])
            t_dev.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F8FAFC')])
            ]))
            story.append(t_dev)
        else:
            story.append(Paragraph("No active hosts discovered in local database during audit window.", body_style))

        story.append(Spacer(1, 14))

        # Security Threat Incidents
        story.append(Paragraph("2. Threat Incidents & Intrusion Detection Alerts", h2_style))
        alerts = Database.get_recent_alerts_sync(limit=20)
        if alerts:
            alt_data = [["Timestamp", "Severity", "Detection Rule", "Attacker -> Target"]]
            for a in alerts:
                alt_data.append([
                    str(a.get("timestamp", ""))[:19],
                    a.get("severity", "HIGH"),
                    a.get("rule", "Anomaly")[:30],
                    f"{a.get('attacker_ip', '')} -> {a.get('target_ip', '')}"[:32]
                ])
            t_alt = RLTable(alt_data, colWidths=[100, 70, 180, 190])
            t_alt.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#991B1B')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#FECACA')),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#FEF2F2')])
            ]))
            story.append(t_alt)
        else:
            story.append(Paragraph("Zero critical threat incidents or anomalous vectors recorded.", body_style))

        doc.build(story)
        return output_path
