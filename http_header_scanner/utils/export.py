"""
Export functionality for various formats
"""

import csv
import json
from datetime import datetime
from typing import Dict, List
from fpdf import FPDF
from http_header_scanner.models.findings import SecurityAnalysisReport

class ReportExporter:
    @staticmethod
    def to_json(report: SecurityAnalysisReport, file_path: str = None) -> Optional[str]:
        """
            Export report to JSON format
        """
        json_data = json.dumps(report, indent=2)
        if file_path:
            with open(file_path, "w") as f:
                f.write(json_data)
            return None
        return json_data

    @staticmethod
    def to_csv(reports: List[SecurityAnalysisReport], file_path: str):
        """
        Export multiple reports to CSV
        """
        fieldnames = [
                "url",
                "final_url",
                "status_code",
                "overall_risk",
                "total_score",
                "tls_version",
                "tls_grade",
                "framework",
                "missing_headers",
                "weak_headers"
        ]

        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for report in reports:
                writer.writerow({
                    "url": report["url"],
                    "final_url": report["final_url"],
                    "status_code": report["status_code"],
                    "overall_risk": report["overall_risk"],
                    "total_score": report["total_score"],
                    "tls_version": report["tls_analysis"]["version"],
                    "tls_grade": report["tls_analysis"]["grade"],
                    "framework": report["framework_analysis"]["name"] if report["framework_analysis"] else "",
                    "missing_headers": ", ".join([
                        h["header"] for h in report["headers"] 
                        if h["status"] in ["Critical", "High", "Medium"]
                    ]),
                    "weak_headers": ", ".join([
                        h["header"] for h in report["headers"] 
                        if h["status"] in ["Low"]
                    ])
                })

    @staticmethod
    def to_pdf(report: SecurityAnalysisReport, file_path: str):
        """
        Export report to PDF
        """
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Aeial", size=12)

        # Title
        pdf.set_font_size(16)
        pdf.cell(200, 10, txt="Security Header Analysis Report", ln=1, align="C")
        pdf.set_font_size(12)

        # Metadata
        pdf.cell(200, 10, txt=f"URL: {report['url']}", ln=1)
        pdf.cell(200, 10, txt=f"Final URL: {report['final_url']}", ln=1)
        pdf.cell(200, 10, txt=f"Scan Date: {report['timestamp']}", ln=1)
        pdf.cell(200, 10, txt=f"Overall Risk: {report['overall_risk']}", ln=1)
        pdf.cell(200, 10, txt=f"Total Score: {report['total_score']}", ln=1)
        pdf.ln(10)

        # Headers section
        pdf.set_font("", "B")
        pdf.cell(200, 10, txt="Header Analysis", ln=1)
        pdf.set_font("")

        for finding in report["headers"]:
            if finding["status"] != "Pass":
                pdf.cell(200, 10, txt=f"{finding['header']}: {finding['value'][:50]}", ln=1)
                pdf.cell(200, 10, txt=f"Status: {finding['status']}, Issue: {finding['issue']}", ln=1)
                pdf.ln(5)

        # Save to file
        pdf.output(file_path)

    @staticmethod
    def to_html(report: SecurityAnalysisReport, file_path: str):
        """
        Export report to HTML
        """
        # Implementation would genrate a complete HTML reort
        pass
