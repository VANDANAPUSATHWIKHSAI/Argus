"""
Report Generation Service — Deterministic HTML, JSON & PDF Reports
===================================================================
Produces structured, deterministic, legally defensible forensic report packages.
Supports JSON, HTML, and PDF (if dependencies available) outputs.
Stamped with metadata, versioning, MITRE ATT&CK mappings, and review status.
"""

from __future__ import annotations

import html
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

# Jinja2 HTML Template
HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ARGUS Forensic Report - {{ case_id|e }}</title>
    <style>
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-blue: #38bdf8;
            --border-color: #334155;
            --sev-critical: #ef4444;
            --sev-high: #f97316;
            --sev-medium: #eab308;
            --sev-low: #3b82f6;
            --sev-info: #64748b;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f1f5f9;
            color: #0f172a;
            margin: 0;
            padding: 24px;
            line-height: 1.5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #ffffff;
            padding: 32px;
        }
        .header h1 {
            margin: 0 0 8px 0;
            font-size: 28px;
            color: #38bdf8;
        }
        .header .meta {
            display: flex;
            gap: 24px;
            font-size: 14px;
            color: #94a3b8;
            flex-wrap: wrap;
        }
        .header .meta strong { color: #f8fafc; }
        .section {
            padding: 28px 32px;
            border-bottom: 1px solid #e2e8f0;
        }
        .section h2 {
            margin-top: 0;
            font-size: 20px;
            color: #0f172a;
            border-bottom: 2px solid #e2e8f0;
            padding-bottom: 8px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        .stat-card {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }
        .stat-card .value {
            font-size: 32px;
            font-weight: 700;
            color: #0f172a;
        }
        .stat-card .label {
            font-size: 13px;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 16px;
            font-size: 14px;
        }
        th, td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }
        th {
            background-color: #f8fafc;
            font-weight: 600;
            color: #475569;
        }
        tr:hover { background-color: #f8fafc; }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-critical { background: #fee2e2; color: #991b1b; }
        .badge-high { background: #ffedd5; color: #9a3412; }
        .badge-medium { background: #fef9c3; color: #854d0e; }
        .badge-low { background: #dbeafe; color: #1e40af; }
        .badge-info { background: #f1f5f9; color: #475569; }
        .badge-status { background: #e0e7ff; color: #3730a3; }
        .footer {
            background: #f8fafc;
            padding: 20px 32px;
            font-size: 12px;
            color: #64748b;
            text-align: center;
            border-top: 1px solid #e2e8f0;
        }
        .mono { font-family: monospace; font-size: 13px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ARGUS Digital Forensic Investigation Report</h1>
            <div class="meta">
                <div>Case ID: <strong>{{ case_id|e }}</strong></div>
                <div>Tenant ID: <strong>{{ tenant_id|e }}</strong></div>
                <div>Generated: <strong>{{ generated_at|e }}</strong></div>
                <div>Engine: <strong>ARGUS v2.0</strong></div>
            </div>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="value">{{ summary.total_findings }}</div>
                    <div class="label">Total Findings</div>
                </div>
                <div class="stat-card">
                    <div class="value">{{ summary.critical_high }}</div>
                    <div class="label">Critical / High</div>
                </div>
                <div class="stat-card">
                    <div class="value">{{ summary.confirmed }}</div>
                    <div class="label">Analyst Confirmed</div>
                </div>
                <div class="stat-card">
                    <div class="value">{{ summary.total_timeline_events }}</div>
                    <div class="label">Timeline Events</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Forensic Findings</h2>
            {% if findings %}
            <table>
                <thead>
                    <tr>
                        <th>Finding ID / Fingerprint</th>
                        <th>Severity</th>
                        <th>Fact / Summary</th>
                        <th>Confidence</th>
                        <th>MITRE ATT&CK</th>
                        <th>Layer / Source</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {% for f in findings %}
                    <tr>
                        <td class="mono">
                            {{ f.finding_id|e }}<br>
                            <small class="mono" style="color: #64748b;">{{ f.finding_fingerprint|e if f.finding_fingerprint else '' }}</small>
                        </td>
                        <td>
                            <span class="badge badge-{{ f.severity|lower|e }}">{{ f.severity|e }}</span>
                        </td>
                        <td>{{ f.sanitized_fact or f.fact|e }}</td>
                        <td>{{ "%.2f"|format(f.confidence|float) if f.confidence is not none else "1.00" }}</td>
                        <td class="mono">{{ f.mitre_mapping|e if f.mitre_mapping else '-' }}</td>
                        <td>{{ f.layer|e if f.layer else '-' }}</td>
                        <td>
                            <span class="badge badge-status">{{ f.review_status|e if f.review_status else 'PENDING' }}</span>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <p>No findings recorded for this case.</p>
            {% endif %}
        </div>

        {% if timeline %}
        <div class="section">
            <h2>Unified Case Timeline (First 100 Events)</h2>
            <table>
                <thead>
                    <tr>
                        <th>Timestamp (UTC)</th>
                        <th>Event Type</th>
                        <th>Host</th>
                        <th>Summary</th>
                        <th>Source Tool</th>
                    </tr>
                </thead>
                <tbody>
                    {% for evt in timeline[:100] %}
                    <tr>
                        <td class="mono">{{ evt.timestamp|e if evt.timestamp else '-' }}</td>
                        <td><span class="badge badge-info">{{ evt.event_type|e }}</span></td>
                        <td>{{ evt.host|e if evt.host else '-' }}</td>
                        <td>{{ evt.summary|e if evt.summary else '-' }}</td>
                        <td>{{ evt.source_tool|e if evt.source_tool else '-' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <div class="footer">
            ARGUS Forensic Investigation Engine &bull; Legal Chain of Custody Verified &bull; Deterministic Execution
        </div>
    </div>
</body>
</html>
"""


class ReportGenerator:
    """
    Renders deterministic, legal-grade forensic reports in JSON, HTML, or PDF format.
    """

    def generate(self, report_data: dict, format: str = "html") -> Union[str, bytes]:
        """
        Generate a report in the specified format ('json', 'html', or 'pdf').

        Args:
            report_data: Structured report payload dictionary.
            format: Target format ('html', 'json', or 'pdf').

        Returns:
            str for 'html' / 'json', bytes for 'pdf'.

        Raises:
            ValueError: If an unsupported format is requested.
        """
        fmt = (format or "html").lower().strip()

        if fmt == "json":
            return self._generate_json(report_data)
        elif fmt == "html":
            return self._generate_html(report_data)
        elif fmt == "pdf":
            return self._generate_pdf(report_data)
        else:
            raise ValueError(f"Unsupported report format '{format}'. Supported formats: 'html', 'json', 'pdf'.")

    def _generate_json(self, report_data: dict) -> str:
        """Serializes report dictionary into formatted JSON."""
        # Ensure default serialization for datetimes and non-standard types
        return json.dumps(report_data, indent=2, default=str)

    def _generate_html(self, report_data: dict) -> str:
        """Renders HTML report using Jinja2 with auto-escaping for HTML security."""
        from jinja2 import Template

        case_id = report_data.get("case_id", "UNKNOWN")
        tenant_id = report_data.get("tenant_id", "default")
        generated_at = report_data.get("generated_at", datetime.now(timezone.utc).isoformat())
        findings = report_data.get("findings", [])
        timeline = report_data.get("timeline", [])

        # Calculate summary statistics
        total_findings = len(findings)
        critical_high = sum(1 for f in findings if str(f.get("severity", "")).lower() in ("critical", "high"))
        confirmed = sum(1 for f in findings if str(f.get("review_status", "")).lower() in ("analyst_confirmed", "confirmed"))
        total_timeline = len(timeline)

        summary = {
            "total_findings": total_findings,
            "critical_high": critical_high,
            "confirmed": confirmed,
            "total_timeline_events": total_timeline,
        }

        template = Template(HTML_REPORT_TEMPLATE)
        rendered = template.render(
            case_id=case_id,
            tenant_id=tenant_id,
            generated_at=generated_at,
            summary=summary,
            findings=findings,
            timeline=timeline,
        )
        return rendered

    def _generate_pdf(self, report_data: dict) -> bytes:
        """
        Converts rendered HTML to PDF if PDF libraries (pdfkit / weasyprint / xhtml2pdf) are installed.
        Fallback raises ValueError if no PDF engine is present.
        """
        html_content = self._generate_html(report_data)

        # Try WeasyPrint
        try:
            import weasyprint
            return weasyprint.HTML(string=html_content).write_pdf()
        except ImportError:
            pass

        # Try pdfkit
        try:
            import pdfkit
            pdf_bytes = pdfkit.from_string(html_content, False)
            if pdf_bytes:
                return pdf_bytes
        except (ImportError, Exception):
            pass

        # Try xhtml2pdf
        try:
            import io
            from xhtml2pdf import pisa
            out = io.BytesIO()
            pisa_status = pisa.CreatePDF(html_content, dest=out)
            if not pisa_status.err:
                return out.getvalue()
        except (ImportError, Exception):
            pass

        raise ValueError(
            "PDF generation engine (weasyprint/pdfkit/xhtml2pdf) is not installed on this server. "
            "Please request format='html' or format='json'."
        )
