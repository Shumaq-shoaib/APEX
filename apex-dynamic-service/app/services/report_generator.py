import io
from datetime import datetime
from typing import List, Optional
from jinja2 import Template
from sqlalchemy.orm import Session, joinedload

from app.models.dynamic import (
    DynamicTestSession, DynamicFinding, DynamicEvidence, Severity
)

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}

HTML_TEMPLATE = Template(r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>APEX Security Report — {{ session.target_base_url }}</title>
<style>
  :root { --critical:#dc2626; --high:#ea580c; --medium:#d97706; --low:#2563eb; --info:#6b7280; }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:'Segoe UI',system-ui,-apple-system,sans-serif; color:#1e293b; background:#f8fafc; line-height:1.5; }
  .page { max-width:960px; margin:0 auto; padding:40px 32px; }
  h1 { font-size:28px; font-weight:800; margin-bottom:4px; }
  .subtitle { color:#64748b; font-size:14px; margin-bottom:32px; }
  .meta-grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:32px; }
  .meta-card { background:#fff; border:1px solid #e2e8f0; border-radius:8px; padding:16px; }
  .meta-card h3 { font-size:12px; text-transform:uppercase; letter-spacing:0.05em; color:#94a3b8; margin-bottom:8px; }
  .meta-card .value { font-size:22px; font-weight:700; }
  .sev-bar { display:flex; gap:8px; margin-bottom:32px; }
  .sev-pill { padding:6px 14px; border-radius:20px; font-size:13px; font-weight:600; color:#fff; }
  .sev-critical { background:var(--critical); }
  .sev-high { background:var(--high); }
  .sev-medium { background:var(--medium); }
  .sev-low { background:var(--low); }
  .sev-info { background:var(--info); }
  .section-title { font-size:20px; font-weight:700; border-bottom:2px solid #e2e8f0; padding-bottom:8px; margin:32px 0 16px; }
  .finding { background:#fff; border:1px solid #e2e8f0; border-radius:8px; margin-bottom:16px; overflow:hidden; page-break-inside:avoid; }
  .finding-header { padding:14px 18px; display:flex; justify-content:space-between; align-items:flex-start; gap:12px; }
  .finding-title { font-size:15px; font-weight:600; }
  .finding-badges { display:flex; gap:6px; flex-shrink:0; }
  .badge { padding:3px 10px; border-radius:12px; font-size:11px; font-weight:600; color:#fff; }
  .finding-body { padding:0 18px 14px; }
  .finding-body p { font-size:13px; color:#475569; margin-bottom:8px; }
  .finding-meta { font-size:11px; color:#94a3b8; font-family:monospace; }
  .evidence-block { background:#0f172a; color:#a3e635; font-family:'Consolas','Courier New',monospace; font-size:12px; padding:14px; border-radius:6px; margin:8px 0; white-space:pre-wrap; word-break:break-all; overflow-x:auto; }
  .evidence-label { font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.05em; color:#64748b; margin-top:12px; margin-bottom:4px; }
  .remediation { background:#eff6ff; border:1px solid #bfdbfe; border-radius:6px; padding:12px; margin-top:10px; font-size:13px; color:#1e40af; white-space:pre-wrap; }
  .footer { text-align:center; color:#94a3b8; font-size:12px; margin-top:48px; padding-top:16px; border-top:1px solid #e2e8f0; }
  @media print { .page { padding:20px; } }
</style>
</head>
<body>
<div class="page">
  <h1>APEX Security Scan Report</h1>
  <p class="subtitle">Generated {{ generated_at }} — Target: {{ session.target_base_url }}</p>

  <div class="meta-grid">
    <div class="meta-card">
      <h3>Session</h3>
      <div class="value" style="font-size:13px;font-family:monospace;">{{ session.id }}</div>
    </div>
    <div class="meta-card">
      <h3>Duration</h3>
      <div class="value">{{ duration }}</div>
    </div>
    <div class="meta-card">
      <h3>Test Cases</h3>
      <div class="value">{{ session.test_cases | length }}</div>
    </div>
    <div class="meta-card">
      <h3>Findings</h3>
      <div class="value">{{ findings | length }}</div>
    </div>
  </div>

  <div class="sev-bar">
    {% for sev, count in severity_counts.items() %}
      {% if count > 0 %}
        <span class="sev-pill sev-{{ sev | lower }}">{{ sev }}: {{ count }}</span>
      {% endif %}
    {% endfor %}
  </div>

  {% for sev_group, group_findings in grouped_findings.items() %}
  <h2 class="section-title">{{ sev_group }} ({{ group_findings | length }})</h2>
  {% for f in group_findings %}
  <div class="finding">
    <div class="finding-header">
      <div>
        <div class="finding-title">{{ f.title }}</div>
        <div class="finding-meta">{{ f.method }} {{ f.endpoint_path }} &middot; {{ f.check_type }}</div>
      </div>
      <div class="finding-badges">
        <span class="badge sev-{{ f.severity | lower }}">{{ f.severity }}</span>
        <span class="badge" style="background:#334155;">CVSS {{ f.cvss_score }}</span>
      </div>
    </div>
    <div class="finding-body">
      {% if f.description %}<p>{{ f.description }}</p>{% endif %}

      {% if f.evidence and f.evidence.request_dump %}
      <div class="evidence-label">Request</div>
      <div class="evidence-block">{{ f.evidence.request_dump }}</div>
      {% endif %}

      {% if f.evidence and f.evidence.response_dump %}
      <div class="evidence-label">Response</div>
      <div class="evidence-block" style="color:#fbbf24;">{{ f.evidence.response_dump }}</div>
      {% endif %}

      {% if f.remediation %}
      <div class="evidence-label">Remediation</div>
      <div class="remediation">{{ f.remediation }}</div>
      {% endif %}
    </div>
  </div>
  {% endfor %}
  {% endfor %}

  <div class="footer">
    APEX API Security Scanner &mdash; Report generated automatically.
  </div>
</div>
</body>
</html>""")


def generate_html_report(session: DynamicTestSession) -> str:
    findings: List[DynamicFinding] = sorted(
        session.findings,
        key=lambda f: SEVERITY_ORDER.get(f.severity.value if hasattr(f.severity, 'value') else str(f.severity), 5)
    )

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    grouped: dict[str, list] = {}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        grouped.setdefault(sev, []).append(f)

    duration = "N/A"
    if session.started_at and session.finished_at:
        delta = (session.finished_at - session.started_at).total_seconds()
        minutes = int(delta // 60)
        seconds = int(delta % 60)
        duration = f"{minutes}m {seconds}s"

    return HTML_TEMPLATE.render(
        session=session,
        findings=findings,
        grouped_findings=grouped,
        severity_counts=severity_counts,
        duration=duration,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    )


def generate_pdf_report(session: DynamicTestSession) -> bytes:
    from xhtml2pdf import pisa

    html = generate_html_report(session)
    buffer = io.BytesIO()
    pisa.CreatePDF(io.StringIO(html), dest=buffer)
    return buffer.getvalue()
