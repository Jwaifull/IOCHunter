import os
from datetime import datetime
from jinja2 import Template

TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IOCHunter Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; }
  
  .header {
    background: linear-gradient(135deg, #161b22, #1f2937);
    border-bottom: 2px solid #21d4fd;
    padding: 30px 40px;
    display: flex;
    align-items: center;
    gap: 20px;
  }
  .logo { font-size: 2.2rem; }
  .header h1 { font-size: 1.8rem; color: #21d4fd; letter-spacing: 2px; }
  .header p { color: #8b949e; font-size: 0.9rem; margin-top: 4px; }

  .summary {
    display: flex;
    gap: 16px;
    padding: 24px 40px;
    background: #161b22;
    border-bottom: 1px solid #30363d;
    flex-wrap: wrap;
  }
  .stat-card {
    background: #1c2333;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px 24px;
    text-align: center;
    min-width: 120px;
  }
  .stat-card .number { font-size: 2rem; font-weight: 700; color: #21d4fd; }
  .stat-card .label { font-size: 0.75rem; color: #8b949e; text-transform: uppercase; margin-top: 4px; }
  .stat-card.critical .number { color: #ff4757; }
  .stat-card.high .number { color: #ff6b35; }
  .stat-card.medium .number { color: #ffa502; }
  .stat-card.clean .number { color: #2ed573; }

  .content { padding: 24px 40px; }
  
  .ioc-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    margin-bottom: 20px;
    overflow: hidden;
  }
  .ioc-header {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 16px 20px;
    background: #1c2333;
    border-bottom: 1px solid #30363d;
  }
  .ioc-value { font-size: 1rem; font-weight: 600; font-family: monospace; color: #e6edf3; }
  .badge {
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  .badge-type { background: #1f3a5f; color: #79c0ff; }
  .badge-Critical { background: #3d0000; color: #ff4757; border: 1px solid #ff4757; }
  .badge-High { background: #3d1a00; color: #ff6b35; border: 1px solid #ff6b35; }
  .badge-Medium { background: #3d2e00; color: #ffa502; border: 1px solid #ffa502; }
  .badge-Low { background: #1a3d00; color: #7bed9f; border: 1px solid #7bed9f; }
  .badge-Clean { background: #003d1a; color: #2ed573; border: 1px solid #2ed573; }
  .badge-Unknown { background: #1c2333; color: #8b949e; border: 1px solid #8b949e; }

  .api-results {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
    gap: 12px;
    padding: 16px 20px;
  }
  .api-block {
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 12px 16px;
  }
  .api-name {
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #58a6ff;
    margin-bottom: 8px;
    padding-bottom: 6px;
    border-bottom: 1px solid #21262d;
  }
  .api-row { display: flex; justify-content: space-between; font-size: 0.8rem; padding: 2px 0; }
  .api-row .key { color: #8b949e; }
  .api-row .val { color: #e6edf3; font-weight: 500; }
  .api-error { color: #f85149; font-size: 0.8rem; }
  .api-skipped { color: #8b949e; font-size: 0.8rem; font-style: italic; }

  .footer {
    text-align: center;
    padding: 20px;
    color: #8b949e;
    font-size: 0.8rem;
    border-top: 1px solid #21262d;
    margin-top: 20px;
  }
</style>
</head>
<body>

<div class="header">
  <div class="logo">🔍</div>
  <div>
    <h1>IOCHunter Report</h1>
    <p>Generated: {{ date }} &nbsp;|&nbsp; IOCs analyzed: {{ total }}</p>
  </div>
</div>

<div class="summary">
  <div class="stat-card"><div class="number">{{ total }}</div><div class="label">Total IOCs</div></div>
  <div class="stat-card critical"><div class="number">{{ counts.Critical }}</div><div class="label">Critical</div></div>
  <div class="stat-card high"><div class="number">{{ counts.High }}</div><div class="label">High</div></div>
  <div class="stat-card medium"><div class="number">{{ counts.Medium }}</div><div class="label">Medium</div></div>
  <div class="stat-card clean"><div class="number">{{ counts.Clean }}</div><div class="label">Clean</div></div>
</div>

<div class="content">
{% for ioc in iocs %}
<div class="ioc-card">
  <div class="ioc-header">
    <span class="ioc-value">{{ ioc.value }}</span>
    <span class="badge badge-type">{{ ioc.type }}</span>
    <span class="badge badge-{{ ioc.overall_risk }}">{{ ioc.overall_risk }}</span>
  </div>
  <div class="api-results">
    {% for api_name, res in ioc.results.items() %}
    <div class="api-block">
      <div class="api-name">{{ res.get('source', api_name) }}</div>
      {% if res.get('error') %}
        <div class="api-error">⚠ {{ res.error }}</div>
      {% elif res.get('skipped') %}
        <div class="api-skipped">— Not applicable</div>
      {% elif not res.get('found') %}
        <div class="api-skipped">Not found in database</div>
      {% else %}
        {% if res.get('score') %}
          <div class="api-row"><span class="key">Score</span><span class="val">{{ res.score }}</span></div>
        {% endif %}
        {% if res.get('abuse_score') is not none %}
          <div class="api-row"><span class="key">Abuse Score</span><span class="val">{{ res.abuse_score }}%</span></div>
        {% endif %}
        {% if res.get('total_reports') %}
          <div class="api-row"><span class="key">Reports</span><span class="val">{{ res.total_reports }}</span></div>
        {% endif %}
        {% if res.get('pulse_count') is not none %}
          <div class="api-row"><span class="key">OTX Pulses</span><span class="val">{{ res.pulse_count }}</span></div>
        {% endif %}
        {% if res.get('country') %}
          <div class="api-row"><span class="key">Country</span><span class="val">{{ res.country }}</span></div>
        {% endif %}
        {% if res.get('org') %}
          <div class="api-row"><span class="key">Org</span><span class="val">{{ res.org[:30] }}</span></div>
        {% endif %}
        {% if res.get('isp') %}
          <div class="api-row"><span class="key">ISP</span><span class="val">{{ res.isp[:30] }}</span></div>
        {% endif %}
        {% if res.get('is_tor') %}
          <div class="api-row"><span class="key">TOR</span><span class="val">⚠ Yes</span></div>
        {% endif %}
        {% if res.get('risk') %}
          <div class="api-row"><span class="key">Risk</span><span class="val">{{ res.risk }}</span></div>
        {% endif %}
      {% endif %}
    </div>
    {% endfor %}
  </div>
</div>
{% endfor %}
</div>

<div class="footer">
  IOCHunter — Open Source Threat Intelligence Tool &nbsp;|&nbsp; github.com/yourusername/IOCHunter
</div>

</body>
</html>
"""


def export_html(analyzed_iocs: list[dict], output_path: str) -> bool:
    try:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Clean": 0, "Unknown": 0}
        for ioc in analyzed_iocs:
            risk = ioc.get("overall_risk", "Unknown")
            counts[risk] = counts.get(risk, 0) + 1

        template = Template(TEMPLATE)
        html = template.render(
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total=len(analyzed_iocs),
            iocs=analyzed_iocs,
            counts=counts,
        )
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return True
    except Exception as e:
        print(f"HTML export error: {e}")
        return False
