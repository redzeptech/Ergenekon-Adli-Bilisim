from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def write_forensic_timeline_html(
    path: Path,
    *,
    amcache_rows: list[dict[str, Any]],
    shimcache_rows: list[dict[str, Any]],
    execution_timeline: list[dict[str, Any]],
) -> None:
    """Write interactive forensic timeline dashboard for Amcache and Shimcache."""
    path.parent.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now().isoformat(timespec="seconds")
    verified_count = sum(
        1 for row in amcache_rows if str(row.get("ExecutionStatus", "")).upper() == "VERIFIED"
    )

    html = f"""<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Forensic Timeline Dashboard</title>
  <style>
    :root {{
      --bg: #0f172a;
      --panel: #111827;
      --panel-2: #1f2937;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --ok: #22c55e;
      --warn: #f59e0b;
      --line: #334155;
      --chip: #0b1220;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Segoe UI, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
    }}
    .container {{ max-width: 1200px; margin: 0 auto; padding: 18px; }}
    .grid {{ display: grid; gap: 12px; grid-template-columns: repeat(4, minmax(0, 1fr)); }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 12px;
    }}
    .metric-value {{ font-size: 1.5rem; font-weight: 700; }}
    .metric-label {{ color: var(--muted); font-size: 0.85rem; }}
    .controls {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      margin: 12px 0;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 10px;
    }}
    input, select {{
      background: var(--panel-2);
      color: var(--text);
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      overflow: hidden;
    }}
    th, td {{
      text-align: left;
      padding: 8px 10px;
      border-bottom: 1px solid var(--line);
      font-size: 0.9rem;
      vertical-align: top;
      word-break: break-word;
    }}
    th {{ background: var(--panel-2); color: #cbd5e1; }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
      background: var(--chip);
      border: 1px solid var(--line);
    }}
    .verified {{ color: var(--ok); border-color: var(--ok); }}
    .muted {{ color: var(--muted); }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Amcache + Shimcache Forensic Timeline</h1>
    <p class="muted">Rapor zamanı: {generated_at}</p>

    <div class="grid">
      <div class="card">
        <div class="metric-value" id="metricAmcache">{len(amcache_rows)}</div>
        <div class="metric-label">Amcache Record</div>
      </div>
      <div class="card">
        <div class="metric-value" id="metricShimcache">{len(shimcache_rows)}</div>
        <div class="metric-label">Shimcache Record</div>
      </div>
      <div class="card">
        <div class="metric-value" id="metricTimeline">{len(execution_timeline)}</div>
        <div class="metric-label">Timeline Event</div>
      </div>
      <div class="card">
        <div class="metric-value" id="metricVerified">{verified_count}</div>
        <div class="metric-label">Verified Execution</div>
      </div>
    </div>

    <div class="controls">
      <label for="sourceFilter">Kaynak:</label>
      <select id="sourceFilter">
        <option value="ALL">ALL</option>
        <option value="Amcache">Amcache</option>
        <option value="Shimcache">Shimcache</option>
      </select>
      <label for="statusFilter">Durum:</label>
      <select id="statusFilter">
        <option value="ALL">ALL</option>
        <option value="VERIFIED">VERIFIED</option>
        <option value="EMPTY">EMPTY</option>
      </select>
      <input id="searchInput" type="text" placeholder="Path veya SHA-1 ara..." />
      <span class="muted" id="resultCount"></span>
    </div>

    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Source</th>
          <th>Path</th>
          <th>SHA-1</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody id="timelineBody"></tbody>
    </table>
  </div>

  <script>
    const timeline = {_json_dumps(execution_timeline)};

    const sourceFilter = document.getElementById("sourceFilter");
    const statusFilter = document.getElementById("statusFilter");
    const searchInput = document.getElementById("searchInput");
    const timelineBody = document.getElementById("timelineBody");
    const resultCount = document.getElementById("resultCount");

    function escapeHtml(value) {{
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;");
    }}

    function render() {{
      const source = sourceFilter.value;
      const status = statusFilter.value;
      const needle = searchInput.value.trim().toLowerCase();

      const filtered = timeline.filter((item) => {{
        const srcOk = source === "ALL" || (item.source || "") === source;
        const itemStatus = String(item.status || "").toUpperCase();
        const statusOk =
          status === "ALL" ||
          (status === "VERIFIED" && itemStatus === "VERIFIED") ||
          (status === "EMPTY" && itemStatus === "");
        const haystack = `${{item.path || ""}} ${{item.sha1 || ""}}`.toLowerCase();
        const searchOk = !needle || haystack.includes(needle);
        return srcOk && statusOk && searchOk;
      }});

      timelineBody.innerHTML = filtered.map((item) => {{
        const st = String(item.status || "");
        const badgeClass = st.toUpperCase() === "VERIFIED" ? "badge verified" : "badge";
        return `
          <tr>
            <td>${{escapeHtml(item.timestamp || "")}}</td>
            <td>${{escapeHtml(item.source || "")}}</td>
            <td>${{escapeHtml(item.path || "")}}</td>
            <td>${{escapeHtml(item.sha1 || "")}}</td>
            <td><span class="${{badgeClass}}">${{escapeHtml(st || "N/A")}}</span></td>
          </tr>`;
      }}).join("");

      resultCount.textContent = `Sonuc: ${{filtered.length}} / ${{timeline.length}}`;
    }}

    [sourceFilter, statusFilter, searchInput].forEach((el) => {{
      el.addEventListener("input", render);
      el.addEventListener("change", render);
    }});
    render();
  </script>
</body>
</html>
"""
    path.write_text(html, encoding="utf-8")
