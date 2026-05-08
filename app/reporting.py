"""HTML-отчёт по результатам скана (содержимое summary.json)."""

from __future__ import annotations

from html import escape as e


def render_html_report(report: dict) -> str:
    """Собрать self-contained HTML из структуры run_pipeline (summary)."""
    scan_id = e(str(report.get("scan_id", "")))
    target = e(str(report.get("target_url", "")))
    generated = e(str(report.get("generated_at", "")))
    ro = report.get("risk_overview") or {}
    risk_rows = ""
    for key in ("critical", "high", "medium", "low", "info"):
        n = int(ro.get(key, 0) or 0)
        risk_rows += f'<span class="pill pill-{e(key)}">{e(key)}: {n}</span>'
    so = report.get("source_overview") or {}
    source_line = ""
    if isinstance(so, dict) and so:
        parts = [f"{e(str(k))}: {int(v)}" for k, v in sorted(so.items(), key=lambda x: str(x[0]))]
        source_line = "<div><strong>По источникам:</strong> " + ", ".join(parts) + "</div>"

    findings = report.get("findings") or []
    table_rows: list[str] = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        sev_raw = str(f.get("severity", "info")).lower()
        if sev_raw not in ("critical", "high", "medium", "low", "info"):
            sev_raw = "info"
        sev_escaped = e(sev_raw)
        table_rows.append(
            "<tr>"
            f'<td class="sev {sev_raw}"><span class="sev-label">{sev_escaped}</span></td>'
            f"<td>{e(str(f.get('source', '')))}</td>"
            f"<td>{e(str(f.get('title', '')))}</td>"
            f'<td class="pre">{e(str(f.get("evidence", "")))}</td>'
            f'<td class="pre">{e(str(f.get("recommendation", "")))}</td>'
            f'<td class="url-cell">{e(str(f.get("affected", "")))}</td>'
            "</tr>"
        )
    if not table_rows:
        table_rows = ['<tr><td colspan="6" class="muted">Найдений нет</td></tr>']

    tool_results = report.get("results") or {}
    tool_block = _tool_status_html(tool_results)

    passive = report.get("passive_checks") or {}
    status_code = passive.get("status_code", "—")
    final_url = e(str(passive.get("final_url", "")))
    adapt = passive.get("adaptive") or {}
    adapt_line = ""
    if isinstance(adapt, dict) and adapt.get("attempts_used"):
        adapt_line = (
            f'<div><strong>Адаптивный HTTP:</strong> успешная попытка '
            f'{e(str(adapt.get("attempts_used")))}</div>'
        )

    extras = passive.get("passive_extras") or {}
    tls_line = ""
    sql_line = ""
    if isinstance(extras, dict):
        tls = extras.get("tls") or {}
        if isinstance(tls, dict) and tls.get("protocol"):
            ciph = tls.get("cipher")
            ciph_s = ""
            if isinstance(ciph, tuple) and ciph:
                ciph_s = f", шифр: {e(str(ciph[0]))}"
            tls_line = (
                f'<div><strong>TLS:</strong> {e(str(tls.get("protocol")))}{ciph_s}</div>'
            )
        probes = extras.get("probes")
        if isinstance(probes, list) and probes:
            tls_line += f'<div class="muted">Пассивных проб путей: {len(probes)}</div>'
        sql_audit = extras.get("sql_audit") or {}
        if isinstance(sql_audit, dict):
            ep_count = int(sql_audit.get("entry_point_count", 0) or 0)
            err_count = int(sql_audit.get("sql_error_indicator_count", 0) or 0)
            sql_line = (
                f"<div><strong>SQLi audit:</strong> passive surface only, "
                f"entry points: {ep_count}, SQL error indicators: {err_count}</div>"
            )
    lh_line = ""
    lh = report.get("lighthouse_summary") or {}
    if isinstance(lh, dict) and lh:
        lh_parts = [f"{e(str(k))}: {int(v)}" for k, v in lh.items()]
        lh_line = "<div><strong>Lighthouse:</strong> " + ", ".join(lh_parts) + "</div>"

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Отчёт скана — {scan_id}</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{ font-family: "Segoe UI", system-ui, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; line-height: 1.5; }}
    .wrap {{ max-width: 1200px; margin: 0 auto; padding: 24px 16px 48px; }}
    h1 {{ font-size: 1.5rem; margin: 0 0 8px; }}
    .meta {{ color: #94a3b8; font-size: 0.9rem; margin-bottom: 20px; }}
    .meta code {{ background: #1e293b; padding: 2px 6px; border-radius: 4px; }}
    .risk {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 16px 0; }}
    .pill {{ display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 0.8rem; font-weight: 600; }}
    .pill-critical {{ background: #7f1d1d; color: #fecaca; }}
    .pill-high {{ background: #9a3412; color: #ffedd5; }}
    .pill-medium {{ background: #854d0e; color: #fef9c3; }}
    .pill-low {{ background: #1e3a5f; color: #bfdbfe; }}
    .pill-info {{ background: #334155; color: #e2e8f0; }}
    h2 {{ font-size: 1.1rem; margin: 28px 0 12px; color: #93c5fd; border-bottom: 1px solid #334155; padding-bottom: 6px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
    th, td {{ border-bottom: 1px solid #1f2937; text-align: left; padding: 10px 8px; vertical-align: top; }}
    th {{ color: #93c5fd; white-space: nowrap; }}
    .sev {{ width: 5.5em; }}
    .sev-label {{ text-transform: uppercase; font-size: 0.72rem; letter-spacing: 0.04em; }}
    tr:hover td {{ background: #111827; }}
    .pre {{ white-space: pre-wrap; word-break: break-word; max-width: 28em; }}
    .url-cell {{ word-break: break-all; max-width: 20em; }}
    .muted {{ color: #64748b; }}
    .tools {{ background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 12px 16px; font-size: 0.85rem; }}
    .tools dl {{ margin: 0; display: grid; grid-template-columns: auto 1fr; gap: 4px 16px; }}
    .tools dt {{ color: #94a3b8; }}
    @media print {{ body {{ background: #fff; color: #111; }} .pill {{ border: 1px solid #ccc; }} }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Security Combine — отчёт</h1>
    <div class="meta">
      <div><strong>Цель:</strong> {target}</div>
      <div><strong>Scan ID:</strong> <code>{scan_id}</code></div>
      <div><strong>Сформировано:</strong> {generated}</div>
      <div><strong>HTTP (пассивно):</strong> статус {e(str(status_code))}, итоговый URL: {final_url or "—"}</div>
      {adapt_line}
      {tls_line}
      {sql_line}
      {lh_line}
      {source_line}
    </div>
    <div class="risk" aria-label="Сводка по рискам">{risk_rows}</div>

    <h2>Найдения</h2>
    <table>
      <thead>
        <tr>
          <th>Уровень</th>
          <th>Источник</th>
          <th>Название</th>
          <th>Доказательства</th>
          <th>Рекомендация</th>
          <th>Затронуто</th>
        </tr>
      </thead>
      <tbody>
        {"".join(table_rows)}
      </tbody>
    </table>

    <h2>Инструменты</h2>
    <div class="tools">
{tool_block}
    </div>
  </div>
</body>
</html>
"""


def _tool_status_html(results: object) -> str:
    if not isinstance(results, dict):
        return "<p class='muted'>Нет данных</p>"
    lines: list[str] = ["<dl>"]
    for name, info in results.items():
        if not isinstance(info, dict):
            continue
        skipped = info.get("skipped")
        ex = info.get("exit_code")
        to = info.get("timed_out")
        if skipped:
            status = "пропущено"
        elif to:
            status = "тайм-аут"
        else:
            status = f"код {ex}" if ex is not None else "—"
        err = (info.get("stderr") or "")[:1200]
        lh = info.get("score_summary")
        score_part = ""
        if isinstance(lh, dict) and lh:
            score_part = " · " + ", ".join(f"{e(str(k))}:{int(v)}" for k, v in lh.items())
        extra = f" <span class='muted'>({e(err)})</span>" if err.strip() else ""
        lines.append(f"<dt>{e(str(name))}</dt><dd>{e(status)}{score_part}{extra}</dd>")
    lines.append("</dl>")
    return "\n    ".join(lines) if len(lines) > 2 else "<p class='muted'>Нет данных</p>"
