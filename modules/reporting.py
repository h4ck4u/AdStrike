"""
Module: Reporting — HTML dashboard / Markdown / JSON
"""
from utils.helpers import *
from config.settings import SESSION, OUTPUT_DIR, redact_obj, redact_text
import datetime, json, html as _html
from pathlib import Path

SEV_ORDER  = {"Critical":0,"High":1,"Medium":2,"Low":3,"Info":4}
SEV_COLORS = {"Critical":"#ff1493","High":"#ff4fb3","Medium":"#ff9bd1",
              "Low":"#36dfff","Info":"#9eeeff"}

def run():
    print_banner("REPORT GENERATOR", "HTML / Markdown / JSON")
    engagement = SESSION.get("engagement") or prompt("Engagement name")
    tester     = SESSION.get("username","tmrswrr")
    dom        = SESSION.get("domain","Unknown")
    dc         = SESSION.get("dc_ip","Unknown")
    cmds_run   = len(SESSION.get("commands_run",[]))
    findings   = dedupe_findings(SESSION.get("findings",[]))
    SESSION["findings"] = findings
    owned_u    = redact_obj(SESSION.get("owned_users", []))
    owned_m    = redact_obj(SESSION.get("owned_machines", []))
    loot       = SESSION.get("loot", {})

    if not findings:
        warn("No auto-tracked findings. Add manually?")
        while True:
            name = prompt("Finding name (blank to finish)")
            if not name: break
            sev  = prompt("Severity [Critical/High/Medium/Low/Info]")
            desc = prompt("Description")
            rec  = prompt("Recommendation")
            findings.append({"id":len(findings)+1,"name":name,"severity":sev,
                              "description":desc,"recommendation":rec,"evidence":""})

    findings.sort(key=lambda x: SEV_ORDER.get(x.get("severity","Info"),4))
    counts = {s: sum(1 for f in findings if f.get("severity")==s)
              for s in ["Critical","High","Medium","Low","Info"]}
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = Path(SESSION.get("output_dir") or str(OUTPUT_DIR)) / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    out = str(report_dir / f"adagent_report_{ts}")

    # HTML Report
    rows = ""
    for f in findings:
        col = SEV_COLORS.get(f.get("severity","Info"),"#888")
        rows += f"""<tr>
          <td>{f['id']}</td><td><strong>{_html.escape(str(f['name']))}</strong></td>
          <td style="color:{col};font-weight:bold">{_html.escape(str(f.get('severity','')))}</td>
          <td>{_html.escape(redact_text(str(f.get('description',''))))}</td>
          <td>{_html.escape(redact_text(str(f.get('recommendation',''))))}</td>
        </tr>"""

    stat_boxes = "".join(
        f'<div class="stat-box"><div class="stat-num" style="color:{SEV_COLORS[s]}">{counts[s]}</div>'
        f'<div class="stat-lbl">{s}</div></div>'
        for s in ["Critical","High","Medium","Low","Info"]
    )
    bars = "".join(
        f'<div class="bar"><span class="sev" style="color:{SEV_COLORS[s]}">{s}</span>'
        f'<span class="cnt">{counts[s]}</span>'
        f'<div class="fill" style="background:{SEV_COLORS[s]};width:{min(counts[s]*50,500)}px"></div></div>'
        for s in ["Critical","High","Medium","Low","Info"]
    )

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>{engagement} – AdStrike Report</title>
<style>
body{{margin:0;font-family:'Segoe UI',Arial,sans-serif;background:#eefbff;color:#163044}}
header{{background:linear-gradient(135deg,#bff6ff,#ffffff,#ffe1f4);padding:40px;border-bottom:3px solid #ff1493}}
h1{{color:#ff1493;margin:0;font-size:2.4em}} h2{{color:#ff4fb3;border-bottom:1px solid #ff1493;padding-bottom:6px}}
.meta{{color:#3f6c80;margin-top:8px}}
.container{{max-width:1200px;margin:auto;padding:30px}}
table{{border-collapse:collapse;width:100%}}
th{{background:#bff6ff;color:#ff1493;padding:12px;text-align:left;border:1px solid #36dfff}}
td{{padding:10px;border:1px solid #9eeeff;vertical-align:top;background:#ffffff;color:#163044}} tr:hover td{{background:#fff0f8}}
.stats{{display:flex;gap:16px;flex-wrap:wrap;margin:20px 0}}
.stat-box{{background:#ffffff;border:1px solid #36dfff;border-radius:8px;padding:16px 24px;text-align:center;box-shadow:0 6px 20px rgba(54,223,255,.22)}}
.stat-num{{font-size:2em;font-weight:bold}} .stat-lbl{{color:#3f6c80;font-size:.85em}}
.bar{{display:flex;align-items:center;gap:10px;margin:5px 0}}
.sev{{width:80px;font-weight:bold;font-size:.9em}} .cnt{{width:24px;text-align:right}}
.fill{{height:20px;border-radius:4px;min-width:4px}}
footer{{text-align:center;color:#3f6c80;padding:20px;font-size:.8em}}
</style></head>
<body>
<header>
  <h1>{engagement}</h1>
  <div class="meta">Date: {datetime.date.today()} | Tester: {tester} | Target: {dom} ({dc}) | Commands: {cmds_run}</div>
</header>
<div class="container">
  <h2>Executive Summary</h2>
  <div class="stats">{stat_boxes}
    <div class="stat-box"><div class="stat-num">{len(findings)}</div><div class="stat-lbl">Total</div></div>
    <div class="stat-box"><div class="stat-num">{len(owned_u)}</div><div class="stat-lbl">Owned Users</div></div>
    <div class="stat-box"><div class="stat-num">{len(owned_m)}</div><div class="stat-lbl">Owned Hosts</div></div>
  </div>
  <h2>Engagement State</h2>
  <table>
    <tr><th>Field</th><th>Value</th></tr>
    <tr><td>Domain</td><td>{_html.escape(str(dom))}</td></tr>
    <tr><td>Domain Controller</td><td>{_html.escape(str(dc))}</td></tr>
    <tr><td>Owned Users</td><td>{_html.escape(', '.join(str(x) for x in owned_u) or 'None')}</td></tr>
    <tr><td>Owned Hosts</td><td>{_html.escape(', '.join(str(x) for x in owned_m) or 'None')}</td></tr>
    <tr><td>Loot Keys</td><td>{_html.escape(', '.join(str(k) for k in loot.keys()) or 'None')}</td></tr>
  </table>
  <h2>Severity Distribution</h2>{bars}
  <h2>Findings</h2>
  <table><tr><th>#</th><th>Finding</th><th>Severity</th><th>Description</th><th>Recommendation</th></tr>
  {rows}</table>
</div>
<footer>Generated by AdStrike v5.0 «AdStrike» | creator: tmrswrr | For authorised use only</footer>
</body></html>"""

    # Markdown
    md = f"# {engagement} – AdStrike Report\n**Date:** {datetime.date.today()} | **Tester:** {tester} | **Target:** {dom}\n\n## Summary\n| Severity | Count |\n|---|---|\n"
    for s in ["Critical","High","Medium","Low","Info"]:
        md += f"| {s} | {counts[s]} |\n"
    md += (
        "\n## Engagement State\n"
        f"- Domain: `{dom}`\n"
        f"- Domain Controller: `{dc}`\n"
        f"- Commands Run: `{cmds_run}`\n"
        f"- Owned Users: `{len(owned_u)}`\n"
        f"- Owned Hosts: `{len(owned_m)}`\n"
        f"- Loot Keys: `{', '.join(str(k) for k in loot.keys()) or 'None'}`\n"
    )
    md += "\n## Findings\n"
    for f in findings:
        md += f"\n### {f['id']}. {f['name']} — `{f.get('severity','')}`\n"
        md += f"**Description:** {redact_text(str(f.get('description','')))}\n\n"
        md += f"**Recommendation:** {redact_text(str(f.get('recommendation','')))}\n"
        if f.get("evidence"):
            md += f"\n**Evidence:** `{redact_text(str(f.get('evidence')))}`\n"

    # Write files
    with open(f"{out}.html","w") as fh: fh.write(html)
    with open(f"{out}.md","w") as fh:   fh.write(md)
    with open(f"{out}.json","w") as fh:
        json.dump({"engagement":engagement,"tester":tester,"date":str(datetime.date.today()),
                   "target":{"domain":dom,"dc":dc},"summary":counts,
                   "commands_run":cmds_run,"owned_users":redact_obj(owned_u),
                   "owned_machines":redact_obj(owned_m),"loot_keys":list(loot.keys()),
                   "findings":redact_obj(findings)}, fh, indent=2)

    success(f"HTML   → {out}.html")
    success(f"Markdown → {out}.md")
    success(f"JSON   → {out}.json")
    pause()
