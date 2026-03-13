from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from datetime import datetime
import os

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "orange1",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "NONE":     "dim",
    "UNKNOWN":  "dim",
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "NONE":     "⚪",
    "UNKNOWN":  "⚪",
}


def print_banner():
    console.print(Panel.fit(
        "[bold white]PortMortem[/bold white]  [dim]CVE Risk Scorer[/dim]",
        border_style="red"
    ))


def print_results(scan_results: list[dict], target: str, overall: dict):
    """Prints a color-coded results table to the terminal."""

    console.print(f"\n[dim]Target:[/dim] [bold]{target}[/bold]")
    console.print(f"[dim]Scanned:[/dim] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    table = Table(box=box.ROUNDED, show_lines=True, border_style="dim")
    table.add_column("Port",     style="cyan",  width=7)
    table.add_column("Service",  style="white", width=12)
    table.add_column("Product",  style="white", width=14)
    table.add_column("Version",  style="white", width=10)
    table.add_column("CVEs",     justify="center", width=6)
    table.add_column("Score",    justify="center", width=7)
    table.add_column("Severity", width=12)

    for r in scan_results:
        sev = r["risk"]["severity"]
        color = SEVERITY_COLORS.get(sev, "white")
        emoji = SEVERITY_EMOJI.get(sev, "")

        table.add_row(
            str(r["port"]),
            r["service"],
            r["product"] or "—",
            r["version"] or "—",
            str(r["risk"]["cve_count"]),
            str(r["risk"]["score"]),
            f"[{color}]{emoji} {sev}[/{color}]",
        )

    console.print(table)

    # overall score
    sev = overall["severity"]
    color = SEVERITY_COLORS.get(sev, "white")
    emoji = SEVERITY_EMOJI.get(sev, "")
    console.print(
        f"\n  Overall Risk Score: [bold {color}]{overall['score']} / 10  "
        f"{emoji} {sev}[/bold {color}]\n"
    )


def save_html_report(scan_results: list[dict], target: str, overall: dict):
    """Saves a standalone HTML report to the reports/ folder."""

    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/{timestamp}_{target.replace('/', '_')}.html"

    sev_colors = {
        "CRITICAL": "#e74c3c",
        "HIGH":     "#e67e22",
        "MEDIUM":   "#f1c40f",
        "LOW":      "#2ecc71",
        "NONE":     "#95a5a6",
        "UNKNOWN":  "#95a5a6",
    }

    rows = ""
    for r in scan_results:
        sev = r["risk"]["severity"]
        color = sev_colors.get(sev, "#fff")
        cve_list = ""
        for cve in r.get("cves", [])[:5]:
            cve_list += f"""
                <tr class='cve-row'>
                    <td><a href='https://nvd.nist.gov/vuln/detail/{cve["id"]}'
                        target='_blank'>{cve["id"]}</a></td>
                    <td>{cve["score"]}</td>
                    <td style='color:{sev_colors.get(cve["severity"], "#fff")}'>{cve["severity"]}</td>
                    <td>{cve["description"][:120]}...</td>
                </tr>"""

        rows += f"""
            <tr class='service-row' onclick='toggleCVEs("{r["port"]}")'>
                <td>{r["port"]}</td>
                <td>{r["service"]}</td>
                <td>{r["product"] or "—"}</td>
                <td>{r["version"] or "—"}</td>
                <td>{r["risk"]["cve_count"]}</td>
                <td>{r["risk"]["score"]}</td>
                <td><span class='badge' style='background:{color}'>{sev}</span></td>
            </tr>
            <tr id='cves-{r["port"]}' class='cve-details' style='display:none'>
                <td colspan='7'>
                    <table class='cve-table'>
                        <tr><th>CVE ID</th><th>Score</th><th>Severity</th><th>Description</th></tr>
                        {cve_list}
                    </table>
                </td>
            </tr>"""

    overall_color = sev_colors.get(overall["severity"], "#fff")

    html = f"""<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <title>PortMortem — {target}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ background: #0d0d0d; color: #ccc; font-family: 'Courier New', monospace; padding: 2rem; }}
        h1 {{ color: #e74c3c; font-size: 2rem; margin-bottom: 0.2rem; }}
        .meta {{ color: #555; font-size: 0.85rem; margin-bottom: 2rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 1rem; }}
        th {{ background: #1a1a1a; color: #e74c3c; padding: 0.6rem 1rem; text-align: left; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; }}
        td {{ padding: 0.6rem 1rem; border-bottom: 1px solid #1f1f1f; font-size: 0.9rem; }}
        .service-row {{ cursor: pointer; }}
        .service-row:hover {{ background: #1a1a1a; }}
        .badge {{ padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; color: #000; }}
        .cve-details td {{ background: #111; padding: 1rem; }}
        .cve-table th {{ background: #0d0d0d; color: #888; }}
        .cve-table td {{ font-size: 0.8rem; color: #aaa; }}
        .cve-table a {{ color: #3498db; text-decoration: none; }}
        .overall {{ margin-top: 1.5rem; padding: 1rem 1.5rem; background: #1a1a1a; border-left: 4px solid {overall_color}; display: inline-block; }}
        .overall span {{ color: {overall_color}; font-size: 1.4rem; font-weight: bold; }}
        .hint {{ color: #444; font-size: 0.75rem; margin-bottom: 0.5rem; }}
    </style>
</head>
<body>
    <h1>PortMortem</h1>
    <div class='meta'>Target: {target} &nbsp;|&nbsp; {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
    <p class='hint'>Click a row to expand CVE details.</p>
    <table>
        <tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>CVEs</th><th>Score</th><th>Severity</th></tr>
        {rows}
    </table>
    <div class='overall'>Overall Risk Score: <span>{overall["score"]} / 10 — {overall["severity"]}</span></div>
    <script>
        function toggleCVEs(port) {{
            const row = document.getElementById('cves-' + port);
            row.style.display = row.style.display === 'none' ? 'table-row' : 'none';
        }}
    </script>
</body>
</html>"""

    with open(filename, "w") as f:
        f.write(html)

    console.print(f"  [dim]Report saved →[/dim] [bold]{filename}[/bold]\n")
    return filename