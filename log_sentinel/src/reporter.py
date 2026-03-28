"""
reporter.py — Log Sentinel
Module de génération de rapport HTML autonome (CSS inline, stdlib uniquement).
"""

import html
import os
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Constantes de scoring
# ---------------------------------------------------------------------------

ATTACK_SCORES: dict[str, int] = {
    "sqli":               20,
    "xss":                15,
    "brute_force":        25,
    "scan":               10,
    "path_traversal":     15,
    "command_injection":  20,
    "sensitive_files":    10,
    "malicious_ua":        5,
}

# Couleurs badge par type d'attaque
BADGE_COLORS: dict[str, str] = {
    "sqli":               "#f85149",
    "xss":                "#ff7b72",
    "brute_force":        "#ffa657",
    "scan":               "#d2a8ff",
    "path_traversal":     "#ffa657",
    "command_injection":  "#f85149",
    "sensitive_files":    "#79c0ff",
    "malicious_ua":       "#56d364",
}

DEFAULT_BADGE_COLOR = "#8b949e"

# ---------------------------------------------------------------------------
# CSS global (style terminal sécurité / dark)
# ---------------------------------------------------------------------------

CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
    background: #0d1117;
    color: #e6edf3;
    font-family: 'Courier New', Courier, monospace;
    font-size: 14px;
    line-height: 1.6;
    padding: 0 0 60px 0;
}

a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }

/* ── Header ── */
.header {
    background: #161b22;
    border-bottom: 2px solid #f85149;
    padding: 28px 40px 22px 40px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 12px;
}

.header-title {
    font-size: 22px;
    font-weight: bold;
    color: #f85149;
    letter-spacing: 1px;
}

.header-subtitle {
    font-size: 12px;
    color: #8b949e;
    margin-top: 4px;
}

.badge-blueteam {
    background: #0d419d;
    color: #58a6ff;
    border: 1px solid #58a6ff;
    border-radius: 20px;
    padding: 4px 14px;
    font-size: 12px;
    font-weight: bold;
    letter-spacing: 1px;
    white-space: nowrap;
}

/* ── Conteneur principal ── */
.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 32px 24px 0 24px;
}

/* ── Section ── */
.section {
    margin-bottom: 36px;
}

.section-title {
    font-size: 14px;
    font-weight: bold;
    color: #58a6ff;
    text-transform: uppercase;
    letter-spacing: 2px;
    border-left: 3px solid #58a6ff;
    padding-left: 10px;
    margin-bottom: 16px;
}

/* ── Score de risque ── */
.risk-wrapper {
    display: flex;
    align-items: center;
    gap: 32px;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 24px 32px;
}

.risk-score {
    font-size: 72px;
    font-weight: bold;
    line-height: 1;
    min-width: 120px;
    text-align: center;
}

.risk-score.low    { color: #56d364; }
.risk-score.medium { color: #ffa657; }
.risk-score.high   { color: #f85149; }

.risk-label {
    font-size: 13px;
    color: #8b949e;
    text-align: center;
    margin-top: 6px;
}

.risk-bar-track {
    flex: 1;
    background: #21262d;
    border-radius: 4px;
    height: 14px;
    overflow: hidden;
}

.risk-bar-fill {
    height: 100%;
    border-radius: 4px;
    transition: width 0s;
}

.risk-detail {
    font-size: 12px;
    color: #8b949e;
    margin-top: 8px;
}

/* ── Cards statistiques ── */
.cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
}

.card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 20px 24px;
    text-align: center;
}

.card-value {
    font-size: 36px;
    font-weight: bold;
    color: #58a6ff;
}

.card-label {
    font-size: 12px;
    color: #8b949e;
    margin-top: 4px;
    text-transform: uppercase;
    letter-spacing: 1px;
}

/* ── Tableaux ── */
.table-wrapper {
    overflow-x: auto;
    border: 1px solid #30363d;
    border-radius: 8px;
}

table {
    width: 100%;
    border-collapse: collapse;
    background: #161b22;
}

thead tr {
    background: #21262d;
}

thead th {
    padding: 10px 16px;
    text-align: left;
    font-size: 12px;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 1px;
    font-weight: bold;
    white-space: nowrap;
}

tbody tr {
    border-top: 1px solid #21262d;
}

tbody tr:hover {
    background: #1c2129;
}

tbody td {
    padding: 9px 16px;
    font-size: 13px;
    color: #e6edf3;
    vertical-align: top;
    word-break: break-all;
}

/* ── Badge type d'attaque ── */
.badge-attack {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 0.5px;
    white-space: nowrap;
    color: #0d1117;
}

/* ── Détails alerte ── */
.alert-details {
    font-size: 12px;
    color: #8b949e;
    max-width: 340px;
}

/* ── OSINT ── */
.osint-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 16px;
}

.osint-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 16px 20px;
}

.osint-ip {
    font-size: 15px;
    font-weight: bold;
    color: #58a6ff;
    margin-bottom: 8px;
}

.osint-row {
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    padding: 3px 0;
    border-bottom: 1px solid #21262d;
}

.osint-row:last-child { border-bottom: none; }

.osint-key { color: #8b949e; }
.osint-val { color: #e6edf3; font-weight: bold; }

/* ── Vide ── */
.empty-notice {
    color: #8b949e;
    font-size: 13px;
    padding: 20px;
    text-align: center;
    background: #161b22;
    border: 1px dashed #30363d;
    border-radius: 8px;
}

/* ── Footer ── */
.footer {
    text-align: center;
    font-size: 11px;
    color: #484f58;
    margin-top: 48px;
    padding-top: 16px;
    border-top: 1px solid #21262d;
}
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _h(value: object) -> str:
    """Échappe une valeur pour insertion HTML."""
    return html.escape(str(value) if value is not None else "")


def _compute_risk_score(alerts: list) -> int:
    """Calcule le score de risque global (0-100) à partir de la liste d'alertes."""
    score = 0
    for alert in alerts:
        attack_type = str(alert.get("type", "")).lower()
        score += ATTACK_SCORES.get(attack_type, 0)
    return min(score, 100)


def _risk_class(score: int) -> str:
    if score < 30:
        return "low"
    if score < 70:
        return "medium"
    return "high"


def _risk_label(score: int) -> str:
    if score < 30:
        return "RISQUE FAIBLE"
    if score < 70:
        return "RISQUE MODERE"
    return "RISQUE ELEVE"


def _bar_color(score: int) -> str:
    if score < 30:
        return "#56d364"
    if score < 70:
        return "#ffa657"
    return "#f85149"


def _badge_html(attack_type: str) -> str:
    color = BADGE_COLORS.get(str(attack_type).lower(), DEFAULT_BADGE_COLOR)
    return (
        f'<span class="badge-attack" style="background:{color};">'
        f'{_h(attack_type.upper())}</span>'
    )


# ---------------------------------------------------------------------------
# Sections HTML
# ---------------------------------------------------------------------------

def _render_header(generated_at: str) -> str:
    return f"""
<div class="header">
  <div>
    <div class="header-title">&#x1F6E1; Log Sentinel &mdash; Rapport d&apos;Analyse</div>
    <div class="header-subtitle">
      G&eacute;n&eacute;r&eacute; le&nbsp;: <strong>{_h(generated_at)}</strong>
    </div>
  </div>
  <span class="badge-blueteam">&#x25CF;&nbsp; BLUE TEAM</span>
</div>
"""


def _render_risk(alerts: list) -> str:
    score = _compute_risk_score(alerts)
    cls = _risk_class(score)
    label = _risk_label(score)
    bar_color = _bar_color(score)
    breakdown_parts = []
    for attack_type, pts in ATTACK_SCORES.items():
        count = sum(
            1 for a in alerts
            if str(a.get("type", "")).lower() == attack_type
        )
        if count:
            breakdown_parts.append(f"{attack_type.upper()}&nbsp;&times;{count} (+{count * pts})")
    breakdown = " &nbsp;|&nbsp; ".join(breakdown_parts) if breakdown_parts else "Aucune alerte"

    return f"""
<div class="section">
  <div class="section-title">Score de risque global</div>
  <div class="risk-wrapper">
    <div>
      <div class="risk-score {cls}">{score}</div>
      <div class="risk-label">{_h(label)}</div>
    </div>
    <div style="flex:1;">
      <div class="risk-bar-track">
        <div class="risk-bar-fill"
             style="width:{score}%; background:{bar_color};"></div>
      </div>
      <div class="risk-detail" style="margin-top:10px;">{breakdown}</div>
    </div>
  </div>
</div>
"""


def _render_stats(stats: dict) -> str:
    total_req  = stats.get("total_requests", 0)
    unique_ips = stats.get("unique_ips", 0)
    error_rate = stats.get("error_rate", 0)
    nb_alerts  = stats.get("total_alerts", 0)

    # Formatage du taux d'erreur
    if isinstance(error_rate, float):
        error_display = f"{error_rate:.1f}%"
    else:
        error_display = f"{error_rate}%"

    cards = [
        (total_req,       "Requêtes totales"),
        (unique_ips,      "IPs uniques"),
        (error_display,   "Taux d'erreur"),
        (nb_alerts,       "Alertes détectées"),
    ]

    cards_html = ""
    for value, label in cards:
        cards_html += f"""
    <div class="card">
      <div class="card-value">{_h(value)}</div>
      <div class="card-label">{_h(label)}</div>
    </div>"""

    return f"""
<div class="section">
  <div class="section-title">Statistiques globales</div>
  <div class="cards">{cards_html}
  </div>
</div>
"""


def _render_alerts(alerts: list) -> str:
    if not alerts:
        return """
<div class="section">
  <div class="section-title">Tableau des alertes</div>
  <div class="empty-notice">Aucune alerte enregistr&eacute;e.</div>
</div>
"""
    rows = ""
    for alert in alerts:
        attack_type = str(alert.get("type", "unknown"))
        ip      = alert.get("ip", "—")
        uri     = alert.get("uri", alert.get("url", "—"))
        details = alert.get("details", alert.get("message", ""))
        rows += f"""
      <tr>
        <td>{_badge_html(attack_type)}</td>
        <td style="font-family:monospace;white-space:nowrap;">{_h(ip)}</td>
        <td style="font-family:monospace;">{_h(uri)}</td>
        <td><div class="alert-details">{_h(details)}</div></td>
      </tr>"""

    return f"""
<div class="section">
  <div class="section-title">Tableau des alertes ({len(alerts)})</div>
  <div class="table-wrapper">
    <table>
      <thead>
        <tr>
          <th>Type</th>
          <th>IP</th>
          <th>URI</th>
          <th>D&eacute;tails</th>
        </tr>
      </thead>
      <tbody>{rows}
      </tbody>
    </table>
  </div>
</div>
"""


def _render_top_ips(stats: dict) -> str:
    top_ips = stats.get("top_ips", [])
    if not top_ips:
        return """
<div class="section">
  <div class="section-title">Top 10 IPs</div>
  <div class="empty-notice">Aucune donn&eacute;e disponible.</div>
</div>
"""
    # Accepte liste de tuples (ip, count) ou liste de dicts
    rows = ""
    for i, entry in enumerate(top_ips[:10], 1):
        if isinstance(entry, (list, tuple)):
            ip, count = entry[0], entry[1]
        elif isinstance(entry, dict):
            ip    = entry.get("ip", "—")
            count = entry.get("count", entry.get("requests", "—"))
        else:
            ip, count = str(entry), "—"
        rows += f"""
      <tr>
        <td style="color:#8b949e;width:40px;">#{i}</td>
        <td style="font-family:monospace;">{_h(ip)}</td>
        <td style="color:#58a6ff;text-align:right;">{_h(count)}</td>
      </tr>"""

    return f"""
<div class="section">
  <div class="section-title">Top 10 IPs</div>
  <div class="table-wrapper">
    <table>
      <thead>
        <tr><th>#</th><th>Adresse IP</th><th style="text-align:right;">Requ&ecirc;tes</th></tr>
      </thead>
      <tbody>{rows}
      </tbody>
    </table>
  </div>
</div>
"""


def _render_top_uris(stats: dict) -> str:
    top_uris = stats.get("top_uris", [])
    if not top_uris:
        return """
<div class="section">
  <div class="section-title">Top URIs</div>
  <div class="empty-notice">Aucune donn&eacute;e disponible.</div>
</div>
"""
    rows = ""
    for i, entry in enumerate(top_uris[:10], 1):
        if isinstance(entry, (list, tuple)):
            uri, count = entry[0], entry[1]
        elif isinstance(entry, dict):
            uri   = entry.get("uri", entry.get("url", "—"))
            count = entry.get("count", entry.get("requests", "—"))
        else:
            uri, count = str(entry), "—"
        rows += f"""
      <tr>
        <td style="color:#8b949e;width:40px;">#{i}</td>
        <td style="font-family:monospace;">{_h(uri)}</td>
        <td style="color:#58a6ff;text-align:right;">{_h(count)}</td>
      </tr>"""

    return f"""
<div class="section">
  <div class="section-title">Top URIs</div>
  <div class="table-wrapper">
    <table>
      <thead>
        <tr><th>#</th><th>URI</th><th style="text-align:right;">Requ&ecirc;tes</th></tr>
      </thead>
      <tbody>{rows}
      </tbody>
    </table>
  </div>
</div>
"""


def _render_http_codes(stats: dict) -> str:
    codes = stats.get("status_codes", stats.get("http_codes", {}))
    if not codes:
        return """
<div class="section">
  <div class="section-title">Distribution codes HTTP</div>
  <div class="empty-notice">Aucune donn&eacute;e disponible.</div>
</div>
"""
    # Tri par code
    sorted_codes = sorted(codes.items(), key=lambda x: str(x[0]))

    def _code_color(code: str) -> str:
        c = str(code)
        if c.startswith("2"):
            return "#56d364"
        if c.startswith("3"):
            return "#58a6ff"
        if c.startswith("4"):
            return "#ffa657"
        if c.startswith("5"):
            return "#f85149"
        return "#8b949e"

    rows = ""
    for code, count in sorted_codes:
        color = _code_color(str(code))
        rows += f"""
      <tr>
        <td style="color:{color};font-weight:bold;font-family:monospace;">{_h(code)}</td>
        <td style="color:#58a6ff;text-align:right;">{_h(count)}</td>
      </tr>"""

    return f"""
<div class="section">
  <div class="section-title">Distribution codes HTTP</div>
  <div class="table-wrapper">
    <table>
      <thead>
        <tr><th>Code HTTP</th><th style="text-align:right;">Occurrences</th></tr>
      </thead>
      <tbody>{rows}
      </tbody>
    </table>
  </div>
</div>
"""


def _render_osint(osint_data: dict) -> str:
    if not osint_data:
        return """
<div class="section">
  <div class="section-title">Donn&eacute;es OSINT</div>
  <div class="empty-notice">Aucune donn&eacute;e OSINT disponible.</div>
</div>
"""
    cards = ""
    for ip, info in osint_data.items():
        if not isinstance(info, dict):
            continue
        country = info.get("country", info.get("pays", "—"))
        city    = info.get("city",    info.get("ville", "—"))
        isp     = info.get("isp",     info.get("org", "—"))
        extra_rows = ""
        # Champs supplémentaires éventuels
        for key in info:
            if key.lower() not in {"country", "pays", "city", "ville", "isp", "org"}:
                extra_rows += f"""
        <div class="osint-row">
          <span class="osint-key">{_h(key)}</span>
          <span class="osint-val">{_h(info[key])}</span>
        </div>"""
        cards += f"""
    <div class="osint-card">
      <div class="osint-ip">{_h(ip)}</div>
      <div class="osint-row">
        <span class="osint-key">Pays</span>
        <span class="osint-val">{_h(country)}</span>
      </div>
      <div class="osint-row">
        <span class="osint-key">Ville</span>
        <span class="osint-val">{_h(city)}</span>
      </div>
      <div class="osint-row">
        <span class="osint-key">ISP</span>
        <span class="osint-val">{_h(isp)}</span>
      </div>{extra_rows}
    </div>"""

    if not cards:
        return """
<div class="section">
  <div class="section-title">Donn&eacute;es OSINT</div>
  <div class="empty-notice">Aucune entr&eacute;e OSINT valide.</div>
</div>
"""

    return f"""
<div class="section">
  <div class="section-title">Donn&eacute;es OSINT</div>
  <div class="osint-grid">{cards}
  </div>
</div>
"""


def _render_footer(generated_at: str) -> str:
    return f"""
<div class="footer">
  Log Sentinel &mdash; Rapport g&eacute;n&eacute;r&eacute; le {_h(generated_at)}
  &nbsp;&bull;&nbsp; Usage interne Blue Team uniquement
</div>
"""


# ---------------------------------------------------------------------------
# Classe principale
# ---------------------------------------------------------------------------

class HTMLReporter:
    """Génère un rapport HTML autonome (CSS inline) pour Log Sentinel."""

    def generate(
        self,
        alerts: list,
        stats: dict,
        osint_data: dict,
        output_path: str,
    ) -> str:
        """
        Génère le rapport HTML et l'écrit dans *output_path*.

        Parameters
        ----------
        alerts      : liste de dicts décrivant chaque alerte détectée.
        stats       : dict de statistiques globales (total_requests, unique_ips,
                      error_rate, total_alerts, top_ips, top_uris, status_codes…).
        osint_data  : dict {ip: {country, city, isp, …}} des données OSINT.
        output_path : chemin du fichier HTML à créer (créé si absent).

        Returns
        -------
        str : chemin absolu du fichier généré.
        """
        generated_at = datetime.now().strftime("%d/%m/%Y à %H:%M:%S")

        body = (
            _render_header(generated_at)
            + '<div class="container">'
            + _render_risk(alerts)
            + _render_stats(stats)
            + _render_alerts(alerts)
            + _render_top_ips(stats)
            + _render_top_uris(stats)
            + _render_http_codes(stats)
            + _render_osint(osint_data)
            + _render_footer(generated_at)
            + "</div>"
        )

        document = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Log Sentinel &mdash; Rapport d&apos;Analyse</title>
  <style>
{CSS}
  </style>
</head>
<body>
{body}
</body>
</html>
"""
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(document, encoding="utf-8")
        return str(output.resolve())
