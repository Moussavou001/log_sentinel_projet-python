"""
main.py - Point d'entrée CLI principal de Log Sentinel.

Orchestre les modules src/ pour analyser des fichiers de logs,
détecter des attaques, calculer des statistiques et générer des rapports.
"""

import argparse
import sys
import os
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from rich import print as rprint

from src.loader import LogLoader
from src.parser import LogParser
from src.detector import AttackDetector
from src.statistics import LogStatistics
from src.osint import OSINTChecker

# HTMLReporter est optionnel : si le module n'existe pas encore on le gère
# proprement pour ne pas bloquer le reste du programme.
try:
    from src.reporter import HTMLReporter
    _REPORTER_AVAILABLE = True
except ImportError:
    _REPORTER_AVAILABLE = False


# ---------------------------------------------------------------------------
# Couleurs et styles Rich utilisés dans l'ensemble du fichier
# ---------------------------------------------------------------------------

_ATTACK_COLORS: dict[str, str] = {
    "sql_injection":    "bold red",
    "xss":              "bold magenta",
    "path_traversal":   "bold yellow",
    "command_injection":"bold red",
    "sensitive_files":  "yellow",
    "malicious_ua":     "bold cyan",
    "brute_force":      "bold orange1",
    "scan":             "bold blue",
}


# ---------------------------------------------------------------------------
# 1. Parseur d'arguments CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Construit et retourne le parseur argparse de l'application."""
    parser = argparse.ArgumentParser(
        prog="log-sentinel",
        description="Log Sentinel — Blue Team Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemples :\n"
            "  python main.py -f access.log\n"
            "  python main.py -f access.log --check-ip --output-dir out/\n"
            "  python main.py -f access.log --no-report --bf-threshold 3\n"
        ),
    )

    parser.add_argument(
        "-f", "--file",
        required=True,
        metavar="FILE",
        help="Chemin vers le fichier de log à analyser.",
    )

    parser.add_argument(
        "--bf-threshold",
        type=int,
        default=5,
        metavar="N",
        dest="bf_threshold",
        help="Nombre d'échecs d'authentification (401/403) avant alerte brute-force. (défaut : 5)",
    )

    parser.add_argument(
        "--scan-threshold",
        type=int,
        default=10,
        metavar="N",
        dest="scan_threshold",
        help="Nombre d'URIs distinctes avant détection de scan. (défaut : 10)",
    )

    parser.add_argument(
        "--report",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Générer (ou non) un rapport HTML. (défaut : activé)",
    )

    parser.add_argument(
        "--check-ip",
        action="store_true",
        default=False,
        dest="check_ip",
        help="Activer la vérification OSINT des IPs suspectes via ip-api.com.",
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default="reports",
        metavar="DIR",
        dest="output_dir",
        help="Dossier de sortie pour le rapport HTML. (défaut : reports)",
    )

    return parser


# ---------------------------------------------------------------------------
# 2. Bannière ASCII
# ---------------------------------------------------------------------------

BANNER = r"""
 _                  _____            _   _            _
| |    ___   __ _  / ____|          | | (_)          | |
| |   / _ \ / _` | \___  \  ___ _ __ | |_ _ _ __   ___ | |
| |__| (_) | (_| |  ___) |/ _ \ '_ \| __| | '_ \ / _ \| |
|_____\___/ \__, | |____/ \  __/ | | | |_| | | | |  __/| |
             __/ |         \___|_| |_|\__|_|_| |_|\___||_|
            |___/
"""


def print_banner(console: Console) -> None:
    """Affiche la bannière ASCII de Log Sentinel dans un Rich Panel rouge."""
    content = (
        f"[bold red]{BANNER}[/bold red]\n"
        "[bold white]  Blue Team Security Analyzer[/bold white]  |  "
        "[dim]v1.0.0[/dim]"
    )
    console.print(
        Panel(
            content,
            border_style="red",
            padding=(0, 2),
        )
    )


# ---------------------------------------------------------------------------
# 3. Affichage des alertes
# ---------------------------------------------------------------------------

def print_alerts(console: Console, alerts: list) -> None:
    """Affiche les alertes de sécurité dans une Rich Table colorée."""
    if not alerts:
        console.print(
            "\n[bold green]  Aucune alerte détectée.[/bold green]\n"
        )
        return

    table = Table(
        title=f"[bold red] Alertes de sécurité ({len(alerts)} détectées)[/bold red]",
        show_header=True,
        header_style="bold white on red",
        border_style="red",
        row_styles=["", "dim"],
        expand=True,
    )

    table.add_column("#",          style="dim",         width=4,  no_wrap=True)
    table.add_column("Type",       style="bold",        width=18, no_wrap=True)
    table.add_column("IP",         style="cyan",        width=16, no_wrap=True)
    table.add_column("URI",        style="yellow",      width=30, overflow="fold")
    table.add_column("Détails",    style="white",       min_width=20, overflow="fold")

    for idx, alert in enumerate(alerts, start=1):
        color = _ATTACK_COLORS.get(alert.attack_type, "white")
        table.add_row(
            str(idx),
            f"[{color}]{alert.attack_type}[/{color}]",
            alert.ip or "-",
            alert.uri[:80] if alert.uri else "-",
            alert.details or "-",
        )

    console.print()
    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# 4. Affichage des statistiques
# ---------------------------------------------------------------------------

def print_stats(console: Console, stats: dict) -> None:
    """Affiche les statistiques de logs dans des Rich Tables."""
    console.print(
        Panel("[bold cyan] Statistiques générales[/bold cyan]",
              border_style="cyan",
              padding=(0, 2))
    )

    # -- Tableau récapitulatif global --
    summary_table = Table(
        show_header=True,
        header_style="bold cyan",
        border_style="cyan",
        expand=False,
    )
    summary_table.add_column("Métrique",  style="bold white", min_width=25)
    summary_table.add_column("Valeur",    style="cyan",       min_width=15)

    summary_table.add_row("Total requêtes",    str(stats.get("total_requests", 0)))
    summary_table.add_row("IPs uniques",       str(stats.get("unique_ips", 0)))
    summary_table.add_row("Taux d'erreur",     f"{stats.get('error_rate', 0.0):.2f} %")
    console.print(summary_table)
    console.print()

    # -- Top IPs --
    top_ips: list = stats.get("top_ips", [])
    if top_ips:
        ip_table = Table(
            title="[bold cyan]Top IPs[/bold cyan]",
            show_header=True,
            header_style="bold white on dark_blue",
            border_style="blue",
        )
        ip_table.add_column("IP",          style="cyan",   width=20, no_wrap=True)
        ip_table.add_column("Requêtes",    style="white",  width=12, justify="right")

        for ip, count in top_ips:
            ip_table.add_row(ip, str(count))

        console.print(ip_table)
        console.print()

    # -- Distribution des codes HTTP --
    status_codes: dict = stats.get("status_codes", {})
    if status_codes:
        status_table = Table(
            title="[bold cyan]Codes HTTP[/bold cyan]",
            show_header=True,
            header_style="bold white on dark_blue",
            border_style="blue",
        )
        status_table.add_column("Code",     style="bold",   width=8,  no_wrap=True)
        status_table.add_column("Nombre",   style="white",  width=10, justify="right")

        for code, count in sorted(status_codes.items()):
            try:
                code_int = int(code)
                if code_int < 300:
                    color = "green"
                elif code_int < 400:
                    color = "yellow"
                else:
                    color = "red"
            except ValueError:
                color = "white"
            status_table.add_row(f"[{color}]{code}[/{color}]", str(count))

        console.print(status_table)
        console.print()

    # -- Top URIs --
    top_uris: list = stats.get("top_uris", [])
    if top_uris:
        uri_table = Table(
            title="[bold cyan]Top URIs[/bold cyan]",
            show_header=True,
            header_style="bold white on dark_blue",
            border_style="blue",
            expand=True,
        )
        uri_table.add_column("URI",         style="yellow", overflow="fold")
        uri_table.add_column("Requêtes",    style="white",  width=10, justify="right")

        for uri, count in top_uris:
            uri_table.add_row(uri[:80] if uri else "-", str(count))

        console.print(uri_table)
        console.print()

    # -- Méthodes HTTP --
    methods: dict = stats.get("methods", {})
    if methods:
        method_table = Table(
            title="[bold cyan]Méthodes HTTP[/bold cyan]",
            show_header=True,
            header_style="bold white on dark_blue",
            border_style="blue",
        )
        method_table.add_column("Méthode",  style="bold magenta", width=12, no_wrap=True)
        method_table.add_column("Nombre",   style="white",        width=10, justify="right")

        for method, count in sorted(methods.items(), key=lambda x: -x[1]):
            method_table.add_row(method, str(count))

        console.print(method_table)
        console.print()


# ---------------------------------------------------------------------------
# 5. Fonction principale
# ---------------------------------------------------------------------------

def main() -> None:
    """Point d'entrée principal de Log Sentinel."""
    console = Console()
    parser = build_parser()
    args = parser.parse_args()

    # -----------------------------------------------------------------------
    # Bannière
    # -----------------------------------------------------------------------
    print_banner(console)

    # -----------------------------------------------------------------------
    # Chargement du fichier de log
    # -----------------------------------------------------------------------
    console.rule("[bold white]Chargement[/bold white]")

    loader = LogLoader()

    try:
        lines = loader.load(args.file)
    except FileNotFoundError as exc:
        console.print(f"[bold red] Erreur :[/bold red] {exc}")
        sys.exit(1)
    except UnicodeDecodeError as exc:
        console.print(
            f"[bold red] Erreur d'encodage :[/bold red] Impossible de lire "
            f"'{args.file}' : {exc.reason}"
        )
        sys.exit(1)
    except OSError as exc:
        console.print(
            f"[bold red] Erreur système :[/bold red] Impossible d'ouvrir "
            f"'{args.file}' : {exc}"
        )
        sys.exit(1)

    if not lines:
        console.print("[bold yellow]  Le fichier est vide ou ne contient aucune ligne valide.[/bold yellow]")
        sys.exit(0)

    console.print(f"[green] Fichier chargé :[/green] [white]{args.file}[/white]")
    console.print(f"[green] Lignes lues   :[/green] [white]{len(lines):,}[/white]")

    # -----------------------------------------------------------------------
    # Détection du format
    # -----------------------------------------------------------------------
    log_format = loader.detect_format(lines)

    format_color = {
        "apache": "green",
        "nginx":  "cyan",
        "syslog": "yellow",
    }.get(log_format, "dim white")

    console.print(
        f"[green] Format détecté :[/green] [{format_color}]{log_format.upper()}[/{format_color}]"
    )
    console.print()

    # -----------------------------------------------------------------------
    # Parsing des lignes
    # -----------------------------------------------------------------------
    console.rule("[bold white]Parsing[/bold white]")

    log_parser = LogParser()

    try:
        entries_obj = log_parser.parse_all(lines, log_format)
    except Exception as exc:
        console.print(f"[bold red] Erreur de parsing :[/bold red] {exc}")
        sys.exit(1)

    if not entries_obj:
        console.print(
            "[bold yellow]  Aucune entrée n'a pu être parsée. "
            "Vérifiez le format du fichier.[/bold yellow]"
        )
        sys.exit(0)

    # Conversion LogEntry -> dict pour les modules en aval
    entries: list[dict] = []
    for e in entries_obj:
        entries.append({
            "ip":         e.ip,
            "timestamp":  e.timestamp,
            "method":     e.method,
            "uri":        e.uri,
            "status":     e.status_code,
            "size":       e.size,
            "user_agent": e.user_agent,
        })

    console.print(
        f"[green] Entrées parsées :[/green] [white]{len(entries):,}[/white] "
        f"[dim]/ {len(lines):,} lignes[/dim]"
    )
    console.print()

    # -----------------------------------------------------------------------
    # Détection des attaques (avec barre de progression)
    # -----------------------------------------------------------------------
    console.rule("[bold white]Détection[/bold white]")

    detector = AttackDetector()
    detector.CONFIG["BRUTE_FORCE_THRESHOLD"] = args.bf_threshold
    detector.CONFIG["SCAN_THRESHOLD"]        = args.scan_threshold

    alerts: list = []

    try:
        with Progress(transient=True, console=console) as progress:
            task = progress.add_task(
                "[cyan]Analyse en cours...[/cyan]",
                total=len(entries),
            )
            # Analyse par chunks pour permettre l'avancement de la barre
            CHUNK = max(1, len(entries) // 20)
            all_entries_local = list(entries)  # copie locale

            # Signatures entry-par-entry avec avancement
            for i in range(0, len(all_entries_local), CHUNK):
                chunk = all_entries_local[i : i + CHUNK]
                for entry in chunk:
                    alerts.extend(detector.detect_signature(entry))
                progress.advance(task, advance=len(chunk))

            # Brute-force et scan (vue globale — rapides)
            alerts.extend(detector.detect_brute_force(all_entries_local))
            alerts.extend(detector.detect_scan(all_entries_local))

    except Exception as exc:
        console.print(f"[bold red] Erreur lors de la détection :[/bold red] {exc}")
        sys.exit(1)

    console.print(
        f"[green] Analyse terminée.[/green] "
        f"[bold red]{len(alerts)} alerte(s)[/bold red] détectée(s)."
    )
    console.print()

    # -----------------------------------------------------------------------
    # Affichage des alertes
    # -----------------------------------------------------------------------
    console.rule("[bold red]Alertes[/bold red]")
    print_alerts(console, alerts)

    # -----------------------------------------------------------------------
    # Statistiques
    # -----------------------------------------------------------------------
    console.rule("[bold cyan]Statistiques[/bold cyan]")

    stats_calculator = LogStatistics()
    try:
        stats = stats_calculator.compute(entries)
    except Exception as exc:
        console.print(f"[bold red] Erreur de calcul des statistiques :[/bold red] {exc}")
        stats = {}

    if stats:
        print_stats(console, stats)

    # -----------------------------------------------------------------------
    # OSINT — vérification des top 5 IPs suspectes
    # -----------------------------------------------------------------------
    if args.check_ip:
        console.rule("[bold magenta]OSINT[/bold magenta]")

        # Collecte les IPs impliquées dans des alertes
        suspect_ips: list[str] = []
        seen: set[str] = set()
        for alert in alerts:
            if alert.ip and alert.ip not in seen:
                suspect_ips.append(alert.ip)
                seen.add(alert.ip)

        # Si pas assez d'alertes, complète avec le top des IPs de stats
        if len(suspect_ips) < 5 and stats.get("top_ips"):
            for ip, _ in stats["top_ips"]:
                if ip not in seen:
                    suspect_ips.append(ip)
                    seen.add(ip)
                if len(suspect_ips) >= 5:
                    break

        top5_ips = suspect_ips[:5]

        if not top5_ips:
            console.print("[dim]  Aucune IP suspecte à vérifier.[/dim]")
        else:
            console.print(
                f"[magenta] Vérification OSINT de {len(top5_ips)} IP(s)...[/magenta]"
            )
            osint = OSINTChecker()

            osint_table = Table(
                title="[bold magenta]Résultats OSINT[/bold magenta]",
                show_header=True,
                header_style="bold white on dark_magenta",
                border_style="magenta",
            )
            osint_table.add_column("IP",       style="cyan",    width=18, no_wrap=True)
            osint_table.add_column("Pays",     style="white",   width=15, no_wrap=True)
            osint_table.add_column("Ville",    style="white",   width=15, no_wrap=True)
            osint_table.add_column("FAI",      style="yellow",  width=25, overflow="fold")
            osint_table.add_column("Proxy",    style="bold",    width=8,  no_wrap=True)

            try:
                results = osint.check_ips(top5_ips, max_ips=5)
            except Exception as exc:
                console.print(
                    f"[bold red] Erreur OSINT :[/bold red] {exc}"
                )
                results = {}

            for ip in top5_ips:
                info = results.get(ip, {})
                if not info:
                    osint_table.add_row(ip, "[dim]N/A[/dim]", "[dim]N/A[/dim]",
                                        "[dim]N/A[/dim]", "[dim]-[/dim]")
                else:
                    proxy_str = (
                        "[bold red]OUI[/bold red]"
                        if info.get("is_proxy")
                        else "[green]non[/green]"
                    )
                    osint_table.add_row(
                        ip,
                        info.get("country", "-"),
                        info.get("city", "-"),
                        info.get("isp", "-"),
                        proxy_str,
                    )

            console.print(osint_table)
            console.print()

    # -----------------------------------------------------------------------
    # Génération du rapport HTML
    # -----------------------------------------------------------------------
    report_path: str | None = None

    if args.report:
        console.rule("[bold green]Rapport HTML[/bold green]")

        if not _REPORTER_AVAILABLE:
            console.print(
                "[bold yellow]  HTMLReporter non disponible "
                "(src/reporter.py introuvable). Rapport ignoré.[/bold yellow]"
            )
        else:
            try:
                output_dir = Path(args.output_dir)
                output_dir.mkdir(parents=True, exist_ok=True)

                reporter = HTMLReporter()
                report_path = reporter.generate(
                    alerts=[vars(a) if hasattr(a, '__dataclass_fields__') else a for a in alerts],
                    stats=stats,
                    osint_data={},
                    output_path=str(output_dir / "report.html"),
                )
                console.print(
                    f"[bold green] Rapport généré :[/bold green] "
                    f"[underline white]{report_path}[/underline white]"
                )
            except OSError as exc:
                console.print(
                    f"[bold red] Impossible de créer le dossier de sortie :[/bold red] {exc}"
                )
            except Exception as exc:
                console.print(
                    f"[bold red] Erreur lors de la génération du rapport :[/bold red] {exc}"
                )

        console.print()

    # -----------------------------------------------------------------------
    # Résumé final avec score de risque
    # -----------------------------------------------------------------------
    console.rule("[bold white]Résumé final[/bold white]")

    total_requests: int  = stats.get("total_requests", len(entries))
    unique_ips: int      = stats.get("unique_ips", 0)
    error_rate: float    = stats.get("error_rate", 0.0)
    alert_count: int     = len(alerts)

    # Score de risque simple (0-100)
    # Composantes :
    #   - Nombre d'alertes (pondéré, plafonné à 50)
    #   - Taux d'erreur    (pondéré sur 30)
    #   - Présence de scan/brute-force (bonus de 20)
    alert_score   = min(50, alert_count * 2)
    error_score   = min(30, error_rate * 0.6)
    heavy_types   = {"brute_force", "scan", "sql_injection", "command_injection"}
    heavy_penalty = 20 if any(a.attack_type in heavy_types for a in alerts) else 0
    risk_score    = int(min(100, alert_score + error_score + heavy_penalty))

    if risk_score < 20:
        risk_color, risk_label = "bold green",  "FAIBLE"
    elif risk_score < 50:
        risk_color, risk_label = "bold yellow", "MODÉRÉ"
    elif risk_score < 75:
        risk_color, risk_label = "bold orange1","ÉLEVÉ"
    else:
        risk_color, risk_label = "bold red",    "CRITIQUE"

    summary_table = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
    )
    summary_table.add_column("Clé",    style="bold white",   min_width=28)
    summary_table.add_column("Valeur", style="white")

    summary_table.add_row("Fichier analysé",       args.file)
    summary_table.add_row("Format",                log_format.upper())
    summary_table.add_row("Total requêtes",        f"{total_requests:,}")
    summary_table.add_row("IPs uniques",           str(unique_ips))
    summary_table.add_row("Taux d'erreur",         f"{error_rate:.2f} %")
    summary_table.add_row("Alertes détectées",     str(alert_count))
    summary_table.add_row(
        "Score de risque",
        f"[{risk_color}]{risk_score}/100 — {risk_label}[/{risk_color}]",
    )
    if report_path:
        summary_table.add_row("Rapport HTML",      report_path)

    console.print(
        Panel(
            summary_table,
            title="[bold white] Log Sentinel — Résumé[/bold white]",
            border_style=risk_color.replace("bold ", ""),
            padding=(1, 2),
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# 6. Entrée du script
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
