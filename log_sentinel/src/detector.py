"""
detector.py - Module de détection d'attaques pour Log Sentinel.

Ce module constitue le coeur analytique du projet : il identifie les tentatives
d'injection SQL, XSS, traversée de répertoires, injection de commandes, accès à
des fichiers sensibles, agents malveillants, force brute et scans de ports/URIs.
"""

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# Patterns de signature d'attaque
# ---------------------------------------------------------------------------

ATTACK_PATTERNS: dict[str, re.Pattern] = {
    "sql_injection": re.compile(
        r"UNION\s+SELECT|OR\s+1\s*=\s*1|DROP\s+TABLE|INSERT\s+INTO|'\s*OR\s+'|--",
        re.IGNORECASE,
    ),
    "xss": re.compile(
        r"<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(",
        re.IGNORECASE,
    ),
    "path_traversal": re.compile(
        r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|C:\\Windows",
        re.IGNORECASE,
    ),
    "command_injection": re.compile(
        r";ls|\|cat|\$\(|&&rm|`whoami`",
        re.IGNORECASE,
    ),
    "sensitive_files": re.compile(
        r"\.env|\.git|\.htaccess|wp-config\.php|/etc/passwd|id_rsa",
        re.IGNORECASE,
    ),
    "malicious_ua": re.compile(
        r"sqlmap|nikto|nmap|burp|wpscan|masscan|metasploit|hydra|dirbuster",
        re.IGNORECASE,
    ),
}


# ---------------------------------------------------------------------------
# Dataclass Alert
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    """Représente une alerte de sécurité levée lors de l'analyse des logs."""

    attack_type: str
    ip: str
    uri: str
    user_agent: str
    details: str


# ---------------------------------------------------------------------------
# Détecteur principal
# ---------------------------------------------------------------------------

class AttackDetector:
    """Détecte différentes catégories d'attaques dans des entrées de logs."""

    CONFIG: dict[str, int] = {
        "BRUTE_FORCE_THRESHOLD": 5,
        "SCAN_THRESHOLD": 10,
    }

    # ------------------------------------------------------------------
    # Détection par signature (regex)
    # ------------------------------------------------------------------

    def detect_signature(self, entry: dict[str, Any]) -> list[Alert]:
        """Analyse une entrée de log unique et retourne les alertes de signature.

        Champs attendus dans *entry* :
            - ``ip``         (str) adresse IP source
            - ``uri``        (str) URI de la requête
            - ``user_agent`` (str) chaîne User-Agent
            - ``status``     (int | str) code HTTP de la réponse  [optionnel]

        Les patterns ``malicious_ua`` sont appliqués sur le champ ``user_agent`` ;
        tous les autres patterns sont appliqués sur le champ ``uri``.
        """
        alerts: list[Alert] = []

        ip: str = entry.get("ip", "")
        uri: str = entry.get("uri", "")
        user_agent: str = entry.get("user_agent", "")

        # Patterns appliqués sur l'URI
        uri_patterns = (
            "sql_injection",
            "xss",
            "path_traversal",
            "command_injection",
            "sensitive_files",
        )
        for attack_type in uri_patterns:
            pattern = ATTACK_PATTERNS[attack_type]
            match = pattern.search(uri)
            if match:
                alerts.append(
                    Alert(
                        attack_type=attack_type,
                        ip=ip,
                        uri=uri,
                        user_agent=user_agent,
                        details=f"Pattern matched in URI: '{match.group(0)}'",
                    )
                )

        # Pattern appliqué sur le User-Agent
        ua_match = ATTACK_PATTERNS["malicious_ua"].search(user_agent)
        if ua_match:
            alerts.append(
                Alert(
                    attack_type="malicious_ua",
                    ip=ip,
                    uri=uri,
                    user_agent=user_agent,
                    details=f"Malicious user-agent detected: '{ua_match.group(0)}'",
                )
            )

        return alerts

    # ------------------------------------------------------------------
    # Détection de force brute
    # ------------------------------------------------------------------

    def detect_brute_force(self, entries: list[dict[str, Any]]) -> list[Alert]:
        """Identifie les IPs ayant généré plus de BRUTE_FORCE_THRESHOLD (5)
        réponses 401 ou 403, signe probable d'une attaque par force brute.

        Champs attendus dans chaque *entry* :
            - ``ip``     (str)       adresse IP source
            - ``status`` (int | str) code HTTP de la réponse
            - ``uri``        (str)   [optionnel, pour le contexte de l'alerte]
            - ``user_agent`` (str)   [optionnel, pour le contexte de l'alerte]
        """
        threshold: int = self.CONFIG["BRUTE_FORCE_THRESHOLD"]
        alerts: list[Alert] = []

        # Compte les codes 401/403 par IP
        fail_counts: Counter = Counter()
        ip_last_entry: dict[str, dict[str, Any]] = {}

        for entry in entries:
            ip = entry.get("ip", "")
            status = str(entry.get("status", ""))
            if status in ("401", "403"):
                fail_counts[ip] += 1
                ip_last_entry[ip] = entry

        for ip, count in fail_counts.items():
            if count > threshold:
                last = ip_last_entry[ip]
                alerts.append(
                    Alert(
                        attack_type="brute_force",
                        ip=ip,
                        uri=last.get("uri", ""),
                        user_agent=last.get("user_agent", ""),
                        details=(
                            f"Brute force suspected: {count} failed "
                            f"authentications (401/403) from {ip} "
                            f"(threshold={threshold})"
                        ),
                    )
                )

        return alerts

    # ------------------------------------------------------------------
    # Détection de scan
    # ------------------------------------------------------------------

    def detect_scan(self, entries: list[dict[str, Any]]) -> list[Alert]:
        """Identifie les IPs qui sondent un grand nombre d'URIs distinctes avec
        un taux élevé de réponses 404 (scan de ressources / énumération).

        Critères (cumulatifs) :
            - nombre d'URIs distinctes > SCAN_THRESHOLD (10)
            - proportion de réponses 404 > 50 %

        Champs attendus dans chaque *entry* :
            - ``ip``         (str)       adresse IP source
            - ``uri``        (str)       URI de la requête
            - ``status``     (int | str) code HTTP de la réponse
            - ``user_agent`` (str)       [optionnel]
        """
        scan_threshold: int = self.CONFIG["SCAN_THRESHOLD"]
        alerts: list[Alert] = []

        # Structure : ip -> {"uris": set, "total": int, "404s": int}
        ip_stats: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"uris": set(), "total": 0, "not_found": 0, "user_agent": ""}
        )

        for entry in entries:
            ip = entry.get("ip", "")
            uri = entry.get("uri", "")
            status = str(entry.get("status", ""))
            ua = entry.get("user_agent", "")

            stats = ip_stats[ip]
            stats["uris"].add(uri)
            stats["total"] += 1
            if status == "404":
                stats["not_found"] += 1
            if ua:
                stats["user_agent"] = ua  # conserve le dernier UA observé

        for ip, stats in ip_stats.items():
            unique_uris = len(stats["uris"])
            total = stats["total"]
            not_found = stats["not_found"]

            if total == 0:
                continue

            not_found_ratio = not_found / total

            if unique_uris > scan_threshold and not_found_ratio > 0.5:
                alerts.append(
                    Alert(
                        attack_type="scan",
                        ip=ip,
                        uri="(multiple)",
                        user_agent=stats["user_agent"],
                        details=(
                            f"Scan suspected from {ip}: "
                            f"{unique_uris} distinct URIs probed, "
                            f"{not_found_ratio:.0%} returned 404 "
                            f"(threshold: >{scan_threshold} URIs and >50% 404)"
                        ),
                    )
                )

        return alerts

    # ------------------------------------------------------------------
    # Point d'entrée principal
    # ------------------------------------------------------------------

    def analyze(self, entries: list[dict[str, Any]]) -> list[Alert]:
        """Lance toutes les détections sur la liste d'entrées et retourne
        l'ensemble des alertes produites.

        Les détections effectuées sont :
            1. Signatures (par entrée individuelle)
            2. Force brute  (analyse globale de la liste)
            3. Scan         (analyse globale de la liste)

        Paramètre
        ---------
        entries:
            Liste de dicts représentant des lignes de log parsées.
            Champs typiques : ``ip``, ``uri``, ``user_agent``, ``status``.

        Retour
        ------
        list[Alert]
            Toutes les alertes levées, dans l'ordre : signatures d'abord,
            puis force brute, puis scans.
        """
        all_alerts: list[Alert] = []

        # 1. Détection par signature (entrée par entrée)
        for entry in entries:
            all_alerts.extend(self.detect_signature(entry))

        # 2. Détection de force brute (vue globale)
        all_alerts.extend(self.detect_brute_force(entries))

        # 3. Détection de scan (vue globale)
        all_alerts.extend(self.detect_scan(entries))

        return all_alerts
