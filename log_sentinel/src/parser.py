"""
parser.py - Module de parsing des lignes de logs pour Log Sentinel.

Supporte les formats : Apache Combined Log, Nginx, Syslog.
"""

import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Patterns de reconnaissance
# ---------------------------------------------------------------------------

_APACHE_PATTERN = re.compile(
    r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"'
)

_NGINX_PATTERN = re.compile(
    r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"'
)

_SYSLOG_PATTERN = re.compile(
    r'(\w{3}\s+\d+\s+\d+:\d+:\d+) (\S+) ([^:]+): (.*)'
)


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class LogEntry:
    """Représente une entrée de log parsée."""

    ip: str = ""
    timestamp: str = ""
    method: str = ""
    uri: str = ""
    status_code: str = ""
    size: str = ""
    user_agent: str = ""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class LogParser:
    """Parse des lignes de logs selon différents formats."""

    # ------------------------------------------------------------------
    # Méthodes privées par format
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_apache(line: str) -> LogEntry | None:
        """Parse une ligne au format Apache Combined Log."""
        match = _APACHE_PATTERN.match(line)
        if not match:
            return None
        ip, timestamp, method, uri, status_code, size, _, user_agent = match.groups()
        return LogEntry(
            ip=ip,
            timestamp=timestamp,
            method=method,
            uri=uri,
            status_code=status_code,
            size=size if size != "-" else "",
            user_agent=user_agent,
        )

    @staticmethod
    def _parse_nginx(line: str) -> LogEntry | None:
        """Parse une ligne au format Nginx (identique Apache Combined Log)."""
        match = _NGINX_PATTERN.match(line)
        if not match:
            return None
        ip, timestamp, method, uri, status_code, size, _, user_agent = match.groups()
        return LogEntry(
            ip=ip,
            timestamp=timestamp,
            method=method,
            uri=uri,
            status_code=status_code,
            size=size if size != "-" else "",
            user_agent=user_agent,
        )

    @staticmethod
    def _parse_syslog(line: str) -> LogEntry | None:
        """Parse une ligne au format Syslog."""
        match = _SYSLOG_PATTERN.match(line)
        if not match:
            return None
        timestamp, host, process, message = match.groups()
        # Pour syslog, on mappe les champs disponibles sur les champs pertinents
        return LogEntry(
            ip=host,
            timestamp=timestamp.strip(),
            method=process.strip(),
            uri=message,
            status_code="",
            size="",
            user_agent="",
        )

    # ------------------------------------------------------------------
    # API publique
    # ------------------------------------------------------------------

    def parse_line(self, line: str, fmt: str) -> LogEntry | None:
        """Parse une seule ligne selon le format spécifié.

        Args:
            line: La ligne brute à parser.
            fmt:  Le format détecté parmi "apache", "nginx", "syslog",
                  "unknown".

        Returns:
            Un objet LogEntry si le parsing réussit, None sinon.
        """
        line = line.strip()
        if not line:
            return None

        fmt_lower = fmt.lower()

        if fmt_lower == "apache":
            return self._parse_apache(line)
        if fmt_lower == "nginx":
            return self._parse_nginx(line)
        if fmt_lower == "syslog":
            return self._parse_syslog(line)

        # fmt == "unknown" ou toute valeur non reconnue : tente les formats
        # dans l'ordre et retourne le premier résultat valide.
        for parser in (self._parse_apache, self._parse_nginx, self._parse_syslog):
            entry = parser(line)
            if entry is not None:
                return entry

        return None

    def parse_all(self, lines: list[str], fmt: str) -> list[LogEntry]:
        """Parse une liste de lignes et retourne les entrées valides.

        Les lignes dont le parsing échoue (None) sont silencieusement ignorées.

        Args:
            lines: Liste des lignes brutes.
            fmt:   Format à utiliser pour chaque ligne.

        Returns:
            Liste des LogEntry parsées avec succès.
        """
        entries: list[LogEntry] = []
        for line in lines:
            entry = self.parse_line(line, fmt)
            if entry is not None:
                entries.append(entry)
        return entries
