"""
statistics.py - Module de statistiques pour Log Sentinel.

Calcule des métriques agrégées à partir d'une liste d'entrées de logs analysées.
"""

from collections import Counter, defaultdict
from typing import Any


class LogStatistics:
    """Calcule des statistiques descriptives sur les entrées de logs."""

    def compute(self, entries: list) -> dict[str, Any]:
        """
        Calcule les statistiques principales à partir d'une liste d'entrées de logs.

        Args:
            entries: Liste de dicts représentant des entrées de logs parsées.
                     Chaque entrée peut contenir les clés :
                     'ip', 'status', 'uri', 'user_agent', 'method'.

        Returns:
            Dictionnaire contenant :
            - total_requests   : nombre total d'entrées
            - unique_ips       : nombre d'IPs distinctes
            - top_ips          : 10 IPs les plus actives [(ip, count)]
            - status_codes     : distribution des codes HTTP {code: count}
            - top_uris         : 10 URIs les plus demandées [(uri, count)]
            - top_user_agents  : 5 user-agents les plus fréquents [(ua, count)]
            - methods          : distribution des méthodes HTTP {method: count}
            - error_rate       : pourcentage de requêtes 4xx/5xx (float)
        """
        if not entries:
            return {
                "total_requests": 0,
                "unique_ips": 0,
                "top_ips": [],
                "status_codes": {},
                "top_uris": [],
                "top_user_agents": [],
                "methods": {},
                "error_rate": 0.0,
            }

        total_requests: int = len(entries)

        ip_counter: Counter = Counter()
        status_counter: Counter = Counter()
        uri_counter: Counter = Counter()
        ua_counter: Counter = Counter()
        method_counter: Counter = Counter()
        error_count: int = 0

        def _get(entry, key):
            """Accès unifié : dataclass (attribut) ou dict (.get)."""
            if hasattr(entry, key):
                return getattr(entry, key)
            if hasattr(entry, "get"):
                return entry.get(key)
            return None

        for entry in entries:
            ip = _get(entry, "ip")
            if ip:
                ip_counter[ip] += 1

            # LogEntry utilise status_code, les dicts peuvent utiliser status ou status_code
            status = _get(entry, "status_code") or _get(entry, "status")
            if status is not None:
                try:
                    code = int(status)
                    status_counter[code] += 1
                    if 400 <= code <= 599:
                        error_count += 1
                except (ValueError, TypeError):
                    pass

            uri = _get(entry, "uri")
            if uri:
                uri_counter[uri] += 1

            ua = _get(entry, "user_agent")
            if ua:
                ua_counter[ua] += 1

            method = _get(entry, "method")
            if method:
                method_counter[str(method).upper()] += 1

        error_rate: float = (
            round((error_count / total_requests) * 100, 2) if total_requests > 0 else 0.0
        )

        return {
            "total_requests": total_requests,
            "unique_ips": len(ip_counter),
            "top_ips": ip_counter.most_common(10),
            "status_codes": dict(status_counter),
            "top_uris": uri_counter.most_common(10),
            "top_user_agents": ua_counter.most_common(5),
            "methods": dict(method_counter),
            "error_rate": error_rate,
        }
