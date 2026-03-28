"""
osint.py - Module OSINT pour Log Sentinel.

Interroge l'API publique ip-api.com afin d'enrichir les IPs suspectes
avec des informations de géolocalisation et de réputation.
"""

import requests


_IP_API_BASE_URL = "http://ip-api.com/json/{ip}"
_REQUEST_TIMEOUT = 3  # secondes


class OSINTChecker:
    """Vérifie des adresses IP via l'API publique ip-api.com (sans clé requise)."""

    def check_ip(self, ip: str) -> dict:
        """
        Interroge ip-api.com pour une adresse IP donnée.

        Args:
            ip: Adresse IPv4 ou IPv6 à vérifier.

        Returns:
            Dictionnaire contenant :
            - country   : pays de l'IP (str)
            - city      : ville associée (str)
            - isp       : fournisseur d'accès (str)
            - is_proxy  : indique si l'IP est un proxy/VPN/Tor (bool)
            Retourne un dict vide en cas d'erreur réseau ou de réponse invalide.
        """
        url = _IP_API_BASE_URL.format(ip=ip)
        try:
            response = requests.get(url, timeout=_REQUEST_TIMEOUT)
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.ConnectionError:
            return {}
        except requests.exceptions.Timeout:
            return {}
        except requests.exceptions.HTTPError:
            return {}
        except requests.exceptions.RequestException:
            return {}
        except ValueError:
            # Réponse non-JSON
            return {}

        if data.get("status") != "success":
            return {}

        return {
            "country": data.get("country", ""),
            "city": data.get("city", ""),
            "isp": data.get("isp", ""),
            "is_proxy": bool(data.get("proxy", False)),
        }

    def check_ips(self, ips: list[str], max_ips: int = 5) -> dict[str, dict]:
        """
        Vérifie les N premières IPs de la liste fournie.

        Args:
            ips     : Liste d'adresses IP à vérifier.
            max_ips : Nombre maximum d'IPs à interroger (défaut : 5).

        Returns:
            Dictionnaire {ip: résultat} où chaque résultat est celui
            retourné par check_ip(). Les IPs en erreur sont représentées
            par un dict vide.
        """
        results: dict[str, dict] = {}
        for ip in ips[:max_ips]:
            results[ip] = self.check_ip(ip)
        return results
