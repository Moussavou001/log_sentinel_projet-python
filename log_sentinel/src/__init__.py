"""
Log Sentinel - Analyseur de Logs Blue Team
===========================================
Boîte à outils Python pour charger, parser et analyser des fichiers de logs
issus des formats serveur courants (Apache, Nginx, Syslog, etc.).
"""

__version__ = "1.0.0"
__author__ = "NAOMIE NGWIDJOMBY MOUSSAVOU"
__module__ = "Python / Master 1 Cybersécurité"
__license__ = "MIT"

from .loader import LogLoader

__all__ = [
    "LogLoader",
]
