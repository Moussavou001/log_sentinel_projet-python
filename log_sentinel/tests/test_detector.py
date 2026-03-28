"""
test_detector.py - Tests unitaires pour Log Sentinel.

Teste AttackDetector (src/detector.py) et LogParser (src/parser.py).
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detector import AttackDetector, Alert
from src.parser import LogParser, LogEntry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Ligne Apache Combined Log valide utilisée comme référence dans les tests
_APACHE_LINE = (
    '192.168.1.1 - - [28/Mar/2026:10:00:00 +0000] '
    '"GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
)

# Deuxième ligne valide (IP et URI différentes)
_APACHE_LINE_2 = (
    '10.0.0.5 - - [28/Mar/2026:10:01:00 +0000] '
    '"POST /login HTTP/1.1" 200 512 "-" "curl/7.68.0"'
)

# Ligne non conforme au format Apache
_INVALID_LINE = "Ceci n'est pas une ligne de log valide."


def _make_entry(ip="127.0.0.1", uri="/index.html",
                user_agent="Mozilla/5.0", status="200") -> dict:
    """Construit un dictionnaire d'entrée de log minimal pour AttackDetector."""
    return {"ip": ip, "uri": uri, "user_agent": user_agent, "status": status}


# ---------------------------------------------------------------------------
# Tests AttackDetector
# ---------------------------------------------------------------------------

class TestAttackDetector(unittest.TestCase):
    """Tests unitaires pour la classe AttackDetector."""

    def setUp(self):
        self.detector = AttackDetector()

    # ------------------------------------------------------------------
    # Détections par signature
    # ------------------------------------------------------------------

    def test_sql_injection_detected(self):
        """Une URI contenant UNION SELECT doit lever une alerte sql_injection."""
        entry = _make_entry(uri="/search?q=UNION SELECT * FROM users")
        alerts = self.detector.detect_signature(entry)
        attack_types = [a.attack_type for a in alerts]
        self.assertIn("sql_injection", attack_types)

    def test_xss_detected(self):
        """Une URI contenant une balise <script> doit lever une alerte xss."""
        entry = _make_entry(uri="/page?name=<script>alert(1)</script>")
        alerts = self.detector.detect_signature(entry)
        attack_types = [a.attack_type for a in alerts]
        self.assertIn("xss", attack_types)

    def test_path_traversal_detected(self):
        """Une URI de traversée de répertoire doit lever une alerte path_traversal."""
        entry = _make_entry(uri="/../../../etc/passwd")
        alerts = self.detector.detect_signature(entry)
        attack_types = [a.attack_type for a in alerts]
        self.assertIn("path_traversal", attack_types)

    def test_sensitive_file_detected(self):
        """Une URI ciblant un fichier sensible doit lever une alerte sensitive_files."""
        entry = _make_entry(uri="/.env")
        alerts = self.detector.detect_signature(entry)
        attack_types = [a.attack_type for a in alerts]
        self.assertIn("sensitive_files", attack_types)

    def test_malicious_ua_detected(self):
        """Un User-Agent correspondant à sqlmap doit lever une alerte malicious_ua."""
        entry = _make_entry(user_agent="sqlmap/1.7.2")
        alerts = self.detector.detect_signature(entry)
        attack_types = [a.attack_type for a in alerts]
        self.assertIn("malicious_ua", attack_types)

    def test_command_injection_detected(self):
        """Une URI avec injection de commande doit lever une alerte command_injection."""
        entry = _make_entry(uri="/cmd?exec=;ls -la")
        alerts = self.detector.detect_signature(entry)
        attack_types = [a.attack_type for a in alerts]
        self.assertIn("command_injection", attack_types)

    def test_clean_request_no_alert(self):
        """Une requête saine ne doit produire aucune alerte."""
        entry = _make_entry(uri="/index.html", user_agent="Mozilla/5.0")
        alerts = self.detector.detect_signature(entry)
        self.assertEqual(len(alerts), 0)

    # ------------------------------------------------------------------
    # Détection force brute
    # ------------------------------------------------------------------

    def test_brute_force_detected(self):
        """6 réponses 401 depuis la même IP doivent lever une alerte brute_force.

        Le seuil est strictement supérieur à 5 (threshold=5, condition count > 5),
        donc 6 entrées déclenchent l'alerte.
        """
        entries = [
            _make_entry(ip="10.0.0.1", uri="/login", status="401")
            for _ in range(6)
        ]
        alerts = self.detector.detect_brute_force(entries)
        attack_types = [a.attack_type for a in alerts]
        self.assertIn("brute_force", attack_types)

    def test_brute_force_below_threshold(self):
        """3 réponses 401 ne doivent pas déclencher d'alerte brute_force."""
        entries = [
            _make_entry(ip="10.0.0.1", uri="/login", status="401")
            for _ in range(3)
        ]
        alerts = self.detector.detect_brute_force(entries)
        attack_types = [a.attack_type for a in alerts]
        self.assertNotIn("brute_force", attack_types)

    # ------------------------------------------------------------------
    # Détection de scan
    # ------------------------------------------------------------------

    def test_scan_detected(self):
        """15 URIs distinctes avec 404 depuis la même IP doivent lever une alerte scan.

        Critères : URIs distinctes > 10 ET proportion de 404 > 50 %.
        """
        scan_uris = [
            "/admin", "/wp-login", "/phpmyadmin", "/backup", "/.git",
            "/config", "/setup", "/install", "/shell", "/console",
            "/manager", "/api/v1/users", "/etc/passwd", "/wp-admin", "/robots.txt",
        ]
        entries = [
            _make_entry(ip="10.0.0.2", uri=uri, status="404")
            for uri in scan_uris
        ]
        alerts = self.detector.detect_scan(entries)
        attack_types = [a.attack_type for a in alerts]
        self.assertIn("scan", attack_types)


# ---------------------------------------------------------------------------
# Tests LogParser
# ---------------------------------------------------------------------------

class TestLogParser(unittest.TestCase):
    """Tests unitaires pour la classe LogParser."""

    def setUp(self):
        self.parser = LogParser()

    def test_parse_apache_line(self):
        """parse_line doit extraire correctement ip, method, uri et status_code."""
        entry = self.parser.parse_line(_APACHE_LINE, "apache")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.ip, "192.168.1.1")
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.uri, "/index.html")
        self.assertEqual(entry.status_code, "200")

    def test_parse_invalid_line(self):
        """parse_line doit retourner None pour une ligne non conforme."""
        entry = self.parser.parse_line(_INVALID_LINE, "apache")
        self.assertIsNone(entry)

    def test_parse_all_filters_none(self):
        """parse_all doit retourner uniquement les entrées valides (len=2 sur 3 lignes)."""
        lines = [_APACHE_LINE, _APACHE_LINE_2, _INVALID_LINE]
        entries = self.parser.parse_all(lines, "apache")
        self.assertEqual(len(entries), 2)


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main()
