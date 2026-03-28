import unittest
import sys, os, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.statistics import LogStatistics
from src.loader import LogLoader
from src.parser import LogEntry


class TestLogStatistics(unittest.TestCase):

    def _make_entry(self, ip="127.0.0.1", method="GET", uri="/", status_code="200", size="512"):
        """Helper pour créer une LogEntry de test."""
        return LogEntry(
            ip=ip,
            timestamp="28/Mar/2026:12:00:00 +0000",
            method=method,
            uri=uri,
            status_code=status_code,
            size=size
        )

    # 1. test_empty_entries
    def test_empty_entries(self):
        stats = LogStatistics().compute([])
        self.assertEqual(stats["total_requests"], 0)
        self.assertEqual(stats["unique_ips"], 0)

    # 2. test_total_requests
    def test_total_requests(self):
        entries = [
            self._make_entry(),
            self._make_entry(),
            self._make_entry(),
        ]
        stats = LogStatistics().compute(entries)
        self.assertEqual(stats["total_requests"], 3)

    # 3. test_unique_ips
    def test_unique_ips(self):
        entries = [
            self._make_entry(ip="192.168.1.1"),
            self._make_entry(ip="192.168.1.1"),
            self._make_entry(ip="10.0.0.1"),
        ]
        stats = LogStatistics().compute(entries)
        self.assertEqual(stats["unique_ips"], 2)

    # 4. test_top_ips
    def test_top_ips(self):
        entries = [
            self._make_entry(ip="192.168.1.1"),
            self._make_entry(ip="192.168.1.1"),
            self._make_entry(ip="192.168.1.1"),
            self._make_entry(ip="10.0.0.1"),
            self._make_entry(ip="10.0.0.1"),
            self._make_entry(ip="172.16.0.1"),
        ]
        stats = LogStatistics().compute(entries)
        top_ips = stats["top_ips"]
        self.assertTrue(len(top_ips) > 0)
        # L'IP la plus fréquente doit être en première position
        self.assertEqual(top_ips[0][0], "192.168.1.1")

    # 5. test_error_rate
    def test_error_rate(self):
        entries = [
            self._make_entry(status_code="200"),
            self._make_entry(status_code="404"),
        ]
        stats = LogStatistics().compute(entries)
        self.assertEqual(stats["error_rate"], 50.0)

    # 6. test_status_codes_counted
    def test_status_codes_counted(self):
        entries = [
            self._make_entry(status_code="200"),
            self._make_entry(status_code="200"),
            self._make_entry(status_code="404"),
            self._make_entry(status_code="500"),
        ]
        stats = LogStatistics().compute(entries)
        status_codes = stats["status_codes"]
        self.assertEqual(status_codes.get(200), 2)
        self.assertEqual(status_codes.get(404), 1)
        self.assertEqual(status_codes.get(500), 1)

    # 7. test_methods_counted
    def test_methods_counted(self):
        entries = [
            self._make_entry(method="GET"),
            self._make_entry(method="GET"),
            self._make_entry(method="POST"),
        ]
        stats = LogStatistics().compute(entries)
        methods = stats["methods"]
        self.assertEqual(methods.get("GET"), 2)
        self.assertEqual(methods.get("POST"), 1)


class TestLogLoader(unittest.TestCase):

    # 8. test_file_not_found
    def test_file_not_found(self):
        loader = LogLoader()
        with self.assertRaises(FileNotFoundError):
            loader.load("/chemin/inexistant/fichier.log")

    # 9. test_load_valid_file
    def test_load_valid_file(self):
        lignes = [
            '127.0.0.1 - - [28/Mar/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 512\n',
            '127.0.0.1 - - [28/Mar/2026:12:00:01 +0000] "POST /api HTTP/1.1" 201 256\n',
            '10.0.0.1 - - [28/Mar/2026:12:00:02 +0000] "GET /page HTTP/1.1" 404 128\n',
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.writelines(lignes)
            tmp_path = f.name
        try:
            loader = LogLoader()
            result = loader.load(tmp_path)
            self.assertEqual(len(result), 3)
        finally:
            os.unlink(tmp_path)

    # 10. test_empty_lines_ignored
    def test_empty_lines_ignored(self):
        contenu = (
            '127.0.0.1 - - [28/Mar/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 512\n'
            "\n"
            "\n"
            '10.0.0.1 - - [28/Mar/2026:12:00:01 +0000] "GET /home HTTP/1.1" 200 300\n'
            "\n"
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write(contenu)
            tmp_path = f.name
        try:
            loader = LogLoader()
            result = loader.load(tmp_path)
            non_empty = [line for line in result if line.strip()]
            self.assertEqual(len(non_empty), 2)
        finally:
            os.unlink(tmp_path)

    # 11. test_detect_apache_format
    def test_detect_apache_format(self):
        lignes_apache = [
            '127.0.0.1 - - [28/Mar/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 512',
            '192.168.1.1 - frank [28/Mar/2026:12:00:01 +0000] "POST /login HTTP/1.1" 302 0',
        ]
        loader = LogLoader.__new__(LogLoader)
        detected = loader.detect_format(lignes_apache)
        self.assertEqual(detected, "apache")

    # 12. test_detect_unknown_format
    def test_detect_unknown_format(self):
        lignes_inconnues = [
            "ceci n'est pas un log",
            "ligne aléatoire sans format reconnu",
            "12345 foo bar baz",
        ]
        loader = LogLoader.__new__(LogLoader)
        detected = loader.detect_format(lignes_inconnues)
        self.assertEqual(detected, "unknown")


if __name__ == "__main__":
    unittest.main()
