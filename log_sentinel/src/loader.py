"""
loader.py - Log file loading and format detection module.

Provides the LogLoader class responsible for:
  - Reading log files with automatic encoding fallback (utf-8 -> latin-1)
  - Detecting the log format (apache, nginx, syslog, unknown)
"""

import re
import os
from pathlib import Path


# ---------------------------------------------------------------------------
# Compiled regex patterns used for format detection.
# Tested against the first few lines of a file to identify the log dialect.
# ---------------------------------------------------------------------------

# Apache Combined/Common Log Format:
#   127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
_APACHE_PATTERN = re.compile(
    r'^\S+\s+\S+\s+\S+\s+\[\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4}\]'
    r'\s+"[A-Z]+\s+\S+\s+HTTP/\d\.\d"\s+\d{3}'
)

# Nginx default access log format (very similar to Apache but slightly different):
#   127.0.0.1 - - [28/Mar/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"
_NGINX_PATTERN = re.compile(
    r'^\S+\s+-\s+-\s+\[\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4}\]'
    r'\s+"[A-Z]+\s+\S+\s+HTTP/\d\.\d"\s+\d{3}\s+\d+\s+"[^"]*"\s+"[^"]*"'
)

# Syslog (RFC 3164) format:
#   Mar 28 12:00:00 hostname process[pid]: message
_SYSLOG_PATTERN = re.compile(
    r'^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}'
    r'\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+:'
)


class LogLoader:
    """
    Loads log files from disk and detects their format.

    Supported formats
    -----------------
    - "apache"  : Apache HTTP Server Combined/Common log format
    - "nginx"   : Nginx default access log format
    - "syslog"  : Standard Unix syslog (RFC 3164)
    - "unknown" : Format could not be identified

    Example
    -------
    >>> loader = LogLoader()
    >>> lines = loader.load("/var/log/nginx/access.log")
    >>> fmt = loader.detect_format(lines)
    >>> print(fmt)
    'nginx'
    """

    # Number of lines sampled from the top of the file for format detection.
    _SAMPLE_SIZE: int = 10

    # Encoding candidates tried in order when reading a file.
    _ENCODINGS: list[str] = ["utf-8", "latin-1"]

    # ---------------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------------

    def load(self, filepath: str) -> list[str]:
        """
        Read a log file and return its non-empty lines.

        Parameters
        ----------
        filepath : str
            Absolute or relative path to the log file.

        Returns
        -------
        list[str]
            Lines of the file with leading/trailing whitespace stripped.
            Empty lines are discarded.

        Raises
        ------
        FileNotFoundError
            If the path does not point to an existing file.
        OSError
            If the file cannot be read for any other OS-level reason.
        UnicodeDecodeError
            If the file cannot be decoded with either utf-8 or latin-1
            (extremely rare in practice).
        """
        path = Path(filepath)

        if not path.exists():
            raise FileNotFoundError(
                f"Log file not found: '{filepath}'"
            )

        if not path.is_file():
            raise FileNotFoundError(
                f"Path exists but is not a regular file: '{filepath}'"
            )

        last_error: Exception | None = None

        for encoding in self._ENCODINGS:
            try:
                with open(path, "r", encoding=encoding, errors="strict") as fh:
                    lines = [
                        line.rstrip("\n").rstrip("\r")
                        for line in fh
                        if line.strip()  # drop blank lines
                    ]
                return lines
            except UnicodeDecodeError as exc:
                last_error = exc
                continue

        # Both encodings failed — re-raise the last error with context.
        raise UnicodeDecodeError(
            last_error.encoding,         # type: ignore[union-attr]
            last_error.object,           # type: ignore[union-attr]
            last_error.start,            # type: ignore[union-attr]
            last_error.end,              # type: ignore[union-attr]
            f"Could not decode '{filepath}' with any of {self._ENCODINGS}",
        )

    def detect_format(self, lines: list[str]) -> str:
        """
        Identify the log format by pattern-matching a sample of lines.

        The detection works by scoring each candidate format against the
        first ``_SAMPLE_SIZE`` non-empty lines and returning the format
        whose regex matched the most lines. Ties are resolved by the order
        of precedence: nginx > apache > syslog > unknown.

        Parameters
        ----------
        lines : list[str]
            Log lines as returned by :meth:`load`.

        Returns
        -------
        str
            One of ``"apache"``, ``"nginx"``, ``"syslog"``, or ``"unknown"``.
        """
        if not lines:
            return "unknown"

        sample: list[str] = lines[: self._SAMPLE_SIZE]

        scores: dict[str, int] = {
            "nginx": 0,
            "apache": 0,
            "syslog": 0,
        }

        for line in sample:
            if _NGINX_PATTERN.match(line):
                scores["nginx"] += 1
            elif _APACHE_PATTERN.match(line):
                scores["apache"] += 1
            elif _SYSLOG_PATTERN.match(line):
                scores["syslog"] += 1

        best_format = max(scores, key=lambda fmt: scores[fmt])
        best_score = scores[best_format]

        if best_score == 0:
            return "unknown"

        return best_format

    # ---------------------------------------------------------------------------
    # Private helpers
    # ---------------------------------------------------------------------------

    def _read_raw(self, path: Path, encoding: str) -> list[str]:
        """
        Internal helper: open *path* with the given *encoding* and return
        stripped, non-empty lines.  Raises ``UnicodeDecodeError`` on failure.
        """
        with open(path, "r", encoding=encoding, errors="strict") as fh:
            return [
                line.rstrip("\n").rstrip("\r")
                for line in fh
                if line.strip()
            ]
