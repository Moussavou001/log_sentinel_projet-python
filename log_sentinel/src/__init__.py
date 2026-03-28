"""
Log Sentinel - Blue Team Log Analyzer
======================================
A Python toolkit for loading, parsing, and analyzing log files
from common server formats (Apache, Nginx, Syslog, etc.).
"""

__version__ = "0.1.0"
__author__ = "Naomie"
__license__ = "MIT"

from .loader import LogLoader

__all__ = [
    "LogLoader",
]
