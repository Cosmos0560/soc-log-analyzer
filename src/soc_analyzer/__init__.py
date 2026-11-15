"""SOC Log Analyzer — a lightweight log parsing and threat-detection engine.

Reads common security-relevant log formats (Linux auth.log, Apache/Nginx
access logs), normalizes them into structured events, runs a rule-based
detection engine over them, and reports the results as human-readable
alerts, JSON, or a SQLite database for further querying.
"""

__version__ = "0.1.0"
