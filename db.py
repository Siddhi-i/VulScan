import sqlite3
from pathlib import Path
import datetime

DB_PATH = Path("scanner.db")


def init_db() -> None:
    """Create tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_url TEXT NOT NULL,
        status TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        vuln_type TEXT NOT NULL,
        url TEXT,
        parameter TEXT,
        payload TEXT,
        severity TEXT,
        evidence TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    )
    """)

    conn.commit()
    conn.close()


def create_scan(target_url: str) -> int:
    """Insert a new scan row and return its ID."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    started = datetime.datetime.now().isoformat()

    cur.execute(
        "INSERT INTO scans (target_url, status, started_at) VALUES (?, ?, ?)",
        (target_url, "running", started),
    )
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


def finish_scan(scan_id: int, status: str = "completed") -> None:
    """Mark a scan as finished with given status."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    finished = datetime.datetime.now().isoformat()

    cur.execute(
        "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?",
        (status, finished, scan_id),
    )
    conn.commit()
    conn.close()


def get_scans():
    """Return all scans as list of dicts."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, target_url, status, started_at, finished_at FROM scans")
    rows = cur.fetchall()
    conn.close()

    keys = ["id", "target_url", "status", "started_at", "finished_at"]
    return [dict(zip(keys, r)) for r in rows]


def add_finding(
    scan_id: int,
    vuln_type: str,
    url: str,
    parameter: str,
    payload: str,
    severity: str,
    evidence: str,
) -> None:
    """Insert a finding row for a scan."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO findings (scan_id, vuln_type, url, parameter, payload, severity, evidence)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (scan_id, vuln_type, url, parameter, payload, severity, evidence),
    )

    conn.commit()
    conn.close()


def get_scan_with_findings(scan_id: int):
    """Return (scan_dict, [finding_dicts]) for a given scan_id."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        "SELECT id, target_url, status, started_at, finished_at FROM scans WHERE id = ?",
        (scan_id,),
    )
    scan_row = cur.fetchone()

    if not scan_row:
        conn.close()
        return None, None

    scan_keys = ["id", "target_url", "status", "started_at", "finished_at"]
    scan = dict(zip(scan_keys, scan_row))

    cur.execute(
        """
        SELECT id, scan_id, vuln_type, url, parameter, payload, severity, evidence
        FROM findings WHERE scan_id = ?
        """,
        (scan_id,),
    )
    finding_rows = cur.fetchall()
    conn.close()

    finding_keys = [
        "id",
        "scan_id",
        "vuln_type",
        "url",
        "parameter",
        "payload",
        "severity",
        "evidence",
    ]
    findings = [dict(zip(finding_keys, r)) for r in finding_rows]

    return scan, findings
