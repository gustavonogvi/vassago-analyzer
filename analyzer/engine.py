import json
import sqlite3
from pathlib import Path

import requests

from .rules import ALL_RULES, Alert

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

_EVENTS_SCHEMA = """
    CREATE TABLE events (
        id               INTEGER PRIMARY KEY,
        ip               TEXT NOT NULL,
        port             INTEGER NOT NULL,
        timestamp        TEXT NOT NULL,
        payload          TEXT,
        country          TEXT,
        city             TEXT,
        region           TEXT,
        asn              TEXT,
        username         TEXT,
        password         TEXT,
        client_version   TEXT,
        hassh            TEXT,
        hassh_algorithms TEXT
    )
"""


def _fetch_events_into_memory(api_url: str) -> sqlite3.Connection:
    response = requests.get(f"{api_url.rstrip('/')}/events", timeout=10)
    response.raise_for_status()
    events = response.json()

    conn = sqlite3.connect(":memory:")
    conn.execute(_EVENTS_SCHEMA)
    conn.executemany(
        """INSERT INTO events
           (id, ip, port, timestamp, payload, country, city, region, asn,
            username, password, client_version, hassh, hassh_algorithms)
           VALUES (:id, :ip, :port, :timestamp, :payload, :country, :city,
                   :region, :asn, :username, :password, :client_version,
                   :hassh, :hassh_algorithms)""",
        events,
    )
    conn.commit()
    return conn


def _run_rules(conn: sqlite3.Connection, alerts_db: str) -> list[Alert]:
    all_alerts: list[Alert] = []

    try:
        for rule in ALL_RULES:
            try:
                alerts = rule.run(conn)
                all_alerts.extend(alerts)
                status = "!" if alerts else " "
                print(f"  [{status}] {rule.name}: {len(alerts)} alert(s)")
            except (sqlite3.Error, ValueError, KeyError) as e:
                print(f"  [x] {rule.name} failed: {e}")
    finally:
        conn.close()

    all_alerts.sort(key=lambda a: SEVERITY_ORDER.get(a.severity, 0), reverse=True)

    Path(alerts_db).parent.mkdir(parents=True, exist_ok=True)
    _save_alerts(alerts_db, all_alerts)

    return all_alerts


def run_analysis_from_api(api_url: str, alerts_db: str) -> list[Alert]:
    conn = _fetch_events_into_memory(api_url)
    return _run_rules(conn, alerts_db)


def run_analysis(naberius_db: str, alerts_db: str) -> list[Alert]:
    conn = sqlite3.connect(naberius_db)
    return _run_rules(conn, alerts_db)


def _save_alerts(alerts_db: str, alerts: list[Alert]) -> None:
    conn = sqlite3.connect(alerts_db)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            rule            TEXT NOT NULL,
            severity        TEXT NOT NULL,
            description     TEXT NOT NULL,
            ip              TEXT,
            mitre_technique TEXT,
            mitre_name      TEXT,
            evidence        TEXT,
            timestamp       TEXT
        )
    """)

    cursor.execute("DELETE FROM alerts")

    for a in alerts:
        cursor.execute("""
            INSERT INTO alerts
                (rule, severity, description, ip, mitre_technique, mitre_name, evidence, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            a.rule, a.severity, a.description, a.ip,
            a.mitre_technique, a.mitre_name,
            json.dumps(a.evidence), a.timestamp,
        ))

    conn.commit()
    conn.close()
