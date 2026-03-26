import json
import sqlite3
from pathlib import Path

from .rules import ALL_RULES, Alert

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def run_analysis(naberius_db: str, alerts_db: str) -> list[Alert]:
    conn = sqlite3.connect(naberius_db)
    all_alerts: list[Alert] = []

    for rule in ALL_RULES:
        try:
            alerts = rule.run(conn)
            all_alerts.extend(alerts)
            status = "!" if alerts else " "
            print(f"  [{status}] {rule.name}: {len(alerts)} alert(s)")
        except Exception as e:
            print(f"  [x] {rule.name} failed: {e}")

    conn.close()

    all_alerts.sort(key=lambda a: SEVERITY_ORDER.get(a.severity, 0), reverse=True)

    Path(alerts_db).parent.mkdir(parents=True, exist_ok=True)
    _save_alerts(alerts_db, all_alerts)

    return all_alerts


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

    # fresh run: replace previous results
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
