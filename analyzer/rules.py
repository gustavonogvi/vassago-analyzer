import sqlite3
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Alert:
    rule: str
    severity: str          
    description: str
    ip: str | None
    mitre_technique: str
    mitre_name: str
    evidence: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class BruteForceRule:
    name            = "Brute Force Detected"
    mitre_technique = "T1110.001"
    mitre_name      = "Brute Force: Password Guessing"
    severity        = "HIGH"
    THRESHOLD       = 5

    def run(self, conn: sqlite3.Connection) -> list[Alert]:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip, COUNT(*) as attempts,
                   MAX(timestamp) as last_seen,
                   MAX(country)   as country
            FROM events
            GROUP BY ip
            HAVING attempts >= ?
            ORDER BY attempts DESC
        """, (self.THRESHOLD,))

        alerts = []
        for ip, attempts, last_seen, country in cursor.fetchall():
            alerts.append(Alert(
                rule=self.name,
                severity=self.severity,
                description=(
                    f"{ip} made {attempts} connection attempts "
                    f"(country: {country or 'unknown'})"
                ),
                ip=ip,
                mitre_technique=self.mitre_technique,
                mitre_name=self.mitre_name,
                evidence={
                    "attempts": attempts,
                    "last_seen": last_seen,
                    "country": country,
                },
                timestamp=last_seen or datetime.now().isoformat(),
            ))
        return alerts


class CredentialStuffingRule:
    name                  = "Credential Stuffing Detected"
    mitre_technique       = "T1110.004"
    mitre_name            = "Brute Force: Credential Stuffing"
    severity              = "HIGH"
    UNIQUE_PAIRS_THRESHOLD = 3

    def run(self, conn: sqlite3.Connection) -> list[Alert]:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip,
                   COUNT(DISTINCT username || ':' || password) as unique_pairs,
                   MAX(timestamp) as last_seen,
                   MAX(country)   as country
            FROM events
            WHERE username IS NOT NULL AND password IS NOT NULL
            GROUP BY ip
            HAVING unique_pairs >= ?
            ORDER BY unique_pairs DESC
        """, (self.UNIQUE_PAIRS_THRESHOLD,))

        alerts = []
        for ip, unique_pairs, last_seen, country in cursor.fetchall():
            alerts.append(Alert(
                rule=self.name,
                severity=self.severity,
                description=(
                    f"{ip} tried {unique_pairs} unique credential pairs "
                    f"(country: {country or 'unknown'})"
                ),
                ip=ip,
                mitre_technique=self.mitre_technique,
                mitre_name=self.mitre_name,
                evidence={
                    "unique_pairs": unique_pairs,
                    "country": country,
                    "last_seen": last_seen,
                },
                timestamp=last_seen or datetime.now().isoformat(),
            ))
        return alerts


class PasswordSprayRule:
    name            = "Password Spray Detected"
    mitre_technique = "T1110.003"
    mitre_name      = "Brute Force: Password Spraying"
    severity        = "MEDIUM"
    MIN_SOURCES     = 3

    def run(self, conn: sqlite3.Connection) -> list[Alert]:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT username,
                   COUNT(DISTINCT ip) as source_count,
                   COUNT(*)           as total_attempts
            FROM events
            WHERE username IS NOT NULL
            GROUP BY username
            HAVING source_count >= ?
            ORDER BY source_count DESC
        """, (self.MIN_SOURCES,))

        alerts = []
        for username, source_count, total_attempts in cursor.fetchall():
            alerts.append(Alert(
                rule=self.name,
                severity=self.severity,
                description=(
                    f"Username '{username}' targeted from {source_count} different IPs "
                    f"({total_attempts} total attempts)"
                ),
                ip=None,
                mitre_technique=self.mitre_technique,
                mitre_name=self.mitre_name,
                evidence={
                    "username": username,
                    "source_count": source_count,
                    "total_attempts": total_attempts,
                },
            ))
        return alerts


class KnownToolHASSHRule:
    name            = "Known Attack Tool Fingerprint"
    mitre_technique = "T1059"
    mitre_name      = "Command and Scripting Interpreter"
    severity        = "MEDIUM"

    # Known HASSH fingerprints for attack tools
    KNOWN_HASHES: dict[str, str] = {
        "92674389fa1e47a27ddd8d9b63ecd42b": "Paramiko (Python SSH library)",
        "b12b093e97afdd43f7941f6f1f5f2d3f": "Metasploit SSH scanner",
        "3f0099d323fed54bb09b3f30f271b138": "Hydra SSH brute-forcer",
        "c6a7f9f87c9dbb9fc2ed0a7b4e4cbf2a": "Medusa SSH scanner",
    }

    def run(self, conn: sqlite3.Connection) -> list[Alert]:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT hassh, ip,
                   MAX(timestamp) as last_seen,
                   COUNT(*)       as hits,
                   MAX(country)   as country
            FROM events
            WHERE hassh IS NOT NULL
            GROUP BY hassh, ip
        """)

        alerts = []
        for hassh, ip, last_seen, hits, country in cursor.fetchall():
            if hassh in self.KNOWN_HASHES:
                tool = self.KNOWN_HASHES[hassh]
                alerts.append(Alert(
                    rule=self.name,
                    severity=self.severity,
                    description=f"{ip} is using {tool} (HASSH: {hassh[:12]}…)",
                    ip=ip,
                    mitre_technique=self.mitre_technique,
                    mitre_name=self.mitre_name,
                    evidence={
                        "hassh": hassh,
                        "tool": tool,
                        "hits": hits,
                        "country": country,
                    },
                    timestamp=last_seen or datetime.now().isoformat(),
                ))
        return alerts


class OffHoursActivityRule:
    name            = "Off-Hours Activity"
    mitre_technique = "T1078"
    mitre_name      = "Valid Accounts"
    severity        = "LOW"
    START_HOUR      = 0   # midnight UTC
    END_HOUR        = 5   # 5 AM UTC

    def run(self, conn: sqlite3.Connection) -> list[Alert]:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip, COUNT(*) as attempts,
                   MAX(timestamp) as last_seen,
                   MAX(country)   as country
            FROM events
            WHERE CAST(strftime('%H', timestamp) AS INTEGER) BETWEEN ? AND ?
            GROUP BY ip
            HAVING attempts >= 2
            ORDER BY attempts DESC
        """, (self.START_HOUR, self.END_HOUR))

        alerts = []
        for ip, attempts, last_seen, country in cursor.fetchall():
            alerts.append(Alert(
                rule=self.name,
                severity=self.severity,
                description=(
                    f"{ip} made {attempts} attempts between "
                    f"{self.START_HOUR:02d}:00–{self.END_HOUR:02d}:00 UTC "
                    f"(country: {country or 'unknown'})"
                ),
                ip=ip,
                mitre_technique=self.mitre_technique,
                mitre_name=self.mitre_name,
                evidence={
                    "attempts": attempts,
                    "window": f"{self.START_HOUR:02d}:00-{self.END_HOUR:02d}:00 UTC",
                    "country": country,
                },
                timestamp=last_seen or datetime.now().isoformat(),
            ))
        return alerts


ALL_RULES = [
    BruteForceRule(),
    CredentialStuffingRule(),
    PasswordSprayRule(),
    KnownToolHASSHRule(),
    OffHoursActivityRule(),
]
