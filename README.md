# vassago

Vassago is a command-line SSH log analyzer built for Blue Team workflows. It reads structured event data from a SQLite database, runs detection rules against it, and surfaces attacker behavior as severity-ranked alerts mapped to MITRE ATT&CK techniques. Findings can be exported as JSON or HTML reports.

Built as a portfolio project while studying Blue Team / SOC fundamentals.

## what it does

Vassago ingests SSH honeypot data and runs a set of detection rules over it. Each rule targets a specific attack pattern — brute force, credential stuffing, password spraying, known tool fingerprints, off-hours activity. Every match produces an alert with severity, description, MITRE ATT&CK mapping, and supporting evidence. Results are saved to a local SQLite database and optionally exported to a report.

## how it works

```
SQLite database (honeypot events)
        ↓
engine loads all detection rules
        ↓
each rule queries the database for its pattern
        ↓
matches produce Alert objects (severity, description, MITRE, evidence)
        ↓
alerts sorted by severity (CRITICAL → HIGH → MEDIUM → LOW)
        ↓
results saved to alerts.db
        ↓
optional export: JSON or HTML report
```

## detection rules

| Rule | Technique | Severity |
|---|---|---|
| Brute Force Detected | [T1110.001 — Password Guessing](https://attack.mitre.org/techniques/T1110/001) | HIGH |
| Credential Stuffing Detected | [T1110.004 — Credential Stuffing](https://attack.mitre.org/techniques/T1110/004) | HIGH |
| Password Spray Detected | [T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003) | MEDIUM |
| Known Attack Tool Fingerprint | [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) | MEDIUM |
| Off-Hours Activity | [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078) | LOW |

Techniques sourced from the [MITRE ATT&CK framework](https://attack.mitre.org).

## stack

- Python — core analyzer, detection engine, report generation
- SQLite — reads event data, writes alert results
- MITRE ATT&CK — technique mapping for every alert
- HTML/CSS — self-contained report output, no framework

## requirements

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) (package manager)

## setup

```bash
# clone the repo
git clone https://github.com/gustavonogvi/Vassago-Analyzer.git
cd vassago-analyzer

# create virtual environment
uv sync
```

## running

```bash
# basic run — reads from data/naberius.db, writes to data/alerts.db
uv run python main.py

# custom database path
uv run python main.py --db /path/to/naberius.db

# export JSON report
uv run python main.py --report json --output reports/report

# export HTML report
uv run python main.py --report html --output reports/report
```

## cli flags

| Flag | Default | Description |
|---|---|---|
| `--db` | `data/naberius.db` | Path to the SQLite event database |
| `--alerts` | `data/alerts.db` | Path to write alert results |
| `--report` | — | Export format: `json` or `html` |
| `--output` | `reports/report` | Output path without extension |

## project structure

```
vassago-analyzer/
├── analyzer/
│   ├── engine.py       # loads rules, runs analysis, saves alerts
│   └── rules.py        # detection rules + Alert dataclass
├── data/
│   └── naberius.db     # input database, gitignored
├── reports/            # exported reports, gitignored
├── main.py             # CLI entrypoint
├── pyproject.toml
└── README.md
```

## adding a new rule

Each rule is a class with metadata fields and a `run` method. To add one:

```python
class MyRule:
    name            = "Rule Name"
    mitre_technique = "T1234"
    mitre_name      = "Technique Name"
    severity        = "HIGH"

    def run(self, conn: sqlite3.Connection) -> list[Alert]:
        # query the database, return a list of Alert objects
        ...
```

Then register it in `ALL_RULES` at the bottom of `rules.py`. The engine picks it up automatically.

## what i learned

- How to structure a detection engine around pluggable rules
- How MITRE ATT&CK techniques map to real observed behavior in logs
- How brute force, credential stuffing, and password spraying differ operationally
- How HASSH fingerprinting identifies attack tools by their SSH algorithm negotiation
- How to produce structured alert output useful for triage and reporting
- The basic workflow of a SOC analyst: ingest → detect → triage → report
