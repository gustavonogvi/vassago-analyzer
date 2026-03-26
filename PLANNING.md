# Planning

## Overview
Vassago is a command-line SSH log analyzer focused on detection engineering. It ingests structured event data, runs detection rules against it, and surfaces attacker behavior as severity-ranked alerts mapped to MITRE ATT&CK techniques.

The long-term goal is to evolve into a full detection pipeline — with pluggable rules, live data ingestion, and structured alert output suitable for SOC workflows.

---

## EPIC 01 — Detection Engine [done]

> Run detection rules against SSH event data and produce structured alerts.

**HU-01** [done] — As an analyst, I want the engine to run all detection rules automatically so that I don't have to trigger each one manually.

**HU-02** [done] — As an analyst, I want alerts to be ranked by severity so that I can triage the most critical findings first.

**HU-03** [done] — As an analyst, I want every alert to include a MITRE ATT&CK technique so that findings are contextualized within a known framework.

**HU-04** [done] — As an analyst, I want alerts to be persisted in SQLite so that results are available after the run.

---

## EPIC 02 — Detection Rules [done]

> Implement rules that cover common SSH attack patterns.

**HU-05** [done] — As an analyst, I want brute force attempts to be detected by IP so that high-volume attackers are flagged.

**HU-06** [done] — As an analyst, I want credential stuffing to be detected by unique username/password pairs per IP so that attackers using lists are identified.

**HU-07** [done] — As an analyst, I want password spraying to be detected by username targeted across multiple IPs so that distributed attacks are surfaced.

**HU-08** [done] — As an analyst, I want known attack tool HASSH fingerprints to be flagged so that tooling can be identified even when banners are spoofed.

**HU-09** [done] — As an analyst, I want off-hours activity to be flagged so that anomalous access patterns are visible.

---

## EPIC 03 — Reporting [done]

> Export alert results in formats suitable for documentation and sharing.

**HU-10** [done] — As an analyst, I want to export alerts as JSON so that results can be consumed by other tools or scripts.

**HU-11** [done] — As an analyst, I want to export alerts as a self-contained HTML report so that findings can be shared without any dependencies.

---

## EPIC 04 — Live Ingestion [todo]

> Allow Vassago to consume live data instead of only static databases.

**HU-12** [todo] — As an analyst, I want Vassago to optionally consume events from a REST API so that it can run against a live honeypot without direct database access.

**HU-13** [todo] — As an analyst, I want to configure the API URL via CLI flag so that Vassago works with any compatible event source.
