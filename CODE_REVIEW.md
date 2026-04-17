# Vassago — Code Review

Reviewed: 2026-04-16

---

## Critical

**~~`engine.py:11-22` — DB connection not closed on exception~~** ✓ fixed
If a rule raises an exception, `conn.close()` on line 23 is never reached. Resource leak on every rule failure.
```python
# fix: wrap in try/finally
conn = sqlite3.connect(naberius_db)
try:
    ...
finally:
    conn.close()
```

**~~`main.py:51` — silent failure on missing database~~** ✓ fixed
When `--db` path doesn't exist, the program does `return` instead of `sys.exit(1)`. The cron job sees exit code 0 and logs nothing wrong.
```python
# fix
sys.exit(1)  # instead of return
```

**~~`main.py:111` — HTML report not escaped~~** ✓ fixed
`a.description` is interpolated directly into HTML. Any `<` or `>` from captured data (usernames, passwords) breaks the report layout.
```python
# fix: use html.escape()
import html
td_description = html.escape(a.description)
```

---

## High

**~~`main.py:13-14` — LOW and MEDIUM same color~~** ✓ fixed
Both map to `\033[33m` (yellow). Indistinguishable in terminal output.
```python
# fix
"LOW":    "\033[33m",   # yellow
"MEDIUM": "\033[38;5;208m",  # orange
```

**`rules.py:196-197` — OffHoursActivity assumes UTC** ⚠ known limitation
`START_HOUR=0, END_HOUR=5` is hardcoded as UTC. Naberius stores timestamps via `datetime.now().isoformat()` (local time, no timezone). If the server runs outside UTC, detection window is wrong. Fix requires aligning Naberius to store UTC timestamps — deferred.

**~~`run.sh:3` — cron can't detect Vassago failures~~** ✓ fixed
`uv run python main.py ... >> /var/log/vassago.log 2>&1` always exits 0. If the analyzer crashes, cron has no way to know.
```bash
# fix: propagate exit code
uv run python main.py ... >> /var/log/vassago.log 2>&1 || echo "[ERROR] vassago failed" >> /var/log/vassago.log
```

---

## Medium

**~~`engine.py:20` — bare Exception catch~~** ✓ fixed
`except Exception` swallows `KeyboardInterrupt`, `SystemExit`, and database corruption equally. Hard to debug failures.
Fix: catch specific exceptions (`sqlite3.Error`, `ValueError`) or at least re-raise fatal ones.

**`rules.py:150-155` — HASSH fingerprints hardcoded** ⚠ deferred
Adding a new attack tool requires a code change. Should be loadable from a config file or external list. Deferred — acceptable for current scope of the project.

---

## Low

**~~`main.py:114` — timestamp sliced without validation~~** ✓ fixed
`a.timestamp[:19]` assumes ISO format with at least 19 chars. Won't fail in practice (timestamps come from `datetime.now().isoformat()`), but fragile.

**~~`rules.py:70` — composite credential key is ambiguous~~** ✓ fixed
`username || ':' || password` replaced with `username || char(0) || password` — null byte separator eliminates ambiguity.

**`run.sh` — no log rotation** ⚠ deferred
Appends to `/var/log/vassago.log` indefinitely. Requires `logrotate` config on the Debian VM — out of scope for the code itself.

---

## Not a bug (noted for clarity)

**`pyproject.toml:7` — empty dependencies**
Correct. All imports (`sqlite3`, `json`, `pathlib`, `argparse`, `datetime`) are Python stdlib. No external deps needed.
