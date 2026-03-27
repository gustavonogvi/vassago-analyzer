#!/bin/bash
cd /opt/vassago
uv run python main.py --db data/naberius.db --alerts data/alerts.db >> /var/log/vassago.log 2>&1
