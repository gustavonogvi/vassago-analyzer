#!/bin/bash
cd /opt/vassago
UV_CACHE_DIR=/tmp/uv-cache uv run python main.py --db data/naberius.db --alerts data/alerts.db >> /var/log/vassago.log 2>&1
