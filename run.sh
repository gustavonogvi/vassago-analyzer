#!/bin/bash
cd /opt/vassago
UV_CACHE_DIR=/tmp/uv-cache uv run python main.py --db data/naberius.db --alerts data/alerts.db >> /var/log/vassago.log 2>&1
if [ $? -ne 0 ]; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ERROR: vassago exited with failure" >> /var/log/vassago.log
fi
