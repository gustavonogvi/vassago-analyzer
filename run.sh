#!/bin/bash
export UV_CACHE_DIR=/opt/naberius-uv-cache
cd /opt/vassago
uv run python main.py --api-url http://192.168.56.20:5000 --alerts data/alerts.db >> /var/log/vassago.log 2>&1
if [ $? -ne 0 ]; then
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] ERROR: vassago exited with failure" >> /var/log/vassago.log
fi
