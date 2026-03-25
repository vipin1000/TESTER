# Deployment Guide

This guide describes a practical production deployment for the Web Audit Tool.

## 1. Runtime Requirements

- Linux server/container host
- Python 3.10+
- Network egress to scanned URLs
- `curl` available on the host/container
- Chromium dependencies for Playwright

## 2. Build and Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install fastapi uvicorn requests playwright playwright-stealth pyspellchecker spacy
python -m playwright install chromium
python -m spacy download en_core_web_sm
```

## 3. Run with Uvicorn

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
```

Recommended: keep `--workers 1` unless you externalize shared runtime state. The app stores scan state in memory.

## 4. Systemd Service Example

```ini
[Unit]
Description=Web Audit Tool
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/test
ExecStart=/opt/test/.venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
Restart=always
RestartSec=5
User=www-data
Group=www-data
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

## 5. Reverse Proxy and TLS

Put the app behind Nginx/Caddy/Traefik:
- terminate TLS at proxy
- proxy pass to `127.0.0.1:8000`
- enable request size/time limits
- enable access/error logging

## 6. Persistence

Persist `user_dictionary.txt`:
- bind mount in VM deployments, or
- persistent volume in container orchestration

Without persistence, approved words are lost on redeploy.

## 7. Security Hardening Checklist

- Restrict `allow_origins` in CORS middleware
- Add authentication before public deployment
- Run with least-privileged OS user
- Add request rate limiting at the proxy layer
- Keep dependencies and browser binaries updated
- Restrict outbound network if policy requires

## 8. Health and Operations

- Basic app check: `GET /api/capabilities`
- Track:
  - request latency
  - scan duration
  - error rate
  - worker/browser crashes
- Log rotation: configure for application and proxy logs

## 9. Scaling Guidance

Current design stores scan state in process memory. For horizontal scale:
- move scan/job state to shared storage (Redis/Postgres)
- move execution to dedicated workers/queue
- use stateless API instances

## 10. Upgrade Procedure

1. Backup `user_dictionary.txt`
2. Deploy new version to staging
3. Run smoke tests:
   - start single URL scan
   - check dictionary add/remove
   - verify UI loads
4. Deploy production with rollback plan
