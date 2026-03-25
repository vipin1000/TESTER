# Web Audit Tool

FastAPI-based web audit tool for:
- Broken link checks
- Spelling checks with optional NLP-based ignore logic
- Lightweight browser UI for running and reviewing scans

## Features

- Scan one URL or multiple URLs (sitemap `.txt` style list)
- Detect visible links and classify them as reachable/broken
- Spell-check visible page text
- Custom dictionary support (`user_dictionary.txt`)
- Live scan progress and per-page result breakdown

## Tech Stack

- Python
- FastAPI
- Playwright (Chromium)
- Requests + `curl` fallback checks
- Optional:
  - `pyspellchecker` for spell checks
  - `spaCy` (`en_core_web_sm`) for dynamic ignore enrichment

## Project Structure

`main.py` - API server and scan engine  
`static/index.html` - Frontend UI

## Local Setup

### 1) Create environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2) Install dependencies

```bash
pip install -r requirements.txt
python -m playwright install chromium
python -m spacy download en_core_web_sm
```

If optional packages are missing, the app still runs, but related capabilities are disabled.

### 3) Run the app

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

Open: `http://localhost:8000`

## Docker

Build image:

```bash
docker build -t test:latest .
```

Run container:

```bash
docker run --rm -p 8000:8000 --name test test:latest
```

Open: `http://localhost:8000`

## API Endpoints

- `POST /api/scan/start` - start scan
- `GET /api/scan/{scan_id}` - poll status/results
- `GET /api/dictionary` - list approved dictionary words
- `POST /api/dictionary/add` - add approved dictionary word
- `POST /api/dictionary/remove` - remove approved dictionary word
- `GET /api/capabilities` - runtime capability flags
- `GET /` - serves frontend

## Production Notes

- See deployment runbook: `DEPLOYMENT.md`
- See security policy and hardening notes: `SECURITY.md`
- Keep `user_dictionary.txt` persisted (volume or shared storage) if you need dictionary state across deploys
- Use a reverse proxy and TLS in production
- Restrict CORS before public exposure (default code currently allows all origins)

## Limitations

- In-memory `scans` state is not shared across processes/replicas
- High parallelism can increase browser and network load significantly
- External site behavior (anti-bot controls, timeouts, robots rules) affects scan accuracy

## License

This project is licensed under the MIT License. See `LICENSE`.
