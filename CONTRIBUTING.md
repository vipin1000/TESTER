# Contributing Guide

Thanks for contributing to the Web Audit Tool.

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn requests playwright playwright-stealth pyspellchecker spacy
python -m playwright install chromium
python -m spacy download en_core_web_sm
```

Run locally:

```bash
uvicorn main:app --reload
```

## Contribution Workflow

1. Fork/branch from `master`
2. Make focused changes
3. Verify local behavior
4. Open pull request with:
   - purpose
   - approach
   - testing notes

## Code Guidelines

- Keep changes minimal and explicit
- Preserve existing API responses unless intentionally versioned
- Prefer readable, testable functions
- Avoid introducing unnecessary dependencies

## Testing Checklist

Before opening a PR, verify:
- app boots without errors
- scan start and polling work
- dictionary add/remove works
- frontend loads and updates with scan progress

## Documentation

If behavior changes, update:
- `README.md`
- `DEPLOYMENT.md` (if operationally relevant)
- `CHANGELOG.md`

## Code of Conduct

By participating, you agree to follow `CODE_OF_CONDUCT.md`.
