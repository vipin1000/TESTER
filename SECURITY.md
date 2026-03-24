# Security Policy

## Supported Versions

This project is currently pre-1.0. Security fixes are applied to the latest `master` code.

## Reporting a Vulnerability

If you discover a security issue:

1. Do not open a public issue with exploit details.
2. Report privately to the project maintainer.
3. Include:
   - affected version/commit
   - reproduction steps
   - impact assessment
   - suggested mitigation (if available)

The maintainer will acknowledge receipt and provide remediation status updates.

## Security Considerations for This Project

- The scanner performs outbound requests to user-provided URLs.
- Untrusted targets can be slow, malicious, or attempt abuse patterns.
- Browser automation executes against external pages and must be sandboxed by deployment environment.

## Deployment Hardening Recommendations

- Restrict CORS origins (avoid wildcard in production).
- Add authentication/authorization in front of API routes.
- Enforce rate limiting at edge proxy.
- Run service as non-root user.
- Isolate runtime with container/VM boundaries.
- Restrict outbound network where possible.
- Set strict timeout and resource limits (CPU/memory/process count).
- Keep Python deps and Playwright/Chromium patched.

## Data Handling

- The app keeps scan state in memory.
- `user_dictionary.txt` stores approved words in plain text.
- Avoid placing secrets in scanned content or logs.

## Abuse and Safety

Use this tool only on websites you are authorized to test.  
Do not use it for intrusive, disruptive, or unauthorized scanning.
