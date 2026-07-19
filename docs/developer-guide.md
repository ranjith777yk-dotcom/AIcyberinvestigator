# Developer Guide

## Architecture

The application follows a layered Flask structure:

- `domain`: investigation entities and pure domain services.
- `application`: DTOs, service orchestration, and ports.
- `infrastructure`: database, storage, plugins, AI providers, security, logging.
- `presentation`: web templates, static assets, error handling.
- `api/v1`: stable REST API.

## Security Expectations

- Use SQLAlchemy expressions and bound parameters for database access.
- Never return stack traces, filesystem paths, secrets, or raw provider errors to clients.
- Add CSRF tokens to browser-originating mutating requests.
- Prefer `textContent` over `innerHTML` for dynamic UI text.
- Keep provider integrations optional and fallback-safe.

## Testing

Run:

```powershell
.\.venv\Scripts\python -m pytest
```

Add focused tests for each new endpoint, domain rule, and security control.
