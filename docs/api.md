# API Documentation

The generated OpenAPI document is available at:

- `GET /api/v1/openapi.json`

Important operational endpoints:

- `GET /api/v1/health/live`
- `GET /api/v1/health/ready`
- `GET /api/v1/monitoring/metrics`
- `GET /api/v1/admin/overview`
- `GET /api/v1/admin/users`
- `GET /api/v1/admin/secrets`
- `POST /api/v1/ai/chat`
- `POST /api/v1/ai/analyze`

Mutating browser requests require `X-CSRF-Token`. Admin endpoints require an admin role.
