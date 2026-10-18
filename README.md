# Authentication Service

JWT-based authentication service built with Rust, Axum, and SQLite.

## Setup

```bash
cp .env.example .env
export $(cat .env | xargs)
cargo run
```

On first run, this creates `auth.db`, applies migrations, and (if `ADMIN_EMAIL`/`ADMIN_PASSWORD` are set) seeds an admin user.

## Routes

| Method | Path                 | Auth required    | Description                                  |
|--------|-----------------------|------------------|-----------------------------------------------|
| POST   | `/api/auth/register`  | None             | Create a new user account, returns tokens    |
| POST   | `/api/auth/login`     | None             | Authenticate with email/password, returns tokens |
| POST   | `/api/auth/refresh`   | None (refresh token in body) | Exchange a refresh token for a new token pair |
| POST   | `/api/auth/logout`    | None (refresh token in body) | Invalidate a refresh token |
| GET    | `/api/me`              | Bearer access token | Returns the current authenticated user's profile |
| GET    | `/api/admin/users`     | Bearer access token + `admin` role | Admin-only endpoint, lists users |

### Request/response shapes

**POST /api/auth/register**
```json
// request
{ "email": "alice@example.com", "password": "password123", "name": "Alice" }

// response (201 Created)
{
  "user": { "id": "...", "email": "...", "name": "..." },
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**POST /api/auth/login**
```json
// request
{ "email": "alice@example.com", "password": "password123" }

// response (200 OK) — same shape as register
```

**POST /api/auth/refresh**
```json
// request
{ "refresh_token": "..." }

// response (200 OK)
{ "access_token": "...", "refresh_token": "...", "token_type": "Bearer", "expires_in": 900 }
```

**POST /api/auth/logout**
```json
// request
{ "refresh_token": "..." }

// response: 204 No Content
```

**GET /api/me**
```
Authorization: Bearer <access_token>
```
```json
// response (200 OK)
{ "id": "...", "email": "...", "roles": ["user"] }
```

**GET /api/admin/users**
```
Authorization: Bearer <access_token>   // must include "admin" role
```
```json
// response (200 OK)
{ "users": [], "total": 0 }

// 403 Forbidden if the token's roles don't include "admin"
```

## Error responses

All errors return `{ "error": "<message>" }` with an appropriate status code:

| Status | When |
|--------|------|
| 400 Bad Request | Validation failure (bad email, password too short, etc.) |
| 401 Unauthorized | Missing/invalid/expired token, or bad login credentials |
| 403 Forbidden | Valid token but missing required role |
| 409 Conflict | Email already registered |
| 500 Internal Server Error | Unexpected server-side failure |
