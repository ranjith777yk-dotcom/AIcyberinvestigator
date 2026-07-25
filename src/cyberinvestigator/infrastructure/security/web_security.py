"""Production-oriented HTTP security, RBAC, rate limiting, and audit logging."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta, timezone
from pathlib import Path
from typing import Callable
from uuid import UUID, uuid4

from flask import Flask, Response, g, jsonify, redirect, request, session, url_for
from sqlalchemy import func, select

from cyberinvestigator.infrastructure.database.base import utc_now
from cyberinvestigator.infrastructure.database.models import (
    AuditLog,
    Notification,
    Permission,
    Role,
    RolePermission,
    SecurityAlert,
    User,
    UserSession,
)

try:
    import bcrypt
except ImportError:  # pragma: no cover - fallback keeps app bootable before dev deps are installed.
    bcrypt = None

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
PUBLIC_ENDPOINTS = {
    "web.login",
    "web.register",
    "web.forgot_password",
    "web.google_auth",
    "web.google_callback",
    "web.logout",
    "api_v1.health_live",
    "api_v1.health_ready",
    "static",
}
ROLE_ALIASES = {
    "administrator": "admin",
    "admin": "admin",
    "user": "user",
    "viewer": "user",
    "analyst": "user",
    "investigator": "user",
}
ROLE_ORDER = ["user", "admin"]
SYSTEM_PERMISSIONS = {
    "user": {
        "dashboard.read",
        "cases.read",
        "cases.write",
        "evidence.read",
        "evidence.write",
        "timeline.read",
        "timeline.write",
        "reports.read",
        "reports.write",
        "ai.chat",
    },
    "admin": {
        "dashboard.read",
        "cases.read",
        "cases.write",
        "evidence.read",
        "evidence.write",
        "timeline.read",
        "timeline.write",
        "reports.read",
        "reports.write",
        "plugins.read",
        "plugins.manage",
        "ai.chat",
        "admin.access",
        "settings.manage",
        "users.manage",
        "security.monitor",
    },
}
ENDPOINT_PERMISSIONS = {
    "web.dashboard": ("dashboard.read",),
    "web.cases": ("cases.read",),
    "web.evidence": ("evidence.read",),
    "web.timeline": ("timeline.read",),
    "web.reports": ("reports.read",),
    "web.ai_chat": ("ai.chat",),
    "web.plugins": ("plugins.manage",),
    "web.settings": ("settings.manage",),
    "web.admin": ("admin.access",),
    "api_v1.dashboard_snapshot": ("dashboard.read",),
    "api_v1.openapi_spec": ("dashboard.read",),
    "api_v1.ai_status": ("ai.chat",),
    "api_v1.ai_chat": ("ai.chat",),
    "api_v1.ai_chat_stream": ("ai.chat",),
    "api_v1.list_ai_conversations": ("ai.chat",),
    "api_v1.get_ai_conversation": ("ai.chat",),
    "api_v1.rename_ai_conversation": ("ai.chat",),
    "api_v1.delete_ai_conversation": ("ai.chat",),
    "api_v1.ai_analyze": ("ai.chat",),
    "api_v1.ai_timeline_summary": ("ai.chat",),
    "api_v1.ai_explain_ioc": ("ai.chat",),
    "api_v1.ai_explain_malware": ("ai.chat",),
    "api_v1.ai_analyze_log": ("ai.chat",),
    "api_v1.ai_analyze_email_header": ("ai.chat",),
    "api_v1.plugin_inventory": ("plugins.manage",),
    "api_v1.reload_plugins": ("plugins.manage",),
    "api_v1.upload_plugin": ("plugins.manage",),
    "api_v1.plugin_lifecycle": ("plugins.manage",),
    "api_v1.list_cases": ("cases.read",),
    "api_v1.create_case": ("cases.write",),
    "api_v1.update_case": ("cases.write",),
    "api_v1.case_action": ("cases.write",),
    "api_v1.list_evidence": ("evidence.read",),
    "api_v1.create_evidence": ("evidence.write",),
    "api_v1.delete_evidence": ("evidence.write",),
    "api_v1.evidence_analysis": ("evidence.write",),
    "api_v1.export_evidence": ("evidence.read",),
    "api_v1.list_timeline": ("timeline.read",),
    "api_v1.export_timeline": ("timeline.read",),
    "api_v1.timeline_ai_summary": ("ai.chat",),
    "api_v1.create_timeline_event": ("timeline.write",),
    "api_v1.list_reports": ("reports.read",),
    "api_v1.create_report": ("reports.write",),
    "api_v1.get_report": ("reports.read",),
    "api_v1.analyze_report": ("reports.read",),
    "api_v1.export_report": ("reports.read",),
    "api_v1.get_settings": ("settings.manage",),
    "api_v1.update_settings": ("settings.manage",),
    "api_v1.monitoring_metrics": ("security.monitor",),
    "api_v1.admin_overview": ("admin.access",),
    "api_v1.admin_logs": ("admin.access",),
    "api_v1.admin_audit_logs": ("admin.access",),
    "api_v1.admin_database": ("admin.access",),
    "api_v1.list_users": ("users.manage",),
    "api_v1.create_user": ("users.manage",),
    "api_v1.update_user": ("users.manage",),
    "api_v1.secrets_inventory": ("admin.access",),
    "api_v1.admin_investigations": ("admin.access",),
    "api_v1.review_investigation": ("admin.access",),
    "api_v1.list_notifications": ("dashboard.read",),
    "api_v1.account_workspace": ("dashboard.read",),
    "api_v1.update_account_preferences": ("dashboard.read",),
    "api_v1.revoke_account_session": ("dashboard.read",),
    "api_v1.mark_notifications_read": ("dashboard.read",),
    "api_v1.archive_notification": ("dashboard.read",),
    "api_v1.mark_notification_read": ("dashboard.read",),
    "api_v1.delete_notification": ("dashboard.read",),
    "api_v1.security_soc": ("security.monitor",),
    "api_v1.security_alerts": ("security.monitor",),
    "api_v1.security_report": ("security.monitor",),
}


@dataclass(frozen=True, slots=True)
class UserPrincipal:
    """Authenticated user context resolved for a request."""

    username: str
    role: str
    user_id: str | None = None
    permissions: frozenset[str] = frozenset()


class SlidingWindowRateLimiter:
    """Small in-process sliding window rate limiter."""

    def __init__(self, *, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, now: float | None = None) -> tuple[bool, int]:
        current = now if now is not None else time.time()
        bucket = self._hits[key]
        while bucket and bucket[0] <= current - self.window_seconds:
            bucket.popleft()
        remaining = max(0, self.limit - len(bucket))
        if remaining <= 0:
            return False, 0
        bucket.append(current)
        return True, remaining - 1


def register_web_security(app: Flask) -> None:
    """Register request security controls that degrade safely in testing."""

    _bootstrap_security_records(app)
    limiter = SlidingWindowRateLimiter(
        limit=int(app.config.get("RATE_LIMIT_REQUESTS", 300)),
        window_seconds=int(app.config.get("RATE_LIMIT_WINDOW_SECONDS", 60)),
    )
    app.extensions["cyberinvestigator_rate_limiter"] = limiter

    @app.before_request
    def establish_request_security():  # type: ignore[no-untyped-def]
        g.request_id = request.headers.get("X-Request-ID") or str(uuid4())
        g.current_user = _resolve_user(app)

        auth_response = _validate_authenticated(app)
        if auth_response is not None:
            _audit(app, "auth.required", status=401, result="blocked", reason="Authentication required.")
            return auth_response

        allowed, remaining = limiter.allow(_rate_limit_key())
        g.rate_limit_remaining = remaining
        if not allowed and not bool(app.config.get("TESTING", False)):
            _audit(app, "rate_limit.blocked", status=429)
            return jsonify({"error": "rate limit exceeded", "request_id": g.request_id}), 429

        csrf_response = _validate_csrf(app)
        if csrf_response is not None:
            _audit(app, "csrf.blocked", status=403)
            return csrf_response

        rbac_response = _validate_rbac(app)
        if rbac_response is not None:
            _audit(app, "rbac.blocked", status=403)
            return rbac_response

    @app.after_request
    def finalize_request_security(response: Response):  # type: ignore[no-untyped-def]
        response.headers.setdefault("X-Request-ID", getattr(g, "request_id", str(uuid4())))
        response.headers.setdefault("X-RateLimit-Limit", str(app.config.get("RATE_LIMIT_REQUESTS", 300)))
        response.headers.setdefault("X-RateLimit-Remaining", str(getattr(g, "rate_limit_remaining", 0)))
        if request.method not in SAFE_METHODS or response.status_code >= 400 or request.path.startswith("/admin"):
            _audit(app, "request.completed", status=response.status_code)
        return response

    @app.context_processor
    def inject_security_context():  # type: ignore[no-untyped-def]
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return {
            "csrf_token": token,
            "current_user": getattr(g, "current_user", UserPrincipal("user", "user")),
            "can": lambda permission: _has_permission(getattr(g, "current_user", None), permission),
            "google_oauth_configured": bool(
                app.config.get("GOOGLE_CLIENT_ID") and app.config.get("GOOGLE_CLIENT_SECRET")
            ),
        }


def require_role(role: str) -> Callable:
    """Decorator for view functions that require a minimum role."""

    allowed = _allowed_roles(_normalize_role(role))

    def decorator(fn: Callable) -> Callable:
        fn._cyberinvestigator_allowed_roles = allowed
        return fn

    return decorator


def _allowed_roles(role: str) -> set[str]:
    if role not in ROLE_ORDER:
        return {role}
    return set(ROLE_ORDER[ROLE_ORDER.index(role) :])


def _normalize_role(role: object) -> str:
    return ROLE_ALIASES.get(str(role or "user").strip().lower(), "user")


def _resolve_user(app: Flask) -> UserPrincipal:
    if bool(app.config.get("TESTING", False)) and request.headers.get("X-CI-Role"):
        role = _normalize_role(request.headers.get("X-CI-Role"))
        username = str(request.headers.get("X-CI-User") or "test-user")
        database = app.extensions.get("cyberinvestigator_database")
        account = (
            database.session.scalar(select(User).where(func.lower(User.username) == username.lower()))
            if database
            else None
        )
        return UserPrincipal(
            username,
            role,
            str(account.id) if account else None,
            frozenset(SYSTEM_PERMISSIONS.get(role, set())),
        )
    if bool(app.config.get("TESTING", False)) and not bool(app.config.get("AUTH_REQUIRED", True)):
        return UserPrincipal("investigator", "admin", permissions=frozenset(SYSTEM_PERMISSIONS["admin"]))
    database = app.extensions.get("cyberinvestigator_database")
    user_id = session.get("user_id")
    if database is not None and user_id:
        user = database.session.get(User, _session_uuid(user_id))
        if user and user.status == "active":
            role_name = _normalize_role(user.role.name)
            permissions = _permissions_for_role(user.role)
            if not permissions or role_name != user.role.name:
                permissions = SYSTEM_PERMISSIONS.get(role_name, set())
            return UserPrincipal(str(user.username), role_name, str(user.id), frozenset(permissions))
    users = _configured_users(app)
    username = (
        request.headers.get("X-CI-User") or session.get("username") or app.config.get("DEFAULT_USER", "investigator")
    )
    role = _normalize_role(
        request.headers.get("X-CI-Role")
        or users.get(str(username), "admin" if bool(app.config.get("TESTING", False)) else "user")
    )
    return UserPrincipal(str(username), str(role), permissions=frozenset(SYSTEM_PERMISSIONS.get(str(role), set())))


def _validate_authenticated(app: Flask):
    if not bool(app.config.get("AUTH_REQUIRED", True)) or bool(app.config.get("TESTING", False)):
        return None
    endpoint = request.endpoint or ""
    if endpoint in PUBLIC_ENDPOINTS or endpoint.startswith("static"):
        return None
    user = getattr(g, "current_user", UserPrincipal("anonymous", "user"))
    if user.user_id and _touch_session(app):
        return None
    if request.path.startswith("/api/"):
        return jsonify({"error": "authentication required", "request_id": getattr(g, "request_id", None)}), 401
    return redirect(url_for("web.login", next=request.full_path if request.query_string else request.path))


def _configured_users(app: Flask) -> dict[str, str]:
    raw = app.config.get("USER_ROLES", "")
    if isinstance(raw, dict):
        return {str(key): str(value) for key, value in raw.items()}
    users: dict[str, str] = {}
    for pair in str(raw or "").split(","):
        if ":" in pair:
            username, role = pair.split(":", 1)
            users[username.strip()] = role.strip()
    return users


def _rate_limit_key() -> str:
    user = getattr(g, "current_user", None)
    username = user.username if user else "anonymous"
    return f"{request.remote_addr or 'local'}:{username}"


def _validate_csrf(app: Flask):
    if bool(app.config.get("TESTING", False)) or not bool(app.config.get("CSRF_ENABLED", True)):
        return None
    if request.method in SAFE_METHODS or request.path.startswith("/api/v1/health"):
        return None
    expected = session.get("csrf_token")
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    if expected and supplied and hmac.compare_digest(str(expected), str(supplied)):
        return None
    return jsonify({"error": "CSRF token is required.", "request_id": getattr(g, "request_id", None)}), 403


def _validate_rbac(app: Flask):
    endpoint = request.endpoint
    view = app.view_functions.get(endpoint or "")
    allowed_roles = getattr(view, "_cyberinvestigator_allowed_roles", None)
    user = getattr(g, "current_user", UserPrincipal("anonymous", "user"))
    if allowed_roles and user.role not in allowed_roles:
        _record_alert(
            app,
            "high",
            "authorization",
            "Privilege violation",
            f"{user.username} attempted to access {endpoint or request.path}",
            70,
        )
        return jsonify({"error": "insufficient role", "request_id": getattr(g, "request_id", None)}), 403
    required_permissions = ENDPOINT_PERMISSIONS.get(endpoint or "", ())
    if not required_permissions:
        return None
    if all(_has_permission(user, permission) for permission in required_permissions):
        return None
    _record_alert(
        app,
        "high",
        "authorization",
        "Privilege violation",
        f"{user.username} attempted to use {endpoint or request.path}",
        70,
    )
    return jsonify({"error": "insufficient permission", "request_id": getattr(g, "request_id", None)}), 403


def _has_permission(user: UserPrincipal | None, permission: str) -> bool:
    return bool(user and permission in user.permissions)


def _permissions_for_role(role: Role) -> set[str]:
    return {item.permission.code for item in role.permissions}


def _audit(app: Flask, event: str, *, status: int, result: str | None = None, reason: str | None = None) -> None:
    try:
        log_dir = Path(app.config["LOGS_FOLDER"])
        log_dir.mkdir(parents=True, exist_ok=True)
        user = getattr(g, "current_user", UserPrincipal("anonymous", "user"))
        record = {
            "ts": time.time(),
            "event": event,
            "request_id": getattr(g, "request_id", None),
            "method": request.method,
            "path": request.path,
            "status": status,
            "user": user.username,
            "role": user.role,
            "remote_addr": request.remote_addr,
            "user_agent": request.headers.get("User-Agent"),
            "reason": reason,
        }
        with (log_dir / "audit.log").open("a", encoding="utf-8") as audit_file:
            audit_file.write(json.dumps(record, separators=(",", ":")) + "\n")
        database = app.extensions.get("cyberinvestigator_database")
        if database is not None and event != "request.completed":
            database.session.add(
                AuditLog(
                    user_id=user.user_id,
                    username=user.username,
                    role=user.role,
                    action=event,
                    result=result or ("success" if status < 400 else "failure"),
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get("User-Agent"),
                    affected_object=request.path,
                    reason=reason,
                )
            )
            database.session.commit()
    except Exception:
        app.logger.debug("Audit logging failed.", exc_info=True)


def hash_password(password: str) -> str:
    """Hash one password with bcrypt."""
    if bcrypt is not None:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), 390_000).hex()
    return f"pbkdf2_sha256$390000${salt}${digest}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verify one password against a bcrypt hash."""
    if password_hash.startswith("pbkdf2_sha256$"):
        try:
            _, rounds, salt, expected = password_hash.split("$", 3)
            digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), int(rounds)).hex()
            return hmac.compare_digest(digest, expected)
        except (ValueError, TypeError):
            return False
    if bcrypt is None:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def authenticate_user(app: Flask, username_or_email: str, password: str, *, remember: bool = False) -> tuple[bool, str]:
    """Authenticate a user, open a server-side session, and audit the result."""
    database = app.extensions["cyberinvestigator_database"]
    session_db = database.session
    identity = username_or_email.strip().lower()
    candidates = list(
        session_db.scalars(
            select(User)
            .join(Role)
            .where((func.lower(User.username) == identity) | (func.lower(User.email) == identity))
            .order_by(Role.name.asc(), User.created_at.asc())
        )
    )
    user = next((candidate for candidate in candidates if verify_password(password, candidate.password_hash)), None)
    now = utc_now()
    if user is None:
        candidate = candidates[0] if candidates else None
        session_db.add(
            AuditLog(
                user_id=candidate.id if candidate else None,
                username=identity,
                role=candidate.role.name if candidate else None,
                action="auth.login",
                result="failure",
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent"),
                reason="bad password" if candidates else "unknown account",
            )
        )
        if candidate is not None:
            candidate.failed_login_count += 1
            if candidate.failed_login_count >= int(app.config.get("MAX_FAILED_LOGINS", 5)):
                candidate.locked_until = now + timedelta(minutes=15)
                _record_alert(app, "high", "authentication", "Account locked", f"{candidate.username} was locked.", 75)
        session_db.commit()
        if candidate is None:
            _record_alert(
                app, "medium", "authentication", "Failed login", f"Unknown account login attempt: {identity}", 45
            )
        return False, "Invalid username or password."
    if user.status != "active":
        session_db.add(
            AuditLog(
                user_id=user.id,
                username=user.username,
                role=user.role.name,
                action="auth.login",
                result="failure",
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent"),
                reason="disabled account",
            )
        )
        session_db.commit()
        return False, "Account is disabled."
    if user.locked_until and user.locked_until > now:
        return False, "Account is temporarily locked."
    user.failed_login_count = 0
    user.locked_until = None
    _open_user_session(app, user, remember=remember, action="auth.login")
    session_db.commit()
    return True, "Authenticated."


def login_user_account(app: Flask, user: User, *, remember: bool = False, action: str = "auth.login") -> None:
    """Open a secure server-side session for an already verified identity."""
    _open_user_session(app, user, remember=remember, action=action)
    app.extensions["cyberinvestigator_database"].session.commit()


def _open_user_session(app: Flask, user: User, *, remember: bool, action: str) -> None:
    now = utc_now()
    token = secrets.token_urlsafe(32)
    expires = now + timedelta(days=30 if remember else 1)
    user.last_login_at = now
    role_name = _normalize_role(user.role.name)
    session["user_id"] = str(user.id)
    session["role"] = role_name
    session["session_token"] = token
    session.permanent = remember
    app.extensions["cyberinvestigator_database"].session.add(
        UserSession(
            user_id=user.id,
            owner_user_id=user.id,
            created_by_user_id=user.id,
            session_token_hash=_token_hash(token),
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
            expires_at=expires,
        )
    )
    app.extensions["cyberinvestigator_database"].session.add(
        AuditLog(
            user_id=user.id,
            username=user.username,
            role=role_name,
            action=action,
            result="success",
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent"),
        )
    )


def logout_user(app: Flask) -> None:
    """Close the active server-side session."""
    database = app.extensions.get("cyberinvestigator_database")
    token = session.get("session_token")
    user_id = session.get("user_id")
    if database is not None and token:
        active = database.session.scalar(
            select(UserSession).where(UserSession.session_token_hash == _token_hash(token))
        )
        if active:
            active.active = False
            active.status = "closed"
            active.updated_at = utc_now()
        user = database.session.get(User, _session_uuid(user_id)) if user_id else None
        database.session.add(
            AuditLog(
                user_id=user.id if user else None,
                username=user.username if user else None,
                role=user.role.name if user else None,
                action="auth.logout",
                result="success",
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent"),
            )
        )
        database.session.commit()
    session.clear()


def _touch_session(app: Flask) -> bool:
    token = session.get("session_token")
    if not token:
        return False
    database = app.extensions["cyberinvestigator_database"]
    active = database.session.scalar(select(UserSession).where(UserSession.session_token_hash == _token_hash(token)))
    now = utc_now()
    expires_at = _aware_utc(active.expires_at) if active else now
    if not active or not active.active or expires_at <= now:
        session.clear()
        return False
    last_seen = _aware_utc(active.last_seen_at) if active.last_seen_at else None
    if last_seen is None or (now - last_seen).total_seconds() >= 60:
        active.last_seen_at = now
        active.updated_at = now
        active.status = "active"
        database.session.commit()
    return True


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _session_uuid(value: object) -> UUID | None:
    try:
        return UUID(str(value))
    except (TypeError, ValueError):
        return None


def _aware_utc(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _bootstrap_security_records(app: Flask) -> None:
    database = app.extensions["cyberinvestigator_database"]
    with app.app_context():
        roles: dict[str, Role] = {}
        for role_name in ROLE_ORDER:
            role = database.session.scalar(select(Role).where(Role.name == role_name))
            if role is None:
                role = Role(name=role_name, description=f"System {role_name} role", is_system=True)
                database.session.add(role)
            roles[role_name] = role
        permissions: dict[str, Permission] = {}
        all_permissions = sorted({permission for values in SYSTEM_PERMISSIONS.values() for permission in values})
        for code in all_permissions:
            permission = database.session.scalar(select(Permission).where(Permission.code == code))
            if permission is None:
                permission = Permission(code=code, label=code.replace(".", " ").title(), category=code.split(".", 1)[0])
                database.session.add(permission)
            permissions[code] = permission
        database.session.flush()
        for role_name, codes in SYSTEM_PERMISSIONS.items():
            role = roles[role_name]
            existing = {item.permission.code for item in role.permissions}
            for code in codes - existing:
                database.session.add(RolePermission(role_id=role.id, permission_id=permissions[code].id))
        database.session.flush()
        for legacy_name in ("viewer", "analyst", "investigator"):
            legacy_role = database.session.scalar(select(Role).where(Role.name == legacy_name))
            if legacy_role is None:
                continue
            target_role = roles["user"]
            for account in legacy_role.users:
                account.role_id = target_role.id
        if database.session.scalar(select(func.count()).select_from(User)) == 0:
            admin_role = roles["admin"]
            database.session.add(
                User(
                    username=str(app.config.get("DEFAULT_USER", "investigator")),
                    email=str(app.config.get("DEFAULT_ADMIN_EMAIL", "investigator@example.local")),
                    password_hash=hash_password(str(app.config.get("DEFAULT_ADMIN_PASSWORD", "ChangeMe!2026"))),
                    role_id=admin_role.id,
                    status="active",
                )
            )
            database.session.add(
                Notification(
                    title="Default administrator created",
                    message="Change the default administrator password in production.",
                    category="security",
                    priority="high",
                    pinned=True,
                )
            )
        database.session.commit()


def _record_alert(app: Flask, level: str, category: str, title: str, message: str, score: int) -> None:
    database = app.extensions.get("cyberinvestigator_database")
    if database is None:
        return
    database.session.add(SecurityAlert(level=level, category=category, title=title, message=message, score=score))
    database.session.add(
        Notification(title=title, message=message, category=category, priority=level, pinned=level == "critical")
    )
    database.session.commit()


def redirect_for_role(role: str) -> str:
    """Return the landing page for an authenticated role."""
    if role == "admin":
        return url_for("web.admin")
    return url_for("web.dashboard")


def safe_next(default: str) -> str:
    """Return a local redirect target only."""
    candidate = request.args.get("next") or request.form.get("next") or ""
    if candidate.startswith("/") and not candidate.startswith("//"):
        return candidate
    return default
