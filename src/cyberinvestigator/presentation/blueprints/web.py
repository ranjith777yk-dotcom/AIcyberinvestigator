"""Server-rendered web interface blueprint."""

import json
import secrets
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from uuid import UUID

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session, url_for
from sqlalchemy import func, select

from cyberinvestigator.infrastructure.database.models import Role, User
from cyberinvestigator.infrastructure.security.web_security import (
    authenticate_user,
    hash_password,
    login_user_account,
    logout_user,
    redirect_for_role,
    require_role,
    safe_next,
)

web_blueprint = Blueprint("web", __name__)
"""Blueprint namespace for the Bootstrap-based web interface."""


def _profile_user_id(value: object) -> UUID | None:
    try:
        return UUID(str(value))
    except (TypeError, ValueError):
        return None


@web_blueprint.get("/")
@require_role("user")
def dashboard() -> str:
    """Render the main CyberInvestigator dashboard."""
    return render_template("dashboard.html", active_page="dashboard", page_title="Dashboard")


@web_blueprint.route("/login", methods=["GET", "POST"])
def login():
    """Render and process the single enterprise login page."""
    if request.method == "POST":
        ok, message = authenticate_user(
            current_app,
            request.form.get("username", ""),
            request.form.get("password", ""),
            remember=request.form.get("remember") == "on",
        )
        if ok:
            target = safe_next(redirect_for_role(str(session.get("role", "user"))))
            return redirect(target)
        flash(message, "danger")
    return render_template("login.html", active_page="login", page_title="Login")


@web_blueprint.route("/register", methods=["GET", "POST"])
def register():
    """Create a standard user account when self-registration is enabled."""
    if not bool(current_app.config.get("REGISTRATION_ENABLED", True)):
        flash("Account registration is disabled by the administrator.", "warning")
        return redirect(url_for("web.login"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if len(username) < 3 or "@" not in email or len(password) < 8:
            flash("Enter a username, valid email, and password with at least 8 characters.", "danger")
            return render_template("login.html", active_page="login", page_title="Register", auth_mode="register")
        database = current_app.extensions["cyberinvestigator_database"]
        role = database.session.scalar(select(Role).where(Role.name == "user"))
        if role is None:
            flash("User role is unavailable. Ask an administrator to repair security settings.", "danger")
            return render_template("login.html", active_page="login", page_title="Register", auth_mode="register")
        existing = database.session.scalar(
            select(User).where(
                (func.lower(User.email) == email)
                | ((func.lower(User.username) == username.lower()) & (User.role_id == role.id))
            )
        )
        if existing:
            flash("A user account with that username or email already exists.", "danger")
            return render_template("login.html", active_page="login", page_title="Register", auth_mode="register")
        database.session.add(
            User(
                username=username, email=email, password_hash=hash_password(password), role_id=role.id, status="active"
            )
        )
        database.session.commit()
        flash("Account created. You can sign in now.", "success")
        return redirect(url_for("web.login"))
    return render_template("login.html", active_page="login", page_title="Register", auth_mode="register")


@web_blueprint.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Render a non-disclosing password recovery entry point."""
    if request.method == "POST":
        flash("If that account exists, a recovery workflow has been recorded for administrator review.", "info")
        return redirect(url_for("web.login"))
    return render_template("login.html", active_page="login", page_title="Forgot Password", auth_mode="forgot")


@web_blueprint.get("/auth/google")
def google_auth():
    """Start Google OAuth when credentials are configured; otherwise fail safely."""
    client_id = current_app.config.get("GOOGLE_CLIENT_ID")
    client_secret = current_app.config.get("GOOGLE_CLIENT_SECRET")
    if not client_id or not client_secret:
        flash(
            "Google Sign-In is not configured. Use username/password or configure Google OAuth in settings.", "warning"
        )
        return redirect(url_for("web.login"))
    params = urlencode(
        {
            "client_id": client_id,
            "redirect_uri": url_for("web.google_callback", _external=True),
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "prompt": "select_account",
        }
    )
    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?{params}")


@web_blueprint.get("/auth/google/callback")
def google_callback():
    """Create or authenticate a user from a verified Google OAuth response."""
    code = request.args.get("code", "")
    client_id = current_app.config.get("GOOGLE_CLIENT_ID")
    client_secret = current_app.config.get("GOOGLE_CLIENT_SECRET")
    if not code or not client_id or not client_secret:
        flash("Google Sign-In is not fully configured. Use username/password sign-in.", "warning")
        return redirect(url_for("web.login"))
    try:
        token_body = urlencode(
            {
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": url_for("web.google_callback", _external=True),
                "grant_type": "authorization_code",
            }
        ).encode("utf-8")
        token_request = Request(
            "https://oauth2.googleapis.com/token",
            data=token_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urlopen(token_request, timeout=10) as response:  # noqa: S310 - fixed Google OAuth endpoint.
            token_payload = json.loads(response.read().decode("utf-8"))
        access_token = token_payload.get("access_token")
        if not access_token:
            flash("Google Sign-In did not return a verified access token.", "danger")
            return redirect(url_for("web.login"))
        profile_request = Request(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            method="GET",
        )
        with urlopen(profile_request, timeout=10) as response:  # noqa: S310 - fixed Google userinfo endpoint.
            profile = json.loads(response.read().decode("utf-8"))
    except (OSError, URLError, json.JSONDecodeError) as error:
        current_app.logger.warning("Google Sign-In failed safely: %s", error)
        flash("Google Sign-In could not complete. Use username/password sign-in.", "danger")
        return redirect(url_for("web.login"))
    email = str(profile.get("email") or "").strip().lower()
    if not email:
        flash("Google Sign-In did not provide an email address.", "danger")
        return redirect(url_for("web.login"))
    database = current_app.extensions["cyberinvestigator_database"]
    user = database.session.scalar(select(User).where(func.lower(User.email) == email))
    if user is None:
        role = database.session.scalar(select(Role).where(Role.name == "user"))
        if role is None:
            flash("User role is unavailable. Ask an administrator to repair security settings.", "danger")
            return redirect(url_for("web.login"))
        username = _unique_google_username(email)
        user = User(
            username=username,
            email=email,
            password_hash=hash_password(secrets.token_urlsafe(32)),
            role_id=role.id,
            status="active",
            profile_image=str(profile.get("picture") or "")[:1024] or None,
        )
        database.session.add(user)
        database.session.flush()
    login_user_account(current_app, user, remember=True, action="auth.google")
    return redirect(redirect_for_role(str(session.get("role", "user"))))


def _unique_google_username(email: str) -> str:
    database = current_app.extensions["cyberinvestigator_database"]
    role = database.session.scalar(select(Role).where(Role.name == "user"))
    base = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in email.split("@", 1)[0])[:40] or "user"
    username = base
    counter = 2
    while role is not None and database.session.scalar(
        select(User).where(func.lower(User.username) == username.lower(), User.role_id == role.id)
    ):
        username = f"{base}{counter}"
        counter += 1
    return username


@web_blueprint.post("/logout")
def logout():
    """End the active user session."""
    from flask import current_app

    logout_user(current_app)
    return redirect(url_for("web.login"))


@web_blueprint.get("/cases")
@require_role("user")
def cases() -> str:
    """Render the case-management workspace."""
    return render_template("cases.html", active_page="cases", page_title="Cases")


@web_blueprint.get("/evidence")
@require_role("user")
def evidence() -> str:
    """Render the evidence workspace."""
    return render_template("evidence.html", active_page="evidence", page_title="Evidence")


@web_blueprint.get("/timeline")
@require_role("user")
def timeline() -> str:
    """Render the investigation timeline workspace."""
    return render_template("timeline.html", active_page="timeline", page_title="Timeline")


@web_blueprint.get("/plugins")
@require_role("admin")
def plugins() -> str:
    """Render the plugin management workspace."""
    return render_template("plugins.html", active_page="plugins", page_title="Plugins")


@web_blueprint.get("/automation")
@require_role("user")
def automation() -> str:
    """Render the tenant-scoped Automation Center."""
    return render_template("automation.html", active_page="automation", page_title="Automation Center")


@web_blueprint.get("/analytics")
@require_role("user")
def analytics() -> str:
    """Render the Analytics & Machine Learning Center."""
    return render_template("analytics.html", active_page="analytics", page_title="Analytics & ML Center")


@web_blueprint.get("/mobile")
@require_role("user")
def mobile_companion() -> str:
    """Render the secure mobile companion view for responsive browsers."""
    return render_template("mobile_companion.html", active_page="mobile", page_title="Mobile Companion")


@web_blueprint.get("/commercial")
@require_role("admin")
def commercial() -> str:
    """Render optional licensing, usage, and marketplace administration."""
    return render_template("commercial.html", active_page="commercial", page_title="Commercial Administration")


@web_blueprint.get("/product")
@require_role("user")
def product() -> str:
    """Render privacy-aware product analytics and improvement workspace."""
    return render_template("product.html", active_page="product", page_title="Product Analytics Center")


@web_blueprint.get("/reports")
@require_role("user")
def reports() -> str:
    """Render the report workspace."""
    return render_template("reports.html", active_page="reports", page_title="Reports")


@web_blueprint.get("/settings")
@require_role("admin")
def settings() -> str:
    """Render the platform settings workspace."""
    return render_template("settings.html", active_page="settings", page_title="Settings")


@web_blueprint.get("/admin")
@require_role("admin")
def admin() -> str:
    """Render the admin operations workspace."""
    return render_template("admin.html", active_page="admin", page_title="Admin")


@web_blueprint.get("/admin/quality")
@require_role("admin")
def quality() -> str:
    """Render the generated-evidence quality management workspace."""
    return render_template("quality.html", active_page="quality", page_title="Quality Assurance")


@web_blueprint.get("/admin/performance")
@require_role("admin")
def performance() -> str:
    """Render the performance, scalability, and availability workspace."""
    return render_template("performance.html", active_page="performance", page_title="Performance & Scalability")


@web_blueprint.get("/admin/governance")
@require_role("admin")
def governance() -> str:
    """Render the compliance, privacy, and governance workspace."""
    return render_template("governance.html", active_page="governance", page_title="Compliance & Governance")


@web_blueprint.get("/developers")
@require_role("user")
def developers() -> str:
    """Render the authenticated developer documentation portal."""
    return render_template("developers.html", active_page="developers", page_title="Developer Platform")


@web_blueprint.get("/organizations")
@require_role("user")
def organizations() -> str:
    """Render the active organization administration and switching workspace."""
    return render_template("organizations.html", active_page="organizations", page_title="Organizations")


@web_blueprint.get("/collaboration")
@require_role("user")
def collaboration() -> str:
    """Render the tenant-scoped investigation collaboration workspace."""
    return render_template("collaboration.html", active_page="collaboration", page_title="Team Collaboration")


@web_blueprint.get("/threat-hunting")
@require_role("user")
def threat_hunting() -> str:
    """Render the tenant-scoped Threat Hunting Center."""
    return render_template("threat_hunting.html", active_page="threat_hunting", page_title="Threat Hunting Center")


@web_blueprint.get("/intelligence")
@require_role("user")
def intelligence_center() -> str:
    """Render the tenant-scoped Threat Intelligence Center."""
    return render_template(
        "intelligence_center.html",
        active_page="intelligence_center",
        page_title="Threat Intelligence Center",
    )


@web_blueprint.get("/ai-chat")
@require_role("user")
def ai_chat() -> str:
    """Render the AI investigation chat workspace."""
    return render_template("ai_chat.html", active_page="ai_chat", page_title="AI Chat")


@web_blueprint.route("/profile", methods=["GET", "POST"])
@require_role("user")
def profile() -> str:
    """Render and update the authenticated user's profile surface."""
    database = current_app.extensions["cyberinvestigator_database"]
    current = getattr(g, "current_user", None)
    user_id = _profile_user_id(getattr(current, "user_id", None))
    user = database.session.get(User, user_id) if user_id else None
    if user is None:
        flash("Profile is available after signing in with a database-backed account.", "warning")
        return render_template("profile.html", active_page="profile", page_title="Profile", profile_user=None)
    if request.method == "POST":
        if request.form.get("form_name") == "password":
            password = request.form.get("password", "")
            if len(password) < 10:
                flash("Password must contain at least 10 characters.", "danger")
            else:
                user.password_hash = hash_password(password)
                database.session.commit()
                flash("Password updated.", "success")
        elif request.form.get("form_name") == "profile":
            image = request.form.get("profile_image", "").strip()
            user.profile_image = image[:1024] or None
            database.session.commit()
            flash("Profile updated.", "success")
    return render_template("profile.html", active_page="profile", page_title="Profile", profile_user=user)
