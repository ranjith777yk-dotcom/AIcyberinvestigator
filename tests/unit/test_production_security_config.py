from __future__ import annotations

import pytest

from cyberinvestigator.config.config import ProductionConfig


def test_production_requires_explicit_bootstrap_password(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_KEY", "production-secret")
    monkeypatch.setenv("DATABASE_URL", "postgresql://database")
    monkeypatch.delenv("DEFAULT_ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr(ProductionConfig, "TRUSTED_HOSTS", ["example.test"])

    with pytest.raises(RuntimeError, match="DEFAULT_ADMIN_PASSWORD"):
        ProductionConfig._validate()


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("SECRET_KEY", "change-me-with-a-strong-random-value", "SECRET_KEY"),
        (
            "DATABASE_URL",
            "postgresql://user:replace-with-secret@database/app",
            "DATABASE_URL",
        ),
        ("DEFAULT_ADMIN_PASSWORD", "replace-with-a-unique-bootstrap-password", "DEFAULT_ADMIN_PASSWORD"),
    ],
)
def test_production_rejects_documented_secret_placeholders(monkeypatch, name: str, value: str, message: str) -> None:
    monkeypatch.setenv("SECRET_KEY", "valid-production-secret")
    monkeypatch.setenv("DATABASE_URL", "postgresql://database/app")
    monkeypatch.setenv("DEFAULT_ADMIN_PASSWORD", "unique-production-password")
    monkeypatch.setenv(name, value)
    monkeypatch.setattr(ProductionConfig, "TRUSTED_HOSTS", ["example.test"])

    with pytest.raises(RuntimeError, match=message):
        ProductionConfig._validate()
