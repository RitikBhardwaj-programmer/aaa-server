"""Unit tests of the portal with mocks: no live LDAP, PostgreSQL or access point.

app.py reads its settings when it is imported. In the portal-test container the real values are
already set; elsewhere (GitHub Actions, a laptop) these test values are used.
"""
import importlib
import os

os.environ.setdefault("LDAP_BASE_DN", "dc=example,dc=test")
os.environ.setdefault("LDAP_PORTAL_PASSWORD", "unit-test")
os.environ.setdefault("POSTGRES_PORTAL_PASSWORD", "unit-test")
os.environ.setdefault("PORTAL_SECRET_KEY", "unit-test-secret-key-0123456789abcdef")

# app.py loads the feature modules (apiauth.py and later ones) at its end, and they import app.
# So app is always imported first, as `flask --app app` does; `import apiauth` alone would be circular.
importlib.import_module("app")
