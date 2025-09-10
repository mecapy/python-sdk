"""Production endpoint smoke tests.

These tests are intended to be executed against the live production API.
They are read-only and only call safe GET endpoints:
- /
- /auth/me
- /auth/protected
- /health

How to run:
- Ensure environment variables are configured for production (defaults are already
  set for URLs). For authenticated tests, set MECAPY_USERNAME and MECAPY_PASSWORD
  (and optionally MECAPY_KEYCLOAK_URL, MECAPY_REALM, MECAPY_CLIENT_ID).
- Run: pytest -m production -q

Notes:
- Tests using authentication are skipped if credentials are not provided.
- Network errors or server issues will cause test failures by design, so we can
  detect incidents.
"""

import os
import pytest

from mecapy_sdk import MecaPyClient, AuthenticationError
from mecapy_sdk.models import APIResponse


pytestmark = pytest.mark.production


@pytest.mark.asyncio
async def test_root_endpoint_replies_with_basic_info():
    async with MecaPyClient.from_env() as client:
        info = await client.get_root()
        assert isinstance(info, APIResponse)
        # Basic sanity checks – fields should exist with expected types
        assert isinstance(info.message, str) and info.message
        assert isinstance(info.status, str) and info.status
        # version may be None or string depending on deployment
        assert (info.version is None) or isinstance(info.version, str)


@pytest.mark.asyncio
async def test_health_endpoint_reports_ok():
    async with MecaPyClient.from_env() as client:
        health = await client.health_check()
        # Expected minimal contract: a dict with a non-empty status string
        assert isinstance(health, dict)
        assert "status" in health
        assert isinstance(health["status"], str) and health["status"]


def _has_auth_env() -> bool:
    return bool(os.getenv("MECAPY_USERNAME") and os.getenv("MECAPY_PASSWORD"))


@pytest.mark.asyncio
@pytest.mark.skipif(not _has_auth_env(), reason="MECAPY_USERNAME/MECAPY_PASSWORD not provided")
async def test_auth_me_returns_current_user_info():
    async with MecaPyClient.from_env() as client:
        user = await client.get_current_user()
        assert user.preferred_username  # non-empty
        # email, given_name, family_name can be optional – only check types when present
        if user.email is not None:
            assert isinstance(user.email, str)


@pytest.mark.asyncio
@pytest.mark.skipif(not _has_auth_env(), reason="MECAPY_USERNAME/MECAPY_PASSWORD not provided")
async def test_auth_protected_accessible_when_authenticated():
    async with MecaPyClient.from_env() as client:
        resp = await client.test_protected_route()
        assert resp.endpoint == "protected"
        assert resp.user_info.preferred_username


@pytest.mark.asyncio
@pytest.mark.skipif(_has_auth_env(), reason="This test validates unauthenticated behavior; skip when credentials are present")
async def test_auth_protected_requires_auth_when_unauthenticated():
    # When no credentials are provided in env, accessing protected should raise AuthenticationError
    async with MecaPyClient.from_env() as client:
        with pytest.raises(AuthenticationError):
            await client.test_protected_route()
