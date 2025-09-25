"""Pytest configuration and fixtures."""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from mecapy import MecaPyClient
from mecapy.auth import MecapyAuth


@pytest.fixture
def mock_auth():
    """Mock MecapyAuth instance."""
    auth = AsyncMock(spec=MecapyAuth)
    auth.get_access_token.return_value = "mock_token"
    auth.get_session.return_value = AsyncMock()
    return auth


@pytest.fixture
def client():
    """MecaPyClient instance with mock auth."""
    with patch('mecapy.client.MecapyAuth') as mock_auth_class:
        mock_auth = AsyncMock()
        mock_auth.get_access_token.return_value = "mock_token"
        mock_auth_class.return_value = mock_auth

        client = MecaPyClient(api_url="https://api.example.com", timeout=10.0)
        client.auth = mock_auth
        return client


@pytest.fixture
def client_no_auth():
    """MecaPyClient instance without auth for public endpoints."""
    with patch('mecapy.client.MecapyAuth') as mock_auth_class:
        mock_auth = Mock()
        mock_auth_class.return_value = mock_auth

        client = MecaPyClient(api_url="https://api.example.com", timeout=10.0)
        client.auth = None  # Set to None for public endpoints
        return client