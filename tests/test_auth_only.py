#!/usr/bin/env python3
"""Simple authentication-only test script.

This script tests only the OAuth2 + PKCE authentication flow without making API calls.
Useful when you want to test authentication independently of the API server.

Usage:
    python tests/test_auth_only.py
"""

import os
import sys
from pathlib import Path

# Add the package to path for direct script execution
sys.path.insert(0, str(Path(__file__).parent.parent))

from mecapy.auth import MecapyAuth
from mecapy.config import config as conf


def test_auth_only():
    """Test OAuth2 + PKCE authentication without API calls."""
    print("=== MecaPy SDK Authentication-Only Test ===")
    print(f"Auth Issuer: {conf.auth.issuer}")
    print(f"Client ID: {conf.auth.client_id}")
    print()

    try:
        print("1. Initializing authentication...")
        auth = MecapyAuth()

        print("2. Getting token (will trigger browser authentication if needed)...")
        token_data = auth.get_token()

        print("✅ Authentication successful!")
        print(f"Token type: {token_data.get('token_type', 'Unknown')}")
        print(f"Expires in: {token_data.get('expires_in', 'Unknown')} seconds")
        print(f"Scopes: {token_data.get('scope', 'Unknown')}")

        # Test access token extraction
        access_token = token_data.get("access_token", "")
        print(f"Access token length: {len(access_token)} characters")

        return True

    except Exception as e:
        print(f"❌ Authentication failed: {e}")
        print("\nTroubleshooting:")
        print("- Ensure Keycloak server is running")
        print("- Check environment variables:")
        print(f"  MECAPY_AUTH_ISSUER: {os.getenv('MECAPY_AUTH_ISSUER', 'Not set')}")
        print(f"  MECAPY_AUTH_CLIENT_ID: {os.getenv('MECAPY_AUTH_CLIENT_ID', 'Not set')}")
        return False


if __name__ == "__main__":
    success = test_auth_only()

    if success:
        print("\n🎉 Authentication-only test completed successfully!")
    else:
        print("\n❌ Authentication test failed")
        sys.exit(1)
