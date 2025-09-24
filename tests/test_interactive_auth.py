#!/usr/bin/env python3
"""Interactive authentication test script.

This script allows you to test the OAuth2 + PKCE authentication flow interactively.
It will open a browser window for authentication and store the token for later use.

Usage:
    python tests/test_interactive_auth.py

Requirements:
    - Keycloak server running on configured URL
    - API server running on configured URL
    - Browser available for authentication
"""

import os
import sys
from pathlib import Path

# Add the package to path for direct script execution
sys.path.insert(0, str(Path(__file__).parent.parent))

from mecapy_sdk.auth import MecapySdkAuth
from mecapy_sdk.config import config as conf


def test_interactive_authentication():
    """Test interactive OAuth2 + PKCE authentication flow."""
    print("=== MecaPy SDK Interactive Authentication Test ===")
    print(f"Auth Issuer: {conf.auth.issuer}")
    print(f"API URL: {conf.api_url}")
    print()

    try:
        print("1. Initializing authentication...")
        auth = MecapySdkAuth()
        auth.logout()

        print("2. Getting session (will trigger browser authentication if needed)...")
        session = auth.get_session()
        print("✅ Authentication successful!")

        print("3. Testing API call to /auth/me...")
        resp = session.get(f"{conf.api_url}/auth/me")

        if resp.status_code == 200:
            user_info = resp.json()
            print("✅ API call successful!")
            print(f"Authenticated as: {user_info.get('preferred_username', 'Unknown')}")
            print(f"Email: {user_info.get('email', 'Not provided')}")
            print(f"Roles: {user_info.get('roles', [])}")
        else:
            print(f"❌ API call failed: {resp.status_code}")
            print(f"Response: {resp.text}")

    except Exception as e:
        print(f"❌ Authentication failed: {e}")
        print("\nTroubleshooting:")
        print("- Ensure Keycloak server is running")
        print("- Ensure API server is running")
        print("- Check environment variables:")
        print(f"  MECAPY_AUTH_ISSUER: {os.getenv('MECAPY_AUTH_ISSUER', 'Not set')}")
        print(f"  MECAPY_API_URL: {os.getenv('MECAPY_API_URL', 'Not set')}")
        return False

    return True


def clear_stored_token():
    """Clear any stored authentication token."""
    try:
        import keyring
        keyring.delete_password("MecaPy", "token")
        print("✅ Stored token cleared")
    except Exception as e:
        print(f"No stored token to clear or error: {e}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Interactive authentication test")
    parser.add_argument("--clear", action="store_true", help="Clear stored token before testing")
    args = parser.parse_args()

    if args.clear:
        clear_stored_token()
        print()

    success = test_interactive_authentication()

    if success:
        print("\n🎉 Authentication test completed successfully!")
        print("You can now run: pytest -m production")
    else:
        print("\n❌ Authentication test failed")
        sys.exit(1)