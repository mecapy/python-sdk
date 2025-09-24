# Authentication Testing Scripts

This directory contains scripts to test the OAuth2 + PKCE authentication flow interactively.

## Scripts Available

### 1. `test_auth_only.py`
Tests only the authentication flow without making API calls.

```bash
# Test with default production URLs
python tests/test_auth_only.py

# Test with local development environment
MECAPY_AUTH_ISSUER=http://localhost:8080/realms/mecapy python tests/test_auth_only.py
```

**Use case**: Test authentication when Keycloak is running but API server is not.

### 2. `test_interactive_auth.py`
Tests both authentication and API calls.

```bash
# Test with environment variables
MECAPY_AUTH_ISSUER=http://localhost:8080/realms/mecapy \
MECAPY_API_URL=http://localhost:8000 \
python tests/test_interactive_auth.py

# Clear stored token and re-authenticate
python tests/test_interactive_auth.py --clear
```

**Use case**: Full integration test when both Keycloak and API servers are running.

## Prerequisites

### For Local Development
1. **Keycloak server running**:
   ```bash
   # Start Keycloak (example with Docker)
   docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
     quay.io/keycloak/keycloak:latest start-dev
   ```

2. **API server running**:
   ```bash
   cd repos/api
   ENV_FILE=dev/env.local uv run uvicorn mecapy_api.main:app --reload
   ```

3. **Environment variables**:
   ```bash
   export MECAPY_AUTH_ISSUER=http://localhost:8080/realms/mecapy
   export MECAPY_API_URL=http://localhost:8000
   ```

### For Production Testing
1. Set production environment variables or use defaults
2. Ensure you have access to the production Keycloak and API

## Authentication Flow

1. **First run**: Browser opens for OAuth2 authentication
2. **Login**: Enter credentials in the browser
3. **Token storage**: Token is stored in system keyring
4. **Subsequent runs**: Uses stored token (no browser needed)

## Troubleshooting

### Error: "No module named 'mecapy'"
Make sure you're running from the SDK root directory:
```bash
cd repos/python-sdk
python tests/test_auth_only.py
```

### Error: "404 Client Error: Not Found for url"
Check that:
- Keycloak server is running
- `MECAPY_AUTH_ISSUER` points to the correct URL
- The realm exists in Keycloak

### Error: "Authentication failed"
Check that:
- Browser opened successfully
- You completed the login flow
- Your user has the necessary permissions

### Clear Stored Token
If you need to re-authenticate:
```bash
python tests/test_interactive_auth.py --clear
```

Or manually:
```python
import keyring
keyring.delete_password("MecaPy", "token")
```

## Integration with Production Tests

Once authentication is successful, you can run production tests:

```bash
# After successful authentication
pytest -m production
```

The production tests will use the stored token automatically.