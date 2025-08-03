#!/usr/bin/env python3
"""
Example usage of MecaPy SDK.

This example demonstrates the main features of the SDK including:
- Authentication with Keycloak
- Getting user information
- Uploading files
- Error handling
"""

import asyncio
from pathlib import Path
from dotenv import load_dotenv

from mecapy_sdk import MecaPyClient
from mecapy_sdk.auth import KeycloakAuth
from mecapy_sdk.exceptions import (
    AuthenticationError,
    ValidationError,
    NotFoundError,
    NetworkError
)

# Load environment variables from .env file
load_dotenv()


async def basic_example():
    """Basic usage example."""
    print("=== Basic Example ===")
    
    try:
        # Create client from environment variables
        async with MecaPyClient.from_env() as client:
            # Check API health
            health = await client.health_check()
            print(f"API Health: {health}")
            
            # Get API information
            info = await client.get_root()
            print(f"API Version: {info.version}")
            print(f"Status: {info.status}")
            
    except Exception as e:
        print(f"Error in basic example: {e}")


async def authentication_example():
    """Authentication example."""
    print("\n=== Authentication Example ===")
    
    try:
        async with MecaPyClient.from_env() as client:
            if not client.auth:
                print("No authentication configured - skipping auth examples")
                return
            
            # Get current user information
            user = await client.get_current_user()
            print(f"Authenticated as: {user.preferred_username}")
            print(f"Email: {user.email}")
            print(f"Roles: {', '.join(user.roles)}")
            
            # Test protected endpoint
            protected_response = await client.test_protected_route()
            print(f"Protected endpoint: {protected_response.message}")
            
            # Try admin endpoint (might fail if user is not admin)
            try:
                admin_response = await client.test_admin_route()
                print(f"Admin endpoint: {admin_response.message}")
            except AuthenticationError:
                print("Admin access denied (user is not admin)")
                
    except AuthenticationError as e:
        print(f"Authentication failed: {e}")
    except Exception as e:
        print(f"Error in authentication example: {e}")


async def file_upload_example():
    """File upload example."""
    print("\n=== File Upload Example ===")
    
    try:
        async with MecaPyClient.from_env() as client:
            if not client.auth:
                print("Authentication required for file upload - skipping")
                return
            
            # Create a sample ZIP file for testing
            sample_file = Path("sample.zip")
            if not sample_file.exists():
                print("Creating sample ZIP file...")
                import zipfile
                with zipfile.ZipFile(sample_file, 'w') as zf:
                    zf.writestr("hello.txt", "Hello from MecaPy SDK!")
            
            # Upload the file
            print(f"Uploading {sample_file}...")
            result = await client.upload_archive(sample_file)
            
            print(f"Upload successful!")
            print(f"Original filename: {result.original_filename}")
            print(f"Server filename: {result.uploaded_filename}")
            print(f"File size: {result.size} bytes")
            print(f"MD5 hash: {result.md5}")
            
            # Clean up
            sample_file.unlink()
            
    except ValidationError as e:
        print(f"Validation error: {e.message}")
    except AuthenticationError:
        print("Authentication required for file upload")
    except Exception as e:
        print(f"Error in file upload example: {e}")


async def error_handling_example():
    """Error handling example."""
    print("\n=== Error Handling Example ===")
    
    try:
        # Create client with invalid URL to demonstrate error handling
        auth = KeycloakAuth(
            keycloak_url="https://invalid-auth-server.example.com",
            username="invalid-user",
            password="invalid-pass"
        )
        
        async with MecaPyClient("https://invalid-api.example.com", auth=auth) as client:
            await client.get_current_user()
            
    except NetworkError as e:
        print(f"Network error (expected): {e.message}")
    except AuthenticationError as e:
        print(f"Authentication error (expected): {e.message}")
    except Exception as e:
        print(f"Other error: {e}")


async def custom_auth_example():
    """Custom authentication example."""
    print("\n=== Custom Authentication Example ===")
    
    try:
        # Create custom auth configuration
        auth = KeycloakAuth(
            keycloak_url="https://auth.mecapy.com",  # Replace with your Keycloak URL
            realm="mecapy",
            client_id="mecapy-api-public"
        )
        
        # Set credentials (you could also pass them in the constructor)
        # auth.set_credentials("your-username", "your-password")
        
        async with MecaPyClient("https://api.mecapy.com", auth=auth) as client:
            # This will work if you have valid credentials
            print("Custom auth client created successfully")
            # user = await client.get_current_user()
            # print(f"Custom auth user: {user.preferred_username}")
            
    except Exception as e:
        print(f"Custom auth example (credentials needed): {e}")


async def main():
    """Run all examples."""
    print("MecaPy SDK Examples")
    print("==================")
    
    await basic_example()
    await authentication_example()
    await file_upload_example()
    await error_handling_example()
    await custom_auth_example()
    
    print("\n=== Examples Complete ===")
    print("\nTo use authentication features, set these environment variables:")
    print("- MECAPY_USERNAME=your-username")
    print("- MECAPY_PASSWORD=your-password")
    print("\n(SDK uses production URLs by default)")
    print("For on-premise, also set:")
    print("- MECAPY_API_URL=https://your-api.company.com")
    print("- MECAPY_KEYCLOAK_URL=https://your-auth.company.com")


if __name__ == "__main__":
    asyncio.run(main())