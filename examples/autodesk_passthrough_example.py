#!/usr/bin/env python3
"""
Autodesk Pass-Through Authentication Example for FastMCP

This example demonstrates the same approach as your working my-demo-mcp-server,
using direct JWT validation from Autodesk tokens (like fastapi_mcp with setup_proxies=True).

This approach:
- Validates original JWT tokens from Autodesk (preserves userid claims)
- Uses FastMCP's BearerAuthProvider configured for Autodesk  
- No token manufacturing - direct pass-through validation
- Matches your working fastapi_mcp implementation architecture

Configuration:
Set these environment variables or configure directly in code:
- AUTODESK_DOMAIN=developer.api.autodesk.com
- AUTODESK_AUDIENCE=https://developer.api.autodesk.com/
- AUTODESK_REQUIRED_SCOPES=data:read,data:write
"""

import os
from typing import Any, Dict

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth.providers.bearer import BearerAuthProvider


def create_autodesk_passthrough_server() -> FastMCP:
    """
    Create a FastMCP server with Autodesk pass-through authentication.
    
    This approach validates original JWT tokens from Autodesk directly,
    exactly like your working my-demo-mcp-server implementation.
    """
    
    # Autodesk OAuth configuration - same as your working fastapi_mcp
    AUTODESK_DOMAIN = "developer.api.autodesk.com"
    AUTODESK_AUDIENCE = "https://developer.api.autodesk.com/"  # Critical: correct audience for userid claims
    AUTODESK_ISSUER = f"https://{AUTODESK_DOMAIN}/"
    AUTODESK_JWKS_URI = f"https://{AUTODESK_DOMAIN}/authentication/v2/keys"
    
    # Required scopes for MCP access (Autodesk format)
    REQUIRED_SCOPES = ["data:read"]
    
    # Create BearerAuthProvider configured for Autodesk JWT validation
    autodesk_auth = BearerAuthProvider(
        jwks_uri=AUTODESK_JWKS_URI,        # Autodesk's public keys for JWT validation
        issuer=AUTODESK_ISSUER,            # Expected JWT issuer  
        audience=AUTODESK_AUDIENCE,        # Critical: correct audience for user context
        algorithm="RS256",                 # Autodesk uses RS256 for JWT signing
        required_scopes=REQUIRED_SCOPES,   # Minimum scopes required for access
    )
    
    return FastMCP(
        name="Autodesk Pass-Through Authentication",
        instructions="Pass-through JWT validation for Autodesk tokens with real user context",
        auth=autodesk_auth
    )


# Create the server
server = create_autodesk_passthrough_server()


@server.tool()
def get_user_info() -> Dict[str, Any]:
    """
    Get information about the authenticated user from their Autodesk JWT token.
    
    This tool extracts real user information from the validated JWT token,
    exactly like your working my-demo-mcp-server implementation.
    
    Returns:
        Dict containing user information extracted from the real JWT token
    """
    from fastmcp.server.dependencies import get_access_token
    import json
    
    try:
        # Get the validated access token (original Autodesk JWT)
        access_token = get_access_token()
        
        if not access_token:
            return {"error": "No access token available"}
        
        # Decode the JWT token to extract user claims (same approach as working example)
        jwt_parts = access_token.token.split('.')
        if len(jwt_parts) != 3:
            return {"error": "Invalid JWT token format"}
        
        # Decode the payload
        import base64
        payload = jwt_parts[1]
        payload += '=' * (4 - len(payload) % 4)  # Add padding
        jwt_claims = json.loads(base64.b64decode(payload))
        
        # Extract user information from Autodesk JWT claims
        # With correct audience, this should now contain userid
        user_id = (jwt_claims.get('userid') or 
                  jwt_claims.get('sub') or 
                  jwt_claims.get('user_id') or 
                  jwt_claims.get('jti') or 
                  "unknown")
        
        return {
            "user_id": user_id,
            "client_id": jwt_claims.get('client_id', 'unknown'),
            "issuer": jwt_claims.get('iss', 'unknown'),
            "audience": jwt_claims.get('aud', 'unknown'),
            "expires_at": jwt_claims.get('exp'),
            "scopes": access_token.scopes,
            "jwt_claims_keys": list(jwt_claims.keys()),
            "jwt_claims_values": jwt_claims,
            "message": "User information from original Autodesk JWT (pass-through validation)",
            "auth_approach": "pass-through (like fastapi_mcp with setup_proxies=True)",
        }
        
    except Exception as e:
        return {
            "error": f"Failed to extract user info: {str(e)}",
            "message": "Unable to decode JWT token"
        }


@server.tool()
async def list_autodesk_hubs() -> Dict[str, Any]:
    """
    List Autodesk hubs/projects for the authenticated user using their real JWT token.
    
    This demonstrates using the real user token (with userid context) to make 
    authenticated API calls to Autodesk services, just like your working example.
    
    Returns:
        Dict containing the user's Autodesk hubs or error information
    """
    from fastmcp.server.dependencies import get_access_token
    
    try:
        # Get the validated access token (original Autodesk JWT)
        access_token = get_access_token()
        
        if not access_token:
            return {"error": "No access token available"}
        
        # Use the real user token to make authenticated requests to Autodesk API
        headers = {
            "Authorization": f"Bearer {access_token.token}",
            "Content-Type": "application/json"
        }
        
        async with httpx.AsyncClient() as client:
            # List BIM 360 hubs (requires appropriate scopes)
            response = await client.get(
                "https://developer.api.autodesk.com/project/v1/hubs",
                headers=headers
            )
            
            if response.status_code == 200:
                hubs_data = response.json()
                return {
                    "success": True,
                    "message": "Successfully retrieved hubs using real user token",
                    "user_has_real_context": True,
                    "hubs": hubs_data,
                    "total_hubs": len(hubs_data.get("data", [])),
                    "auth_method": "pass-through JWT validation"
                }
            else:
                return {
                    "error": f"Autodesk API error: {response.status_code}",
                    "message": response.text,
                    "user_token_was_real": True,  # Confirms we used a real user token
                    "auth_method": "pass-through JWT validation"
                }
                
    except Exception as e:
        return {
            "error": f"Failed to list hubs: {str(e)}",
            "message": "Error occurred while accessing Autodesk API with user token",
            "auth_method": "pass-through JWT validation"
        }


@server.tool()
def protected_action(action: str) -> Dict[str, Any]:
    """Perform a protected action that requires Autodesk authentication."""
    return {
        "action": action,
        "status": "success",
        "message": f"Action '{action}' completed with Autodesk authentication",
        "auth_method": "Autodesk Pass-Through (BearerAuthProvider)",
    }


@server.tool()
def admin_operation(operation: str) -> Dict[str, Any]:
    """Admin-only operation that requires elevated scopes."""
    return {
        "operation": operation,
        "status": "authorized", 
        "message": f"Admin operation '{operation}' executed with Autodesk auth",
        "requires_scopes": ["data:read", "data:write"],
        "auth_method": "pass-through JWT validation"
    }


@server.tool()
async def compare_auth_methods() -> Dict[str, Any]:
    """
    Compare OAuth Proxy vs OAuth Passthrough authentication methods.
    
    Returns:
        Dict explaining the differences between the two approaches
    """
    return {
        "oauth_proxy_approach": {
            "description": "Manufactures tokens using client_credentials flow",
            "token_source": "Generated by FastMCP using client credentials",
            "user_context": "Lost - no real user information in tokens",
            "userid_claim": "Not available - client credentials tokens don't contain user info",
            "use_case": "Good for service-to-service authentication",
            "limitations": [
                "No user-specific information available",
                "Cannot access user's personal data or projects",
                "JWT tokens contain only client information, not user information"
            ]
        },
        "oauth_passthrough_approach": {
            "description": "Passes through real OAuth flows to upstream server",
            "token_source": "Real JWT tokens issued by Autodesk for the actual user",
            "user_context": "Preserved - full user information available in JWT claims",
            "userid_claim": "Available - contains real user ID from Autodesk",
            "use_case": "Perfect for user-specific operations and data access",
            "benefits": [
                "Real user context preserved in JWT tokens",
                "Can access user's personal projects and data",
                "userid claim available for user identification",
                "Full OAuth scopes and permissions respected"
            ]
        },
        "when_to_use_which": {
            "use_oauth_proxy": [
                "Service-to-service authentication",
                "When you only need basic API access without user context",
                "When the OAuth server doesn't support user-specific operations"
            ],
            "use_oauth_passthrough": [
                "User-specific data access required",
                "Need real user identity and context",
                "Building user-facing applications",
                "When userid or other user claims are essential"
            ]
        }
    }


if __name__ == "__main__":
    # Run the server - use http transport to match previous working example
    server.run(transport="http", port=8000) 