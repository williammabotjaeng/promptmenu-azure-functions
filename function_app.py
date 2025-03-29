"""
Azure Functions App with v2 programming model
Contains register_users_ms function
"""

import logging
import json
import os
import requests
from msal import ConfidentialClientApplication
import azure.functions as func

# Import helper functions
from helpers import load_env_variables

# Create the FunctionApp instance
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="register-users-db", methods=["POST"])
def register_users_db(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing user registration request via Microsoft Graph API.")
    
    try:
        # Load environment variables
        load_env_variables()
            
        # Get Azure AD configuration from app settings
        tenant_id = os.environ.get("AZ_TENANT_ID")
        client_id = os.environ.get("AZ_CLIENT_ID")
        client_secret = os.environ.get("AZ_CLIENT_SECRET")
        
        # Check for missing required configuration
        missing_config = []
        if not tenant_id:
            missing_config.append("AZ_TENANT_ID")
        if not client_id:
            missing_config.append("AZ_CLIENT_ID")
        if not client_secret:
            missing_config.append("AZ_CLIENT_SECRET")
            
        if missing_config:
            error_message = f"Missing required configuration: {', '.join(missing_config)}"
            logging.error(error_message)
            return func.HttpResponse(
                json.dumps({"error": error_message}),
                status_code=500,
                mimetype="application/json"
            )
            
        # Constants
        graph_api_scope = ["https://graph.microsoft.com/.default"]
        graph_api_endpoint = "https://graph.microsoft.com/v1.0/users"
        
        # Parse the request body
        req_body = req.get_json()
        required_fields = ["displayName", "givenName", "surname", "email", "password"]
        
        # Validate required fields
        if not all(field in req_body for field in required_fields):
            missing_fields = [field for field in required_fields if field not in req_body]
            error_message = f"Missing required fields: {', '.join(missing_fields)}"
            return func.HttpResponse(
                json.dumps({"error": error_message}),
                status_code=400,
                mimetype="application/json"
            )
            
        # Extract email domain part
        email = req_body["email"]
        if "@" not in email:
            return func.HttpResponse(
                json.dumps({"error": "Email must include a domain (e.g., user@example.com)"}),
                status_code=400,
                mimetype="application/json"
            )
            
        # Extract username part (before the @)
        username = email.split("@")[0]
        
        # Your verified domain from Azure AD
        verified_domain = "infotheappspaza.onmicrosoft.com"
        
        # Create the userPrincipalName with your verified domain
        user_principal_name = f"{username}@{verified_domain}"
        
        # Prepare the user data for registration
        user_data = {
            "accountEnabled": True,
            "displayName": req_body["displayName"],
            "givenName": req_body["givenName"],
            "surname": req_body["surname"],
            "mailNickname": username,
            "userPrincipalName": user_principal_name,
            "mail": req_body["email"],
            "passwordProfile": {
                "forceChangePasswordNextSignIn": False,
                "password": req_body["password"]
            }
        }
        
        # Authenticate with Azure AD using MSAL
        app = ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret
        )
        
        # Acquire a token for Microsoft Graph API
        result = app.acquire_token_for_client(scopes=graph_api_scope)
        
        if "access_token" not in result:
            logging.error(f"Failed to acquire access token. Error: {result.get('error')}")
            logging.error(f"Error description: {result.get('error_description')}")
            return func.HttpResponse(
                json.dumps({"error": "Authentication with Azure AD failed"}),
                status_code=500,
                mimetype="application/json"
            )
            
        # Make a POST request to Microsoft Graph API to create the user
        headers = {
            "Authorization": f"Bearer {result['access_token']}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(graph_api_endpoint, headers=headers, json=user_data)
        
        # Handle the response from Microsoft Graph API
        if response.status_code == 201:
            user_response = response.json()
            
            # Get token for the newly created user (optional - for auto-login after registration)
            try:
                # Get a token for the user to auto-login
                user_token = app.acquire_token_by_username_password(
                    username=user_principal_name,
                    password=req_body["password"],
                    scopes=graph_api_scope
                )
                
                if "access_token" in user_token:
                    return func.HttpResponse(
                        json.dumps({
                            "message": "User registered successfully",
                            "userId": user_response.get("id"),
                            "userPrincipalName": user_principal_name,
                            "displayName": req_body["displayName"],
                            "token": {
                                "access_token": user_token.get("access_token"),
                                "token_type": user_token.get("token_type", "Bearer"),
                                "expires_in": user_token.get("expires_in")
                            }
                        }),
                        status_code=201,
                        mimetype="application/json"
                    )
                else:
                    # Registration succeeded but auto-login failed
                    return func.HttpResponse(
                        json.dumps({
                            "message": "User registered successfully, but automatic login failed",
                            "userId": user_response.get("id"),
                            "userPrincipalName": user_principal_name,
                            "displayName": req_body["displayName"]
                        }),
                        status_code=201,
                        mimetype="application/json"
                    )
            except Exception as token_error:
                # Registration succeeded but token acquisition failed
                logging.warning(f"User registered but token acquisition failed: {str(token_error)}")
                return func.HttpResponse(
                    json.dumps({
                        "message": "User registered successfully",
                        "userId": user_response.get("id"),
                        "userPrincipalName": user_principal_name,
                        "displayName": req_body["displayName"]
                    }),
                    status_code=201,
                    mimetype="application/json"
                )
        else:
            logging.error(f"Graph API error: {response.status_code} - {response.text}")
            return func.HttpResponse(
                json.dumps({
                    "error": f"Failed to register user", 
                    "details": response.text
                }),
                status_code=response.status_code,
                mimetype="application/json"
            )
            
    except ValueError as ve:
        logging.error(f"Invalid request body: {str(ve)}")
        return func.HttpResponse(
            json.dumps({"error": "Invalid request format. Please provide a valid JSON body."}),
            status_code=400,
            mimetype="application/json"
        )
    except Exception as e:
        logging.error(f"Unexpected error during MS registration: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"An unexpected error occurred: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )