import logging
import json
import requests
from msal import ConfidentialClientApplication
import azure.functions as func

# Azure AD B2C Configuration
TENANT_ID = "YOUR_TENANT_ID"  # Replace with your Azure AD B2C Tenant ID
CLIENT_ID = "YOUR_CLIENT_ID"  # Replace with your Azure AD B2C Application (Client) ID
CLIENT_SECRET = "YOUR_CLIENT_SECRET"  # Replace with your Azure AD B2C Client Secret
GRAPH_API_SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH_API_ENDPOINT = "https://graph.microsoft.com/v1.0/users"

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing user registration request.")

    try:
        # Parse the request body
        req_body = req.get_json()
        required_fields = ["displayName", "givenName", "surname", "email", "password"]

        # Validate required fields
        if not all(field in req_body for field in required_fields):
            return func.HttpResponse(
                "Missing required fields in the payload.",
                status_code=400
            )

        # Prepare the user data for registration
        user_data = {
            "accountEnabled": True,
            "displayName": req_body["displayName"],
            "givenName": req_body["givenName"],
            "surname": req_body["surname"],
            "userPrincipalName": req_body["email"],
            "passwordProfile": {
                "forceChangePasswordNextSignIn": False,
                "password": req_body["password"]
            }
        }

        # Authenticate with Azure AD B2C using MSAL
        app = ConfidentialClientApplication(
            CLIENT_ID,
            authority=f"https://login.microsoftonline.com/{TENANT_ID}",
            client_credential=CLIENT_SECRET
        )

        # Acquire a token for Microsoft Graph API
        result = app.acquire_token_for_client(scopes=GRAPH_API_SCOPE)
        if "access_token" not in result:
            logging.error("Failed to acquire access token.")
            return func.HttpResponse(
                "Authentication with Azure AD B2C failed.",
                status_code=500
            )

        # Make a POST request to Microsoft Graph API to create the user
        headers = {
            "Authorization": f"Bearer {result['access_token']}",
            "Content-Type": "application/json"
        }
        response = requests.post(GRAPH_API_ENDPOINT, headers=headers, json=user_data)

        # Handle the response from Microsoft Graph API
        if response.status_code == 201:
            return func.HttpResponse(
                json.dumps({"message": "User registered successfully."}),
                status_code=201,
                mimetype="application/json"
            )
        else:
            logging.error(f"Graph API error: {response.status_code} - {response.text}")
            return func.HttpResponse(
                f"Failed to register user: {response.text}",
                status_code=response.status_code
            )

    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return func.HttpResponse(
            "An unexpected error occurred.",
            status_code=500
        )