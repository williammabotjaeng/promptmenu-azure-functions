"""
Database-First Registration Function
This function creates a user in the Cosmos DB and then registers them in Entra ID,
using different payload requirements based on user_role
"""

import logging
import hashlib
import json
import requests
from msal import ConfidentialClientApplication
import azure.functions as func
from pymongo import MongoClient
import os

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing HTTP request for database-first user registration.')
    
    # Load environment variables
    cosmos_db_connection_string = os.environ["COSMOS_DB_CONNECTION_STRING"]
    database_name = os.environ.get("DATABASE_NAME", "UserDatabase")
    container_name = os.environ.get("CONTAINER_NAME", "Users")
    
    # Get Azure AD configuration from app settings
    tenant_id = os.environ["AZ_TENANT_ID"]
    client_id = os.environ["AZ_CLIENT_ID"]
    client_secret = os.environ["AZ_CLIENT_SECRET"]
    graph_api_scope = ["https://graph.microsoft.com/.default"]
    graph_api_endpoint = "https://graph.microsoft.com/v1.0/users"
    
    # Your verified domain from Azure AD
    verified_domain = "infotheappspaza.onmicrosoft.com"
    
    try:
        # Parse the request body
        req_body = req.get_json()
        
        # Check for user_role field first
        if "user_role" not in req_body:
            return func.HttpResponse(
                json.dumps({"error": "Missing user_role field. Must be 'restaurant' or 'customer'"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Validate user_role value
        if req_body["user_role"] not in ["restaurant", "customer"]:
            return func.HttpResponse(
                json.dumps({"error": "user_role must be either 'restaurant' or 'customer'"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Different required fields based on user role
        if req_body["user_role"] == "restaurant":
            required_fields = [
                "address", "businessEmail", "ownerEmail", "ownerName",
                "password", "phoneNumber", "restaurantName"
            ]
        else:  # customer
            required_fields = ["fullname", "email", "password"]
        
        # Validate required fields
        if not all(field in req_body for field in required_fields):
            missing_fields = [field for field in required_fields if field not in req_body]
            logging.error(f"Missing fields for {req_body['user_role']}: {missing_fields}")
            return func.HttpResponse(
                json.dumps({"error": f"Missing fields for {req_body['user_role']}: {', '.join(missing_fields)}"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Hash the password for database storage
        hashed_password = hashlib.sha256(req_body["password"].encode()).hexdigest()
        
        # Connect to Cosmos DB
        logging.info("Connecting to Cosmos DB (MongoDB API)...")
        client = MongoClient(
            cosmos_db_connection_string,
            socketTimeoutMS=60000,
            connectTimeoutMS=60000
        )
        database = client[database_name]
        container = database[container_name]
        
        # Get email based on role
        if req_body["user_role"] == "restaurant":
            user_email = req_body["ownerEmail"]
            display_name = req_body["ownerName"]
            # Split name for given name and surname
            name_parts = display_name.split(" ", 1)
            given_name = name_parts[0]
            surname = name_parts[1] if len(name_parts) > 1 else ""
        else:  # customer
            user_email = req_body["email"]
            display_name = req_body["fullname"]
            # Split name for given name and surname
            name_parts = display_name.split(" ", 1)
            given_name = name_parts[0]
            surname = name_parts[1] if len(name_parts) > 1 else ""
        
        # Check if user already exists in database
        existing_user = container.find_one({"email": user_email})
        if existing_user:
            return func.HttpResponse(
                json.dumps({"error": "A user with this email already exists in the database"}),
                status_code=409,
                mimetype="application/json"
            )
        
        # Prepare user data for Entra ID registration
        username = user_email.split("@")[0]
        user_principal_name = f"{username}@{verified_domain}"
            
        # Now register the user in Entra ID
        logging.info("Registering user in Entra ID...")
        
        # Prepare the user data for Entra ID
        entra_id_user_data = {
            "accountEnabled": True,
            "displayName": display_name,
            "givenName": given_name,
            "surname": surname,
            "mailNickname": username,
            "userPrincipalName": user_principal_name,
            "mail": user_email,
            "passwordProfile": {
                "forceChangePasswordNextSignIn": False,
                "password": req_body["password"]
            }
            # Note: We can't add custom extension attributes without first registering them
            # "extension_USER_ROLE": req_body["user_role"]
        }
        
        # Authenticate with Azure AD using MSAL
        app = ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret
        )
        
        # Acquire a token for Microsoft Graph API
        token_result = app.acquire_token_for_client(scopes=graph_api_scope)
        
        entra_id = None
        if "access_token" not in token_result:
            logging.error(f"Failed to acquire access token. Error: {token_result.get('error')}")
            logging.error(f"Error description: {token_result.get('error_description')}")
            
            # Since we couldn't register in Entra ID, we'll still create the user in the database
            logging.info("Proceeding with database-only registration...")
        else:
            # We have a token, try to create the user in Entra ID
            headers = {
                "Authorization": f"Bearer {token_result['access_token']}",
                "Content-Type": "application/json"
            }
            
            entra_id_response = requests.post(graph_api_endpoint, headers=headers, json=entra_id_user_data)
            
            # Check if user was created successfully in Entra ID
            if entra_id_response.status_code == 201:
                created_user = entra_id_response.json()
                entra_id = created_user.get("id")
                logging.info(f"User created in Entra ID with ID: {entra_id}")
            else:
                logging.error(f"Failed to create user in Entra ID: {entra_id_response.status_code} - {entra_id_response.text}")
                # Continue with database registration anyway
        
        # Prepare the user data for database based on role
        if req_body["user_role"] == "restaurant":
            user_data = {
                "address": req_body["address"],
                "businessEmail": req_body["businessEmail"],
                "email": req_body["ownerEmail"],  # Consistent email field for all users
                "ownerEmail": req_body["ownerEmail"],
                "ownerName": req_body["ownerName"],
                "fullname": req_body["ownerName"],  # Consistent fullname field for all users
                "password": hashed_password,
                "phoneNumber": req_body["phoneNumber"],
                "restaurantName": req_body["restaurantName"],
                "userType": "restaurant",
                "user_role": "restaurant",
                "entraId": entra_id,
                "userPrincipalName": user_principal_name if entra_id else None
            }
        else:  # customer
            user_data = {
                "email": req_body["email"],
                "fullname": req_body["fullname"],
                "password": hashed_password,
                "userType": "customer",
                "user_role": "customer",
                "entraId": entra_id,
                "userPrincipalName": user_principal_name if entra_id else None
            }
        
        # Insert the user data into Cosmos DB
        logging.info("Inserting user data into Cosmos DB...")
        result = container.insert_one(user_data)
        
        # Prepare response
        response_data = {
            "message": "User registration successful",
            "databaseId": str(result.inserted_id),
            "user_role": req_body["user_role"],
            "entraIdStatus": "Success" if entra_id else "Failed or Skipped"
        }
        
        # Include token and entra ID if available
        if entra_id:
            response_data["entraId"] = entra_id
            
        if "access_token" in token_result:
            response_data["token"] = {
                "access_token": token_result.get("access_token"),
                "token_type": token_result.get("token_type", "Bearer"),
                "expires_in": token_result.get("expires_in"),
                "ext_expires_in": token_result.get("ext_expires_in")
            }
        
        return func.HttpResponse(
            json.dumps(response_data),
            status_code=201,
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
        logging.error(f"Unexpected error: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"An unexpected error occurred: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )