"""
Entra ID-First Registration Function
This function creates a user in Entra ID and then creates a corresponding record in the database,
handling different payload requirements based on user_role
"""

import logging
import json
import hashlib
import requests
from msal import ConfidentialClientApplication
import azure.functions as func
from pymongo import MongoClient
import os

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing Entra ID-first user registration request.")
    
    # Get Azure AD configuration from app settings
    tenant_id = os.environ["AZ_TENANT_ID"]
    client_id = os.environ["AZ_CLIENT_ID"]
    client_secret = os.environ["AZ_CLIENT_SECRET"]
    graph_api_scope = ["https://graph.microsoft.com/.default"]
    graph_api_endpoint = "https://graph.microsoft.com/v1.0/users"
    
    # Database configuration
    cosmos_db_connection_string = os.environ["COSMOS_DB_CONNECTION_STRING"]
    database_name = os.environ.get("DATABASE_NAME", "UserDatabase")
    container_name = os.environ.get("CONTAINER_NAME", "Users")
    
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
            # For restaurant, we need more fields but accept minimal fields for Entra ID registration
            required_fields = ["password"]
            if "ownerEmail" in req_body:
                email_field = "ownerEmail"
                if "ownerName" in req_body:
                    name_field = "ownerName"
                else:
                    name_field = "displayName"  # Fallback to displayName
            else:
                if "email" in req_body:
                    email_field = "email"
                else:
                    return func.HttpResponse(
                        json.dumps({"error": "Missing email field for user registration"}),
                        status_code=400,
                        mimetype="application/json"
                    )
                if "fullname" in req_body:
                    name_field = "fullname"
                elif "displayName" in req_body:
                    name_field = "displayName"
                else:
                    return func.HttpResponse(
                        json.dumps({"error": "Missing name field (fullname or displayName) for user registration"}),
                        status_code=400,
                        mimetype="application/json"
                    )
        else:  # customer
            required_fields = ["password"]
            # Determine which fields to use for email and name
            if "email" in req_body:
                email_field = "email"
            else:
                return func.HttpResponse(
                    json.dumps({"error": "Missing email field for user registration"}),
                    status_code=400,
                    mimetype="application/json"
                )
                
            if "fullname" in req_body:
                name_field = "fullname"
            elif "displayName" in req_body:
                name_field = "displayName"
            else:
                return func.HttpResponse(
                    json.dumps({"error": "Missing name field (fullname or displayName) for user registration"}),
                    status_code=400,
                    mimetype="application/json"
                )
        
        # Check for required fields
        if not all(field in req_body for field in required_fields):
            missing_fields = [field for field in required_fields if field not in req_body]
            return func.HttpResponse(
                json.dumps({"error": f"Missing required fields: {', '.join(missing_fields)}"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Extract email and name from the appropriate fields
        user_email = req_body[email_field]
        display_name = req_body[name_field]
        
        # Ensure email has domain suffix
        if "@" not in user_email:
            return func.HttpResponse(
                json.dumps({"error": "Email must include a domain (e.g., user@example.com)"}),
                status_code=400,
                mimetype="application/json"
            )
        
        # Extract username part (before the @)
        username = user_email.split("@")[0]
        
        # Create the userPrincipalName with your verified domain
        user_principal_name = f"{username}@{verified_domain}"
        
        # Split name for given name and surname
        name_parts = display_name.split(" ", 1)
        given_name = name_parts[0]
        surname = name_parts[1] if len(name_parts) > 1 else ""
            
        # Prepare Entra ID user data
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
        
        # Log configuration info
        logging.info(f"Using tenant ID: {tenant_id}")
        logging.info(f"Using client ID: {client_id}")
        logging.info(f"Using userPrincipalName: {user_principal_name}")
        logging.info(f"User role: {req_body['user_role']}")
        
        # Authenticate with Azure AD using MSAL
        app = ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret
        )
        
        # Acquire a token for Microsoft Graph API
        token_result = app.acquire_token_for_client(scopes=graph_api_scope)
        
        if "access_token" not in token_result:
            logging.error(f"Failed to acquire access token. Error: {token_result.get('error')}")
            logging.error(f"Error description: {token_result.get('error_description')}")
            return func.HttpResponse(
                json.dumps({"error": f"Authentication with Azure AD failed: {token_result.get('error_description')}"}),
                status_code=500,
                mimetype="application/json"
            )
        
        logging.info("Successfully acquired token. Making Graph API request...")
        
        # Make a POST request to Microsoft Graph API to create the user
        headers = {
            "Authorization": f"Bearer {token_result['access_token']}",
            "Content-Type": "application/json"
        }
        
        entra_response = requests.post(graph_api_endpoint, headers=headers, json=entra_id_user_data)
        
        # Handle the response from Microsoft Graph API
        if entra_response.status_code == 201:
            # Extract the created user data
            created_user = entra_response.json()
            entra_id = created_user.get("id")
            
            # Now, create the user in the database
            logging.info("Creating user record in database...")
            
            # Hash the password for database storage
            hashed_password = hashlib.sha256(req_body["password"].encode()).hexdigest()
            
            # Connect to Cosmos DB
            client = MongoClient(
                cosmos_db_connection_string,
                socketTimeoutMS=60000,
                connectTimeoutMS=60000
            )
            database = client[database_name]
            container = database[container_name]
            
            # Check if the user already exists in the database
            existing_user = container.find_one({"email": user_email})
            if existing_user:
                logging.info(f"User with email {user_email} already exists in database, updating with Entra ID")
                
                # Update existing user with Entra ID information
                container.update_one(
                    {"email": user_email},
                    {"$set": {
                        "entraId": entra_id,
                        "userPrincipalName": user_principal_name,
                        "user_role": req_body["user_role"]
                    }}
                )
                database_id = str(existing_user.get("_id"))
            else:
                # Create a new user in the database based on role
                if req_body["user_role"] == "restaurant":
                    # For restaurants, use a complete data structure
                    user_data = {
                        "address": req_body.get("address", ""),
                        "businessEmail": req_body.get("businessEmail", user_email),
                        "email": user_email,  # Consistent field for all users
                        "ownerEmail": user_email,
                        "ownerName": display_name,
                        "fullname": display_name,  # Consistent field for all users
                        "password": hashed_password,
                        "phoneNumber": req_body.get("phoneNumber", ""),
                        "restaurantName": req_body.get("restaurantName", f"{display_name}'s Restaurant"),
                        "userType": "restaurant",
                        "user_role": "restaurant",
                        "entraId": entra_id,
                        "userPrincipalName": user_principal_name
                    }
                else:  # customer
                    # For customers, use a simpler data structure
                    user_data = {
                        "email": user_email,
                        "fullname": display_name,
                        "password": hashed_password,
                        "phoneNumber": req_body.get("phoneNumber", ""),
                        "userType": "customer",
                        "user_role": "customer",
                        "entraId": entra_id,
                        "userPrincipalName": user_principal_name
                    }
                
                result = container.insert_one(user_data)
                database_id = str(result.inserted_id)
            
            # Prepare response with user data and tokens
            response_data = {
                "message": "User registered successfully",
                "userId": entra_id,
                "databaseId": database_id,
                "userPrincipalName": user_principal_name,
                "displayName": display_name,
                "user_role": req_body["user_role"],
                "token": {
                    "access_token": token_result.get("access_token"),
                    "token_type": token_result.get("token_type", "Bearer"),
                    "expires_in": token_result.get("expires_in"),
                    "ext_expires_in": token_result.get("ext_expires_in")
                }
            }
            
            return func.HttpResponse(
                json.dumps(response_data),
                status_code=201,
                mimetype="application/json"
            )
        else:
            logging.error(f"Graph API error: {entra_response.status_code} - {entra_response.text}")
            return func.HttpResponse(
                json.dumps({"error": f"Failed to register user: {entra_response.text}"}),
                status_code=entra_response.status_code,
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