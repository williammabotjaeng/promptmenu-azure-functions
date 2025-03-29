"""
Azure Functions App with v2 programming model
Contains all functions in a single file
"""

import logging
import json
import hashlib
import asyncio
import requests
from msal import ConfidentialClientApplication
import azure.functions as func
from azure.identity import ClientSecretCredential
from msgraph_core.authentication import AzureIdentityAuthenticationProvider
from msgraph_core import BaseGraphRequestAdapter
from kiota_abstractions.request_information import RequestInformation
from kiota_abstractions.api_error import APIError
from pymongo import MongoClient
import os

# Create the FunctionApp instance
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

###################
# HELPER FUNCTIONS
###################

# Helper function to get Entra ID token
def get_entra_id_token(tenant_id, client_id, client_secret, username, password):
    try:
        # Setup MSAL client
        app = ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret
        )
        
        # Get token
        scopes = ["https://graph.microsoft.com/.default"]
        
        # Try client credentials flow if no password (for service-to-service)
        if not password:
            result = app.acquire_token_for_client(scopes=scopes)
        else:
            # Use username/password flow
            result = app.acquire_token_by_username_password(
                username=username,
                password=password,
                scopes=scopes
            )
        
        if "access_token" in result:
            return result
        else:
            logging.error(f"Failed to get Entra ID token: {result.get('error')}")
            logging.error(f"Error description: {result.get('error_description')}")
            return None
    except Exception as e:
        logging.error(f"Error getting Entra ID token: {str(e)}")
        return None

# Helper function to try Entra ID login
def try_entra_id_login(tenant_id, client_id, client_secret, db_user, password):
    user_principal_name = db_user.get("userPrincipalName")
    
    if not user_principal_name:
        return func.HttpResponse(
            json.dumps({"error": "User does not have Entra ID credentials"}),
            status_code=401,
            mimetype="application/json"
        )
    
    token_result = get_entra_id_token(tenant_id, client_id, client_secret, user_principal_name, password)
    
    if token_result and "access_token" in token_result:
        logging.info("Entra ID authentication successful")
        response_data = prepare_success_response(db_user, token_result)
        return func.HttpResponse(
            json.dumps(response_data),
            status_code=200,
            mimetype="application/json"
        )
    else:
        return func.HttpResponse(
            json.dumps({"error": "Invalid email or password"}),
            status_code=401,
            mimetype="application/json"
        )

# Helper function to get user details from Microsoft Graph
def get_user_from_graph(access_token):
    try:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        response = requests.get(
            "https://graph.microsoft.com/v1.0/me",
            headers=headers
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            logging.error(f"Error getting user details: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        logging.error(f"Error in Graph API call: {str(e)}")
        return None

# Helper function to create user in database
def create_user_in_database(container, user_details, password):
    try:
        # Extract basic user info
        entra_id = user_details.get("id")
        user_principal_name = user_details.get("userPrincipalName")
        display_name = user_details.get("displayName")
        email = user_details.get("mail") or user_details.get("userPrincipalName")
        
        # Hash password if provided
        hashed_password = None
        if password:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        # Determine user role (default to customer)
        user_role = "customer"
        
        # Create user document
        user_data = {
            "email": email,
            "fullname": display_name,
            "password": hashed_password,
            "userType": user_role,
            "user_role": user_role,
            "entraId": entra_id,
            "userPrincipalName": user_principal_name,
            "createdFromEntraId": True
        }
        
        # Insert the user
        result = container.insert_one(user_data)
        
        # Add the _id to the user data for the response
        user_data["_id"] = str(result.inserted_id)
        
        return user_data
    except Exception as e:
        logging.error(f"Error creating user in database: {str(e)}")
        return None

# Helper to prepare success response
def prepare_success_response(db_user, token_result):
    response_data = {
        "message": "Login successful",
        "user": {
            "id": str(db_user.get("_id")),
            "email": db_user.get("email"),
            "fullname": db_user.get("fullname"),
            "user_role": db_user.get("user_role", "customer"),
        }
    }
    
    # Add restaurant-specific fields if applicable
    if db_user.get("user_role") == "restaurant":
        response_data["user"]["restaurantName"] = db_user.get("restaurantName")
        response_data["user"]["businessEmail"] = db_user.get("businessEmail")
        response_data["user"]["address"] = db_user.get("address")
        response_data["user"]["phoneNumber"] = db_user.get("phoneNumber")
    
    # Add token information if available
    if token_result and "access_token" in token_result:
        response_data["token"] = {
            "access_token": token_result.get("access_token"),
            "token_type": token_result.get("token_type", "Bearer"),
            "expires_in": token_result.get("expires_in"),
            "ext_expires_in": token_result.get("ext_expires_in")
        }
    
    return response_data

###################
# MAIN FUNCTIONS
###################

@app.function_name(name="register-users-db")
@app.route(route="register-users-db", auth_level=func.AuthLevel.FUNCTION, methods=["POST"])
def register_users_db(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing Entra ID-first user registration request.")
    
    try:
        # Try to import dotenv and load from .env file
        try:
            from dotenv import load_dotenv
            load_dotenv()
            logging.info("Loaded environment variables from .env file")
        except ImportError:
            logging.info("python-dotenv not installed, using environment variables directly")
        except Exception as e:
            logging.warning(f"Could not load .env file: {str(e)}")
        
        # Get required configuration with fallbacks to handle missing values gracefully
        tenant_id = os.environ.get("AZ_TENANT_ID")
        client_id = os.environ.get("AZ_CLIENT_ID")
        client_secret = os.environ.get("AZ_CLIENT_SECRET")
        cosmos_db_connection_string = os.environ.get("COSMOS_DB_CONNECTION_STRING")
        
        # Check for missing required configuration
        missing_config = []
        if not tenant_id:
            missing_config.append("AZ_TENANT_ID")
        if not client_id:
            missing_config.append("AZ_CLIENT_ID")
        if not client_secret:
            missing_config.append("AZ_CLIENT_SECRET")
        if not cosmos_db_connection_string:
            missing_config.append("COSMOS_DB_CONNECTION_STRING")
            
        if missing_config:
            error_message = f"Missing required configuration: {', '.join(missing_config)}"
            logging.error(error_message)
            return func.HttpResponse(
                json.dumps({"error": error_message}),
                status_code=500,
                mimetype="application/json"
            )
        
        # Database configuration
        database_name = os.environ.get("DATABASE_NAME", "UserDatabase")
        container_name = os.environ.get("CONTAINER_NAME", "Users")
        
        # Your verified domain from Azure AD
        verified_domain = "infotheappspaza.onmicrosoft.com"
        
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
        user_data = {
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
        }
        
        # Log configuration info
        logging.info(f"Using tenant ID: {tenant_id}")
        logging.info(f"Using client ID: {client_id}")
        logging.info(f"Using userPrincipalName: {user_principal_name}")
        logging.info(f"User role: {req_body['user_role']}")
        
        # Create credentials using the non-async ClientSecretCredential since Azure Functions might not support async
        # In a fully async environment, you would use ClientSecretCredential from azure.identity.aio
        credential = ClientSecretCredential(tenant_id, client_id, client_secret)
        
        # Create the authentication provider
        auth_provider = AzureIdentityAuthenticationProvider(credential)
        
        # Create the request adapter
        adapter = BaseGraphRequestAdapter(auth_provider)
        
        # Create a request to add a user
        request_info = RequestInformation()
        request_info.url = 'https://graph.microsoft.com/v1.0/users'
        request_info.http_method = "POST"
        request_info.headers["Content-Type"] = "application/json"
        request_info.set_content_from_parsable(None, user_data, "application/json")
        
        # Execute the request synchronously (for Azure Functions compatibility)
        # In a fully async environment, you would use await adapter.send_async()
        try:
            # The response will be a dictionary representing the created user
            response = asyncio.run(adapter.send_async(request_info, dict, {}))
            
            # Get the user ID
            entra_id = response.get("id")
            
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
                    db_user_data = {
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
                    db_user_data = {
                        "email": user_email,
                        "fullname": display_name,
                        "password": hashed_password,
                        "phoneNumber": req_body.get("phoneNumber", ""),
                        "userType": "customer",
                        "user_role": "customer",
                        "entraId": entra_id,
                        "userPrincipalName": user_principal_name
                    }
                
                result = container.insert_one(db_user_data)
                database_id = str(result.inserted_id)
            
            # Get token information
            # Note: In this approach we can't easily get token details to return to the client
            
            # Prepare response with user data
            response_data = {
                "message": "User registered successfully",
                "userId": entra_id,
                "databaseId": database_id,
                "userPrincipalName": user_principal_name,
                "displayName": display_name,
                "user_role": req_body["user_role"]
            }
            
            return func.HttpResponse(
                json.dumps(response_data),
                status_code=201,
                mimetype="application/json"
            )
            
        except APIError as api_error:
            # Handle Graph API errors
            error_message = str(api_error)
            logging.error(f"Graph API error: {error_message}")
            return func.HttpResponse(
                json.dumps({"error": f"Failed to register user in Entra ID: {error_message}"}),
                status_code=500,
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
