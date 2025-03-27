"""
Login Function
This function handles user login through either database authentication or Entra ID,
with fallback mechanisms between the two methods.
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
    logging.info('Processing HTTP request for user login.')
    
    try:
        # Try to load environment variables if needed
        try:
            from dotenv import load_dotenv
            load_dotenv()
            logging.info("Loaded environment variables from .env file")
        except ImportError:
            logging.info("python-dotenv not installed, using environment variables directly")
        except Exception as e:
            logging.warning(f"Could not load .env file: {str(e)}")
        
        # Load environment variables with fallbacks
        cosmos_db_connection_string = os.environ.get("COSMOS_DB_CONNECTION_STRING")
        database_name = os.environ.get("DATABASE_NAME", "UserDatabase")
        container_name = os.environ.get("CONTAINER_NAME", "Users")
        
        # Get Azure AD configuration from app settings
        tenant_id = os.environ.get("AZ_TENANT_ID")
        client_id = os.environ.get("AZ_CLIENT_ID")
        client_secret = os.environ.get("AZ_CLIENT_SECRET")
        
        # Check for missing required configuration
        missing_config = []
        if not cosmos_db_connection_string:
            missing_config.append("COSMOS_DB_CONNECTION_STRING")
        
        # Entra ID config check
        entra_id_available = True
        if not tenant_id:
            missing_config.append("AZ_TENANT_ID")
            entra_id_available = False
        if not client_id:
            missing_config.append("AZ_CLIENT_ID")
            entra_id_available = False
        if not client_secret:
            missing_config.append("AZ_CLIENT_SECRET")
            entra_id_available = False
            
        if "COSMOS_DB_CONNECTION_STRING" in missing_config:
            error_message = f"Missing required database configuration: {', '.join(missing_config)}"
            logging.error(error_message)
            return func.HttpResponse(
                json.dumps({"error": error_message}),
                status_code=500,
                mimetype="application/json"
            )
        
        if not entra_id_available:
            logging.warning(f"Entra ID authentication will be skipped due to missing config: {', '.join(missing_config)}")
        
        # Parse the request body
        req_body = req.get_json()
        
        # Check required login fields
        if "email" not in req_body:
            return func.HttpResponse(
                json.dumps({"error": "Missing email field in request"}),
                status_code=400,
                mimetype="application/json"
            )
        
        user_email = req_body["email"]
        has_password = "password" in req_body and req_body["password"]
        
        # Connect to database
        try:
            client = MongoClient(
                cosmos_db_connection_string,
                socketTimeoutMS=30000,
                connectTimeoutMS=30000
            )
            database = client[database_name]
            container = database[container_name]
            logging.info(f"Connected to database {database_name}")
        except Exception as e:
            logging.error(f"Failed to connect to database: {str(e)}")
            return func.HttpResponse(
                json.dumps({"error": "Database connection error"}),
                status_code=500,
                mimetype="application/json"
            )
        
        # Try to find user in database
        db_user = container.find_one({"email": user_email})
        
        # Authentication path decision
        if db_user:
            # User exists in database
            logging.info(f"User found in database: {user_email}")
            
            # If password is provided, try database authentication first
            if has_password:
                logging.info("Attempting database authentication")
                
                # Hash the provided password
                hashed_password = hashlib.sha256(req_body["password"].encode()).hexdigest()
                
                # Verify password
                if db_user.get("password") == hashed_password:
                    logging.info("Database authentication successful")
                    
                    # Check if user has Entra ID, if yes, try to get a token
                    entra_id = db_user.get("entraId")
                    user_principal_name = db_user.get("userPrincipalName")
                    
                    token_result = None
                    if entra_id and user_principal_name and entra_id_available:
                        logging.info(f"User has Entra ID ({entra_id}), getting token")
                        token_result = get_entra_id_token(tenant_id, client_id, client_secret, user_principal_name, req_body.get("password"))
                    
                    # Create success response
                    response_data = prepare_success_response(db_user, token_result)
                    return func.HttpResponse(
                        json.dumps(response_data),
                        status_code=200,
                        mimetype="application/json"
                    )
                else:
                    logging.info("Database authentication failed, invalid password")
                    
                    # If we have Entra ID info, try that as fallback
                    if db_user.get("entraId") and entra_id_available:
                        logging.info("Trying Entra ID authentication as fallback")
                        return try_entra_id_login(tenant_id, client_id, client_secret, db_user, req_body.get("password"))
                    else:
                        return func.HttpResponse(
                            json.dumps({"error": "Invalid email or password"}),
                            status_code=401,
                            mimetype="application/json"
                        )
            else:
                # No password provided, try Entra ID only if user has Entra ID info
                if db_user.get("entraId") and entra_id_available:
                    logging.info("No password provided, trying Entra ID authentication directly")
                    return try_entra_id_login(tenant_id, client_id, client_secret, db_user, req_body.get("password"))
                else:
                    return func.HttpResponse(
                        json.dumps({"error": "Password is required for login"}),
                        status_code=400,
                        mimetype="application/json"
                    )
        else:
            # User not found in database
            logging.info(f"User not found in database: {user_email}")
            
            # If Entra ID is available, try to authenticate there
            if entra_id_available and has_password:
                logging.info("Trying Entra ID authentication for user not in database")
                
                # Extract username for userPrincipalName construction
                username = user_email.split("@")[0]
                verified_domain = "infotheappspaza.onmicrosoft.com"
                user_principal_name = f"{username}@{verified_domain}"
                
                # Try to get token
                token_result = get_entra_id_token(tenant_id, client_id, client_secret, user_principal_name, req_body.get("password"))
                
                if token_result and "access_token" in token_result:
                    logging.info("Entra ID authentication successful for user not in database")
                    
                    # Get user details from Microsoft Graph API to create database entry
                    user_details = get_user_from_graph(token_result["access_token"])
                    
                    if user_details:
                        # Create user in database
                        db_user = create_user_in_database(container, user_details, req_body.get("password"))
                        
                        # Create success response
                        response_data = prepare_success_response(db_user, token_result)
                        return func.HttpResponse(
                            json.dumps(response_data),
                            status_code=200,
                            mimetype="application/json"
                        )
                
            # If we got here, authentication failed
            return func.HttpResponse(
                json.dumps({"error": "User not found. Please register first."}),
                status_code=404,
                mimetype="application/json"
            )
    
    except Exception as e:
        logging.error(f"Unexpected error during login: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"An unexpected error occurred: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )

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