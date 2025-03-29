"""
Helper functions for Azure Functions App
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

# Load environment variables with dotenv
def load_env_variables():
    try:
        from dotenv import load_dotenv
        load_dotenv()
        logging.info("Loaded environment variables from .env file")
    except ImportError:
        logging.info("python-dotenv not installed, using environment variables directly")
    except Exception as e:
        logging.warning(f"Could not load .env file: {str(e)}")