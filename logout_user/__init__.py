import logging
import json
import azure.functions as func
import os

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing HTTP request for user logout.')
    
    try:
        # Try to load environment variables if needed
        try:
            from dotenv import load_dotenv
            load_dotenv()
        except ImportError:
            pass
        
        # Get tenant ID for the logout URL
        tenant_id = os.environ.get("AZ_TENANT_ID")
        client_id = os.environ.get("AZ_CLIENT_ID")
        
        if not tenant_id or not client_id:
            error_message = "Missing required configuration: AZ_TENANT_ID or AZ_CLIENT_ID"
            logging.error(error_message)
            return func.HttpResponse(
                json.dumps({"error": error_message}),
                status_code=500,
                mimetype="application/json"
            )
        
        # Parse the request to get the post-logout redirect URL
        req_body = req.get_json() if req.get_body() else {}
        post_logout_redirect_uri = req_body.get('post_logout_redirect_uri', '')
        
        # Construct the Entra ID logout URL
        # This uses the Microsoft identity platform v2.0 endpoint
        logout_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/logout"
        
        # Add post-logout redirect URI if provided
        if post_logout_redirect_uri:
            logout_url += f"?post_logout_redirect_uri={post_logout_redirect_uri}"
            
        # For SPAs and web applications, the client needs to:
        # 1. Clear local storage, session storage, and cookies
        # 2. Redirect the user to the logout URL
        
        response_data = {
            "message": "Logout successful",
            "logout_url": logout_url,
            "instructions": "To complete logout: 1) Clear local session data 2) Redirect user to logout_url"
        }
        
        return func.HttpResponse(
            json.dumps(response_data),
            status_code=200,
            mimetype="application/json"
        )
    
    except Exception as e:
        logging.error(f"Error during logout: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"An unexpected error occurred: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )