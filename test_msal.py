from msal import ConfidentialClientApplication

# Replace with your environment variables
TENANT_ID = "1b5a26ab-bd78-4a85-b9ec-b6e11b41a1d4"
CLIENT_ID = "84182813-1cbd-4ce4-8cfc-0a109e94d75c"
CLIENT_SECRET = "-CR8Q~EbEP8oS8Wn-CEJuWc.93cgpC.Ma7y85bDp"
GRAPH_API_SCOPE = ["https://graph.microsoft.com/.default"]

try:
    # Authenticate with Azure AD using MSAL
    app = ConfidentialClientApplication(
        CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
        client_credential=CLIENT_SECRET
    )

    # Acquire a token for Microsoft Graph API
    result = app.acquire_token_for_client(scopes=GRAPH_API_SCOPE)
    if "access_token" in result:
        print("Access token acquired successfully!")
        print(result["access_token"])
    else:
        print("Failed to acquire access token.")
        print(result)
except Exception as e:
    print(f"Error: {e}")