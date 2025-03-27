import logging
import hashlib
import json
import os
import azure.functions as func
from azure.cosmos import CosmosClient, exceptions

# Load the Cosmos DB connection string from environment variables
COSMOS_DB_CONNECTION_STRING = os.getenv("COSMOS_DB_CONNECTION_STRING")
DATABASE_NAME = "UserDatabase"
CONTAINER_NAME = "Users"

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing HTTP request to create a user.')

    try:
        # Parse the request body
        req_body = req.get_json()
        required_fields = [
            "address", "businessEmail", "ownerEmail", "ownerName",
            "password", "phoneNumber", "restaurantName", "userType"
        ]

        # Validate required fields
        if not all(field in req_body for field in required_fields):
            return func.HttpResponse(
                "Missing required fields in the payload.",
                status_code=400
            )

        # Hash the password
        hashed_password = hashlib.sha256(req_body["password"].encode()).hexdigest()

        # Prepare the user data
        user_data = {
            "id": req_body["businessEmail"],  # Use businessEmail as the unique ID
            "address": req_body["address"],
            "businessEmail": req_body["businessEmail"],
            "ownerEmail": req_body["ownerEmail"],
            "ownerName": req_body["ownerName"],
            "password": hashed_password,
            "phoneNumber": req_body["phoneNumber"],
            "restaurantName": req_body["restaurantName"],
            "userType": req_body["userType"]
        }

        # Connect to Cosmos DB using the connection string
        client = CosmosClient.from_connection_string(COSMOS_DB_CONNECTION_STRING)
        database = client.create_database_if_not_exists(DATABASE_NAME)
        container = database.create_container_if_not_exists(
            id=CONTAINER_NAME,
            partition_key={"paths": ["/businessEmail"], "kind": "Hash"}
        )

        # Insert the user data into Cosmos DB
        container.create_item(body=user_data)

        return func.HttpResponse(
            json.dumps({"message": "User account created successfully."}),
            status_code=201,
            mimetype="application/json"
        )

    except exceptions.CosmosHttpResponseError as e:
        logging.error(f"Cosmos DB error: {e}")
        return func.HttpResponse(
            "An error occurred while interacting with the database.",
            status_code=500
        )
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return func.HttpResponse(
            "An unexpected error occurred.",
            status_code=500
        )