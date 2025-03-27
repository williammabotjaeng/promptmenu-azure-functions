import logging
import hashlib
import json
from dotenv import load_dotenv
import os
import azure.functions as func
from pymongo import MongoClient

# Load environment variables from .env file
load_dotenv()

# Load environment variables
COSMOS_DB_CONNECTION_STRING = os.getenv("COSMOS_DB_CONNECTION_STRING")
DATABASE_NAME = os.getenv("DATABASE_NAME", "UserDatabase")
CONTAINER_NAME = os.getenv("CONTAINER_NAME", "Users")

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
        if not all(field in req_body and req_body[field] for field in required_fields):
            missing_fields = [field for field in required_fields if field not in req_body or not req_body[field]]
            logging.error(f"Missing or invalid fields: {missing_fields}")
            return func.HttpResponse(
                f"Missing or invalid fields: {', '.join(missing_fields)}",
                status_code=400
            )

        # Hash the password
        hashed_password = hashlib.sha256(req_body["password"].encode()).hexdigest()

        # Prepare the user data
        user_data = {
            "address": req_body["address"],
            "businessEmail": req_body["businessEmail"],
            "ownerEmail": req_body["ownerEmail"],
            "ownerName": req_body["ownerName"],
            "password": hashed_password,
            "phoneNumber": req_body["phoneNumber"],
            "restaurantName": req_body["restaurantName"],
            "userType": req_body["userType"]
        }

        # Connect to Cosmos DB using pymongo with increased timeout
        logging.info("Connecting to Cosmos DB (MongoDB API)...")
        client = MongoClient(
            COSMOS_DB_CONNECTION_STRING,
            socketTimeoutMS=60000,  # 60 seconds
            connectTimeoutMS=60000  # 60 seconds
        )
        database = client[DATABASE_NAME]
        container = database[CONTAINER_NAME]

        # Insert the user data into Cosmos DB
        logging.info("Inserting user data into Cosmos DB...")
        container.insert_one(user_data)

        return func.HttpResponse(
            json.dumps({"message": "User account created successfully."}),
            status_code=201,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return func.HttpResponse(
            "An unexpected error occurred.",
            status_code=500
        )