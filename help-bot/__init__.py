import logging
import azure.functions as func
import json

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing a request from the Bot Framework.")

    try:
        # Parse the incoming request body
        req_body = req.get_json()

        # Extract the intent from the request
        intent = req_body.get("intent", {}).get("name", None)

        # Handle different intents
        if intent == "HelpIntent":
            response = {
                "text": "How can I assist you? Here are some things I can help with: [list of options]."
            }
        elif intent == "GreetingIntent":
            response = {
                "text": "Hello! How can I help you today?"
            }
        elif intent == "GoodbyeIntent":
            response = {
                "text": "Goodbye! Have a great day!"
            }
        else:
            response = {
                "text": "I'm sorry, I didn't understand that. Can you try rephrasing?"
            }

        # Return the response as JSON
        return func.HttpResponse(
            json.dumps(response),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return func.HttpResponse(
            "An error occurred while processing the request.",
            status_code=500
        )