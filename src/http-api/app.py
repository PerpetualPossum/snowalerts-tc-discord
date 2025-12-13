from discord_interactions import verify_key
from aws_lambda_powertools.event_handler import APIGatewayHttpResolver
from aws_lambda_powertools.utilities.data_classes import (
    APIGatewayProxyEventV2,
)

app = APIGatewayHttpResolver()


def verify_event(event: APIGatewayProxyEventV2) -> bool:
    discord_public_key = "TODO"

    raw_body = event["body"]
    headers = event["headers"]
    signature = headers["x-signature-ed25519"]
    timestamp = headers["x-signature-timestamp"]

    # Verify if the request is valid
    is_verified = verify_key(
        raw_body.encode(), signature, timestamp, discord_public_key
    )
    return is_verified


def handle_ping():
    pong_body = {"type": 1}
    return {"statusCode": 200, "body": pong_body}


@app.get("/healthz-no-checks")
def healthz_no_checks():
    return {"statusCode": 200, "body": "OK"}


@app.get("/healthz")
def healthz():
    # Will add checks for DDB, Twilio, etc. later
    return {"statusCode": 200, "body": "OK"}


@app.post("/webhooks/incoming_sms")
def incoming_sms():
    # Placeholder for handling incoming SMS via Twilio
    return {"statusCode": 200, "body": "SMS received"}


@app.post("/api/interactions")
def interactions():

    # Verify the request
    if not verify_event(app.current_event):
        return {"statusCode": 401, "body": "Invalid request signature"}

    # Handle Ping interaction
    if app.current_event.json_body["type"] == 1:
        return handle_ping()
