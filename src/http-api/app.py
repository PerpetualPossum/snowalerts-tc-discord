import json
import os
import time
from typing import Annotated
from urllib.parse import parse_qs

import boto3
from aws_lambda_powertools import Logger
from aws_lambda_powertools.event_handler import (
    APIGatewayHttpResolver,
    Response,
    content_types,
)
from aws_lambda_powertools.event_handler.openapi.params import Form
from aws_lambda_powertools.logging import correlation_paths
from aws_lambda_powertools.utilities.data_classes import APIGatewayProxyEventV2
from discord_interactions import verify_key
from twilio.request_validator import RequestValidator

dynamo_table = os.getenv("DYNAMO_TABLE_SMS_MESSAGES", "sms-messages-dev")
sqs_queue = os.getenv("SQS_QUEUE_URL_INCOMING_SMS", "")

twilio_auth_token = os.getenv("TWILIO_AUTH_TOKEN", "")
incoming_sms_url = os.getenv("INCOMING_SMS_URL", "")

app = APIGatewayHttpResolver(enable_validation=True)
logger = Logger()

dynamo = boto3.client("dynamodb")
sqs = boto3.client("sqs")


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


def verify_twilio_request(raw_body: str | None, headers: dict) -> bool:
    validator = RequestValidator(twilio_auth_token)
    url = incoming_sms_url
    signature = headers.get("X-Twilio-Signature", "")

    # Parse the raw body into a dictionary
    parsed = parse_qs(raw_body)
    twilio_params = {}
    for key in parsed:
        twilio_params[key] = parsed[key][0]

    is_valid = validator.validate(url, twilio_params, signature)

    logger.debug(f"Twilio request validation result: {is_valid}")

    return is_valid


def handle_ping():
    pong_body = {"type": 1}
    return {"statusCode": 200, "body": pong_body}


@logger.inject_lambda_context(correlation_id_path=correlation_paths.API_GATEWAY_HTTP)
def lambda_handler(event, context):
    return app.resolve(event, context)


@app.post("/webhooks/incoming-sms")
def incoming_sms(
    message_sid: Annotated[str, Form(alias="MessageSid")],
    account_sid: Annotated[str, Form(alias="AccountSid")],
    messaging_service_sid: Annotated[str, Form(alias="MessagingServiceSid")],
    from_number: Annotated[str, Form(alias="From")],
    to_number: Annotated[str, Form(alias="To")],
    body: Annotated[str, Form(alias="Body")],
    num_media: Annotated[int, Form(alias="NumMedia")],
    num_segments: Annotated[int, Form(alias="NumSegments")],
):

    # Store the incoming SMS message in DynamoDB for record-keeping
    item = {
        "message_sid": message_sid,
        "account_sid": account_sid,
        "messaging_service_sid": messaging_service_sid,
        "from_number": from_number,
        "to_number": to_number,
        "body": body,
        "num_media": num_media,
        "num_segments": num_segments,
        "received_at": int(time.time()),
    }

    logger.debug(f"Storing incoming SMS message: {item}")

    # Verify the Twilio request
    if not verify_twilio_request(
        app.current_event.decoded_body, app.current_event.headers
    ):
        return Response(
            status_code=401,
            content_type=content_types.TEXT_PLAIN,
        )

    try:
        dynamo.put_item(
            TableName=dynamo_table,
            Item={
                k: {"S": str(v)} if isinstance(v, str) else {"N": str(v)}
                for k, v in item.items()
            },
        )
    except Exception as e:
        logger.exception(f"Error storing SMS message in DynamoDB: {e}")
        return Response(
            status_code=500,
            content_type=content_types.TEXT_PLAIN,
            body="Internal Server Error",
        )

    # Encode the message as JSON and send it to SQS for processing
    sqs_message_body = json.dumps(item)

    try:
        sqs.send_message(
            QueueUrl=sqs_queue,
            MessageBody=sqs_message_body,
        )
    except Exception as e:
        logger.exception(f"Error sending SMS message to SQS: {e}")
        return Response(
            status_code=500,
            content_type=content_types.TEXT_PLAIN,
            body="Internal Server Error",
        )

    return Response(
        status_code=200,
        content_type=content_types.TEXT_PLAIN,
    )


@app.post("/api/interactions")
def interactions():

    # Verify the request
    if not verify_event(app.current_event):
        return {"statusCode": 401, "body": "Invalid request signature"}

    # Handle Ping interaction
    if app.current_event.json_body["type"] == 1:
        return handle_ping()
