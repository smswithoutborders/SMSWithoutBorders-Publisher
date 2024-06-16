"""gRPC Publish Service"""

import logging
import base64
from email.message import EmailMessage
import json
import grpc

import publisher_pb2
import publisher_pb2_grpc

from utils import error_response, validate_request_fields
from oauth2 import OAuth2Client
from relaysms_payload import decode_relay_sms_payload
from grpc_vault_entity_client import (
    get_entity_access_token_and_decrypt_payload,
    encrypt_payload,
)


PLATFORM_DETAILS = {
    "g": {
        "platform_name": "gmail",
        "service_type": "email",
        "protocol": "oauth2",
    }
}

logging.basicConfig(
    level=logging.INFO, format=("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
)
logger = logging.getLogger("[gRPC Publish Service]")


def parse_email_content(content):
    """
    Parse the email content string into its components.

    Args:
        content (str): The email content string in the format
            'from:to:cc:bcc:subject:body'.

    Returns:
        tuple: A tuple containing the from_email, to_email,
            cc_email, bcc_email, subject, and body.
    """
    parts = content.split(":")

    from_email = parts[0]
    to_email = parts[1]
    cc_email = parts[2]
    bcc_email = parts[3]
    subject = parts[4]
    body = parts[5]

    return from_email, to_email, cc_email, bcc_email, subject, body


def create_email_message(content):
    """
    Create an encoded email message from a formatted content string.

    Args:
        content (str): The email content string in the format
            'from:to:cc:bcc:subject:body'.

    Returns:
        dict: A dictionary containing the raw encoded email message.
    """
    from_email, to_email, cc_email, bcc_email, subject, body = parse_email_content(
        content
    )

    message = EmailMessage()
    message.set_content(body)

    message["To"] = to_email
    message["From"] = from_email
    message["Subject"] = subject

    if cc_email:
        message["Cc"] = cc_email
    if bcc_email:
        message["Bcc"] = bcc_email

    encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    create_message = {"raw": encoded_message}

    return create_message


class PublishService(publisher_pb2_grpc.PublisherServicer):
    """Publish Service Descriptor"""

    def PublishContent(self, request, context):
        """Handles Publising relaysms payload"""

        response = publisher_pb2.PublishContentResponse

        try:
            invalid_fields_response = validate_request_fields(
                context,
                request,
                response,
                ["content"],
            )
            if invalid_fields_response:
                return invalid_fields_response

            platform_letter, encrypted_content, device_id = decode_relay_sms_payload(
                request.content
            )

            platform_info = PLATFORM_DETAILS.get(platform_letter)
            if platform_info is None:
                return error_response(
                    context,
                    response,
                    f"Unknown platform letter '{platform_letter}' received.",
                    grpc.StatusCode.INVALID_ARGUMENT,
                )

            platform_name = platform_info["platform_name"]
            service_type = platform_info["service_type"]
            protocol = platform_info["protocol"]

            get_access_token_response, get_access_token_error = (
                get_entity_access_token_and_decrypt_payload(
                    device_id=device_id, payload_ciphertext=encrypted_content
                )
            )

            if get_access_token_error:
                return error_response(
                    context,
                    response,
                    get_access_token_error.details(),
                    get_access_token_error.code(),
                    _type="UNKNOWN",
                )

            if not get_access_token_response.success:
                return response(
                    message=get_access_token_response.message,
                    success=get_access_token_response.success,
                )

            if protocol == "oauth2":
                if service_type == "email":
                    email_message = create_email_message(response.payload_plaintext)
                    oauth2_client = OAuth2Client(
                        platform_name, json.loads(response.token)
                    )
                    message_response = oauth2_client.send_message("me", email_message)

            encrypt_payload_response, encrypt_payload_error = encrypt_payload(
                device_id=device_id, payload_plaintext=message_response.text
            )

            if encrypt_payload_error:
                return error_response(
                    context,
                    response,
                    encrypt_payload_error.details(),
                    encrypt_payload_error.code(),
                    _type="UNKNOWN",
                )

            if not encrypt_payload_response.success:
                return response(
                    message=encrypt_payload_response.message,
                    success=encrypt_payload_response.success,
                )

            return response(
                message=f"Successfully published {platform_name} message",
                publisher_response=encrypt_payload_response.payload_ciphertext,
                success=True,
            )

        except Exception as exc:
            return error_response(
                context,
                response,
                exc,
                grpc.StatusCode.INTERNAL,
                user_msg="Oops! Something went wrong. Please try again later.",
                _type="UNKNOWN",
            )
