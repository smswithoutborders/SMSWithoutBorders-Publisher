"""gRPC Publisher Service"""

import logging
import base64
from email.message import EmailMessage
import json
import grpc

from authlib.integrations.base_client import OAuthError

import publisher_pb2
import publisher_pb2_grpc

from utils import error_response, validate_request_fields
from oauth2 import OAuth2Client
from relaysms_payload import decode_relay_sms_payload
from grpc_vault_entity_client import (
    list_entity_stored_tokens,
    store_entity_token,
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
SUPPORTED_PLATFORMS = tuple(
    platform_info["platform_name"] for platform_info in PLATFORM_DETAILS.values()
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("[gRPC Publisher Service]")


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

    message["to"] = to_email
    message["from"] = from_email
    message["subject"] = subject

    if cc_email:
        message["cc"] = cc_email
    if bcc_email:
        message["bcc"] = bcc_email

    encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode("utf-8")
    create_message = {"raw": encoded_message}

    return create_message


class PublisherService(publisher_pb2_grpc.PublisherServicer):
    """Publisher Service Descriptor"""

    def GetOAuth2AuthorizationUrl(self, request, context):
        """Handles generating OAuth2 authorization URL"""

        response = publisher_pb2.GetOAuth2AuthorizationUrlResponse

        try:
            invalid_fields_response = validate_request_fields(
                context,
                request,
                response,
                ["platform"],
            )
            if invalid_fields_response:
                return invalid_fields_response

            if request.platform.lower() not in SUPPORTED_PLATFORMS:
                raise NotImplementedError(
                    f"The protocol '{request.platform}' is currently not supported. "
                    "Please contact the developers for more information on when "
                    "this platform will be implemented."
                )

            oauth2_client = OAuth2Client(request.platform)

            extra_params = {
                "state": getattr(request, "state") or None,
                "code_verifier": getattr(request, "code_verifier") or None,
                "autogenerate_code_verifier": getattr(
                    request, "autogenerate_code_verifier"
                ),
            }

            authorization_url, state, code_verifier = (
                oauth2_client.get_authorization_url(**extra_params)
            )

            return response(
                authorization_url=authorization_url,
                state=state,
                code_verifier=code_verifier,
                message="Successfully generated authorization url",
            )

        except NotImplementedError as e:
            return error_response(
                context,
                response,
                str(e),
                grpc.StatusCode.UNIMPLEMENTED,
            )

        except Exception as e:
            return error_response(
                context,
                response,
                e,
                grpc.StatusCode.INTERNAL,
                user_msg="Oops! Something went wrong. Please try again later.",
                _type="UNKNOWN",
            )

    def ExchangeOAuth2CodeAndStore(self, request, context):
        """Handles exchanging OAuth2 authorization code for a token"""

        response = publisher_pb2.ExchangeOAuth2CodeAndStoreResponse

        try:
            invalid_fields_response = validate_request_fields(
                context,
                request,
                response,
                [
                    "long_lived_token",
                    "platform",
                    "authorization_code",
                ],
            )
            if invalid_fields_response:
                return invalid_fields_response

            if request.platform.lower() not in SUPPORTED_PLATFORMS:
                raise NotImplementedError(
                    f"The protocol '{request.platform}' is currently not supported. "
                    "Please contact the developers for more information on when "
                    "this platform will be implemented."
                )

            _, list_token_error = list_entity_stored_tokens(
                long_lived_token=request.long_lived_token
            )

            if list_token_error:
                return error_response(
                    context,
                    response,
                    list_token_error.details(),
                    list_token_error.code(),
                    _type="UNKNOWN",
                )

            oauth2_client = OAuth2Client(request.platform)

            extra_params = {"code_verifier": getattr(request, "code_verifier") or None}

            token = oauth2_client.fetch_token(
                code=request.authorization_code,
                **extra_params,
            )
            profile = oauth2_client.fetch_userinfo()

            store_response, store_error = store_entity_token(
                long_lived_token=request.long_lived_token,
                platform=request.platform,
                account_identifier=profile.get("email") or profile.get("username"),
                token=json.dumps(token),
            )

            if store_error:
                return error_response(
                    context,
                    response,
                    store_error.details(),
                    store_error.code(),
                    _type="UNKNOWN",
                )

            if not store_response.success:
                return response(
                    message=store_response.message, success=store_response.success
                )

            return response(
                success=True,
                message="Successfully fetched and stored token",
            )

        except OAuthError as e:
            return error_response(
                context,
                response,
                str(e),
                grpc.StatusCode.INVALID_ARGUMENT,
                _type="UNKNOWN",
            )

        except NotImplementedError as e:
            return error_response(
                context,
                response,
                str(e),
                grpc.StatusCode.UNIMPLEMENTED,
            )

        except Exception as e:
            return error_response(
                context,
                response,
                e,
                grpc.StatusCode.INTERNAL,
                user_msg="Oops! Something went wrong. Please try again later.",
                _type="UNKNOWN",
            )

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

            platform_letter, encrypted_content, device_id, decode_error = (
                decode_relay_sms_payload(request.content)
            )

            if decode_error:
                return error_response(
                    context,
                    response,
                    decode_error,
                    grpc.StatusCode.INVALID_ARGUMENT,
                    user_msg="Invalid content format.",
                    _type="UNKNOWN",
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
                    device_id=device_id,
                    payload_ciphertext=encrypted_content,
                    platform=platform_name,
                )
            )

            if get_access_token_error:
                return error_response(
                    context,
                    response,
                    get_access_token_error.details(),
                    get_access_token_error.code(),
                )

            if not get_access_token_response.success:
                return response(
                    message=get_access_token_response.message,
                    success=get_access_token_response.success,
                )

            if protocol == "oauth2":
                if service_type == "email":
                    email_message = create_email_message(
                        get_access_token_response.payload_plaintext
                    )
                    oauth2_client = OAuth2Client(
                        platform_name, json.loads(get_access_token_response.token)
                    )
                    message_response = oauth2_client.send_message("me", email_message)

            encrypt_payload_response, encrypt_payload_error = encrypt_payload(
                device_id=device_id, payload_plaintext=message_response
            )

            if encrypt_payload_error:
                return error_response(
                    context,
                    response,
                    encrypt_payload_error.details(),
                    encrypt_payload_error.code(),
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
