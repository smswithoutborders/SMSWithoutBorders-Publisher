"""gRPC OAuth2 Service"""

import logging
import json
import grpc
from authlib.integrations.base_client import OAuthError

import publisher_pb2
import publisher_pb2_grpc

from oauth2 import OAuth2Client

logging.basicConfig(
    level=logging.INFO, format=("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
)
logger = logging.getLogger("[gRPC OAuth2 Service]")


def error_response(context, response, sys_msg, status_code, user_msg=None, _type=None):
    """
    Create an error response.

    Args:
        context: gRPC context.
        response: gRPC response object.
        sys_msg (str or tuple): System message.
        status_code: gRPC status code.
        user_msg (str or tuple): User-friendly message.
        _type (str): Type of error.

    Returns:
        An instance of the specified response with the error set.
    """
    if not user_msg:
        user_msg = sys_msg

    if isinstance(user_msg, tuple):
        user_msg = "".join(user_msg)
    if isinstance(sys_msg, tuple):
        sys_msg = "".join(sys_msg)

    if _type == "UNKNOWN":
        logger.exception(sys_msg, exc_info=True)
    else:
        logger.error(sys_msg)

    context.set_details(user_msg)
    context.set_code(status_code)

    return response()


def validate_request_fields(context, request, response, required_fields):
    """
    Validates the fields in the gRPC request.

    Args:
        context: gRPC context.
        request: gRPC request object.
        response: gRPC response object.
        required_fields (list): List of required fields.

    Returns:
        None or response: None if no missing fields,
            error response otherwise.
    """
    missing_fields = [field for field in required_fields if not getattr(request, field)]
    if missing_fields:
        return error_response(
            context,
            response,
            f"Missing required fields: {', '.join(missing_fields)}",
            grpc.StatusCode.INVALID_ARGUMENT,
        )

    return None


class OAuth2Service(publisher_pb2_grpc.PublisherServicer):
    """OAuth2 Service Descriptor"""

    def GetAuthorizationUrl(self, request, context):
        """Handles generating auth url"""

        response = publisher_pb2.GetAuthorizationUrlResponse

        try:
            invalid_fields_response = validate_request_fields(
                context,
                request,
                response,
                [
                    "redirect_uri",
                    "client_id",
                    "scope",
                    "authorization_endpoint",
                ],
            )
            if invalid_fields_response:
                return invalid_fields_response

            oauth2_client = OAuth2Client(
                client_id=request.client_id,
                redirect_uri=request.redirect_uri,
            )

            extra_params = {
                "state": getattr(request, "state") or None,
                "prompt": getattr(request, "prompt") or None,
                "code_verifier": getattr(request, "code_verifier") or None,
                "autogenerate_code_verifier": getattr(
                    request, "autogenerate_code_verifier"
                ),
                "access_type": getattr(request, "access_type") or None,
            }

            authorization_url, state, code_verifier = (
                oauth2_client.get_authorization_url(
                    auth_uri=request.authorization_endpoint,
                    scope=" ".join(request.scope),
                    **extra_params,
                )
            )

            return response(
                authorization_url=authorization_url,
                state=state,
                code_verifier=code_verifier,
                message="Successfully generated authorization url",
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

    def ExchangeOAuth2Code(self, request, context):
        """Handles exchanging oauth2 auth_code for tokens"""

        response = publisher_pb2.ExchangeOAuth2CodeResponse

        try:
            invalid_fields_response = validate_request_fields(
                context,
                request,
                response,
                [
                    "authorization_code",
                    "redirect_uri",
                    "client_id",
                    "client_secret",
                    "token_endpoint",
                    "userinfo_endpoint",
                ],
            )
            if invalid_fields_response:
                return invalid_fields_response

            oauth2_client = OAuth2Client(
                client_id=request.client_id,
                client_secret=request.client_secret,
                redirect_uri=request.redirect_uri,
            )

            extra_params = {"code_verifier": getattr(request, "code_verifier") or None}

            token = oauth2_client.fetch_token(
                token_uri=request.token_endpoint,
                code=request.authorization_code,
                **extra_params,
            )
            profile = oauth2_client.fetch_userinfo(
                userinfo_uri=request.userinfo_endpoint
            )

            return response(
                token=json.dumps(token),
                profile=json.dumps(profile),
                message="Successfully fetched tokens",
            )

        except OAuthError as e:
            return error_response(
                context,
                response,
                str(e),
                grpc.StatusCode.INVALID_ARGUMENT,
                _type="UNKNOWN",
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
