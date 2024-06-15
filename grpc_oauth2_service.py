"""gRPC OAuth2 Service"""

import logging
import json
import grpc
from authlib.integrations.base_client import OAuthError

import publisher_pb2
import publisher_pb2_grpc

from oauth2 import OAuth2Client
from grpc_vault_entity_client import store_entity_token, list_entity_stored_tokens

from utils import error_response, validate_request_fields

SUPPORTED_PLATFORMS = ("gmail",)

logging.basicConfig(
    level=logging.INFO, format=("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
)
logger = logging.getLogger("[gRPC OAuth2 Service]")


class OAuth2Service(publisher_pb2_grpc.PublisherServicer):
    """OAuth2 Service Descriptor"""

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
