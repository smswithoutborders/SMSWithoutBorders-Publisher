"""gRPC Publish Service"""

import logging
import grpc

import publisher_pb2
import publisher_pb2_grpc

from utils import error_response, validate_request_fields
from relaysms_payload import decode_relay_sms_payload


logging.basicConfig(
    level=logging.INFO, format=("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
)
logger = logging.getLogger("[gRPC Publish Service]")


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

        except Exception as exc:
            return error_response(
                context,
                response,
                exc,
                grpc.StatusCode.INTERNAL,
                user_msg="Oops! Something went wrong. Please try again later.",
                _type="UNKNOWN",
            )
