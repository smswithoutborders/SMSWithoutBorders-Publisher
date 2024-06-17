"""Utitlies Module."""

import os
import logging

import grpc

logging.basicConfig(
    level=logging.INFO, format=("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
)
logger = logging.getLogger(__name__)


def get_configs(config_name, strict=False, default_value=None):
    """
    Retrieves the value of a configuration from the environment variables.

    Args:
        config_name (str): The name of the configuration to retrieve.
        strict (bool): If True, raises an error if the configuration
            is not found. Default is False.
        default_value (str): The default value to return if the configuration
            is not found and strict is False. Default is None.

    Returns:
        str: The value of the configuration, or default_value if not found and s
            trict is False.

    Raises:
        KeyError: If the configuration is not found and strict is True.
        ValueError: If the configuration value is empty and strict is True.
    """
    try:
        value = (
            os.environ[config_name]
            if strict
            else os.environ.get(config_name) or default_value
        )
        if strict and (value is None or value.strip() == ""):
            raise ValueError(f"Configuration '{config_name}' is missing or empty.")
        return value
    except KeyError as error:
        logger.error(
            "Configuration '%s' not found in environment variables: %s",
            config_name,
            error,
        )
        raise
    except ValueError as error:
        logger.error("Configuration '%s' is empty: %s", config_name, error)
        raise


def set_configs(config_name: str, config_value: str) -> None:
    """
    Sets the value of a configuration in the environment variables.

    Args:
        config_name (str): The name of the configuration to set.
        config_value (str): The value of the configuration to set.

    Raises:
        ValueError: If config_name or config_value is empty.
    """
    if not config_name or not config_value:
        error_message = (
            f"Cannot set configuration. Invalid config_name '{config_name}' ",
            "or config_value '{config_value}'.",
        )
        logger.error(error_message)
        raise ValueError(error_message)

    try:
        os.environ[config_name] = config_value
    except Exception as error:
        logger.error("Failed to set configuration '%s': %s", config_name, error)
        raise


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
