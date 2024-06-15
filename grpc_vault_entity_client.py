"""Vault gRPC Client"""

import logging
import grpc

import vault_pb2
import vault_pb2_grpc

from utils import get_configs

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("[Vault gRPC Client]")


def get_channel():
    """Get the appropriate gRPC channel based on the mode.

    Returns:
        grpc.Channel: The gRPC channel.
    """
    mode = get_configs("MODE", default_value="development")
    hostname = get_configs("VAULT_GRPC_HOST")
    port = get_configs("VAULT_GRPC_PORT")
    secure_port = get_configs("VAULT_GRPC_SSL_PORT")

    if mode == "production":
        logger.info("Connecting to vault gRPC server at %s:%s", hostname, secure_port)
        credentials = grpc.ssl_channel_credentials()
        logger.info("Using secure channel for gRPC communication")
        return grpc.secure_channel(f"{hostname}:{secure_port}", credentials)

    logger.info("Connecting to vault gRPC server at %s:%s", hostname, port)
    logger.warning("Using insecure channel for gRPC communication")
    return grpc.insecure_channel(f"{hostname}:{port}")


def store_entity_token(long_lived_token, token, platform, account_identifier):
    """Store an entity token in the vault.

    Args:
        long_lived_token (str): The long-lived token.
        token (str): The token to store.
        platform (str): The platform name.
        account_identifier (str): The account identifier.

    Returns:
        tuple: A tuple containing the response and an error message, if any.
    """
    try:
        channel = get_channel()

        with channel as conn:
            stub = vault_pb2_grpc.EntityStub(conn)
            request = vault_pb2.StoreEntityTokenRequest(
                long_lived_token=long_lived_token,
                token=token,
                platform=platform,
                account_identifier=account_identifier,
            )

            logger.debug("Storing token for platform '%s'", platform)
            response = stub.StoreEntityToken(request)
            logger.info("Successfully stored token for platform '%s'", platform)
            return response, None
    except grpc.RpcError as e:
        return None, e
    except Exception as e:
        raise e


def list_entity_stored_tokens(long_lived_token):
    """Fetches and lists entity's stored tokens from the vault.

    Args:
        long_lived_token (str): The long-lived token.

    Returns:
        list: A list of stored tokens
    """
    try:
        channel = get_channel()

        with channel as conn:
            stub = vault_pb2_grpc.EntityStub(conn)
            request = vault_pb2.ListEntityStoredTokenRequest(
                long_lived_token=long_lived_token
            )

            logger.debug(
                "Requesting stored tokens for long-lived token '%s'", long_lived_token
            )
            response = stub.ListEntityStoredTokens(request)
            tokens = response.stored_tokens

            logger.info(
                "Successfully retrieved tokens for long-lived token '%s'",
                long_lived_token,
            )
            return tokens, None
    except grpc.RpcError as e:
        return None, e
    except Exception as e:
        raise e
