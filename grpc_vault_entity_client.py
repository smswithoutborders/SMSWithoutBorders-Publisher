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
        tuple: A tuple containing:
            - server response (object): The vault server response.
            - error (Exception): The error encountered if the request fails, otherwise None.
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
    """Fetches and lists an entity's stored tokens from the vault.

    Args:
        long_lived_token (str): The long-lived token used to authenticate
            the request.

    Returns:
        tuple: A tuple containing:
            - list: A list of stored tokens if the request is successful.
            - error (Exception): The error encountered if the request fails,
                otherwise None.
    """
    try:
        channel = get_channel()

        with channel as conn:
            stub = vault_pb2_grpc.EntityStub(conn)
            request = vault_pb2.ListEntityStoredTokenRequest(
                long_lived_token=long_lived_token
            )

            logger.debug(
                "Sending request to list stored tokens for long_lived_token: %s",
                long_lived_token,
            )
            response = stub.ListEntityStoredTokens(request)
            tokens = response.stored_tokens

            logger.info("Successfully retrieved stored tokens.")
            return tokens, None
    except grpc.RpcError as e:
        return None, e
    except Exception as e:
        raise e


def get_entity_access_token(device_id, platform, account_identifier):
    """
    Retrieves an entity access token.

    Args:
        device_id (str): The ID of the device.
        platform (str): The platform name.
        account_identifier (str): The account identifier.

    Returns:
        tuple: A tuple containing:
            - server response (object): The vault server response.
            - error (Exception): The error encountered if the request fails, otherwise None.
    """
    try:
        channel = get_channel()

        with channel as conn:
            stub = vault_pb2_grpc.EntityStub(conn)
            request = vault_pb2.GetEntityAccessTokenRequest(
                device_id=device_id,
                platform=platform,
                account_identifier=account_identifier,
            )

            logger.debug("Requesting access tokens for device_id '%s'...", device_id)
            response = stub.GetEntityAccessToken(request)

            logger.info(
                "Successfully retrieved access token for device id '%s'.",
                device_id,
            )
            return response, None
    except grpc.RpcError as e:
        return None, e
    except Exception as e:
        raise e


def decrypt_payload(device_id, payload_ciphertext):
    """
    Decrypts the payload.

    Args:
        device_id (str): The ID of the device.
        payload_ciphertext (bytes): The ciphertext of the payload to be decrypted.

    Returns:
        tuple: A tuple containing:
            - server response (object): The vault server response.
            - error (Exception): The error encountered if the request fails, otherwise None.
    """
    try:
        channel = get_channel()

        with channel as conn:
            stub = vault_pb2_grpc.EntityStub(conn)
            request = vault_pb2.DecryptPayloadRequest(
                device_id=device_id, payload_ciphertext=payload_ciphertext
            )

            logger.debug(
                "Sending request to decrypt payload for device_id: %s",
                device_id,
            )
            response = stub.DecryptPayload(request)
            logger.info("Successfully decrypted payload.")
            return response, None
    except grpc.RpcError as e:
        return None, e
    except Exception as e:
        raise e


def encrypt_payload(device_id, payload_plaintext):
    """
    Encrypts the payload.

    Args:
        device_id (str): The ID of the device.
        payload_plaintext (str): The plaintext of the payload to be encrypted.

    Returns:
        tuple: A tuple containing:
            - server response (object): The vault server response.
            - error (Exception): The error encountered if the request fails, otherwise None.
    """
    try:
        channel = get_channel()

        with channel as conn:
            stub = vault_pb2_grpc.EntityStub(conn)
            request = vault_pb2.EncryptPayloadRequest(
                device_id=device_id, payload_plaintext=payload_plaintext
            )

            logger.debug(
                "Sending request to encrypt payload for device_id: %s",
                device_id,
            )
            response = stub.EncryptPayload(request)
            logger.info("Successfully encrypted payload.")
            return response, None
    except grpc.RpcError as e:
        return None, e
    except Exception as e:
        raise e


def update_entity_token(device_id, token, platform, account_identifier):
    """Update an entity's token in the vault.

    Args:
        device_id (str): The ID of the device.
        token (str): The token to store.
        platform (str): The platform name.
        account_identifier (str): The account identifier.

    Returns:
        tuple: A tuple containing:
            - server response (object): The vault server response.
            - error (Exception): The error encountered if the request fails, otherwise None.
    """
    try:
        channel = get_channel()

        with channel as conn:
            stub = vault_pb2_grpc.EntityStub(conn)
            request = vault_pb2.UpdateEntityTokenRequest(
                device_id=device_id,
                token=token,
                platform=platform,
                account_identifier=account_identifier,
            )

            logger.debug("Updating token for platform '%s'", platform)
            response = stub.UpdateEntityToken(request)
            logger.info("Successfully updated token for platform '%s'", platform)
            return response, None
    except grpc.RpcError as e:
        return None, e
    except Exception as e:
        raise e
