"""Module for decoding and extracting information from RelaySMS payloads."""

import base64
import struct


def decode_relay_sms_payload(content):
    """
    Decodes and extracts information from a base64-encoded payload.

    Args:
        content (str): The base64-encoded payload string.

    Returns:
        tuple: A tuple containing:
            - platform letter (str)
            - encrypted content (bytes)
            - device ID (bytes)
            - error (Exception or None)
    """
    try:
        payload = base64.b64decode(content)

        # Unpack the length of the encrypted content (first 4 bytes)
        len_enc_content = struct.unpack("<i", payload[:4])[0]

        # Extract the platform letter (5th byte)
        platform_letter = chr(payload[4])

        # Extract the encrypted content (next len_enc_content bytes)
        encrypted_content = payload[5 : 5 + len_enc_content]

        # Extract the remaining payload as the device ID
        device_id = payload[5 + len_enc_content :]

        return platform_letter, encrypted_content, device_id, None

    except (struct.error, IndexError, base64.binascii.Error) as e:
        return None, None, None, e
