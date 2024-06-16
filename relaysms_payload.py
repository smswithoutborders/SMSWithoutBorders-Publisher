"""Module for decoding and extracting information from RelaySMS payloads."""

import base64
import struct


def decode_relay_sms_payload(content):
    """
    Decodes and extracts information from a base64-encoded payload.

    Args:
        content (str): The base64-encoded payload string.

    Returns:
        tuple: A tuple containing the platform letter, encrypted content, and device ID.

    Raises:
        ValueError: If the payload format is invalid or if decoding fails.
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

        return platform_letter, encrypted_content, device_id

    except (struct.error, IndexError, base64.binascii.Error) as e:
        raise ValueError("Invalid payload format") from e


if __name__ == "__main__":
    platform_letter = b"g"
    encrypted_content = b"encrypted_content"
    device_id = b"device_id"

    payload = (
        struct.pack("<i", len(encrypted_content))
        + platform_letter
        + encrypted_content
        + device_id
    )
    encoded_payload = base64.b64encode(payload)

    result = decode_relay_sms_payload(encoded_payload)
    if result:
        platform_letter, encrypted_content, device_id = result
        print(f"Platform letter: {platform_letter}")
        print(f"Encrypted content: {encrypted_content}")
        print(f"Device ID: {device_id}")
