# Publisher Specifications Documentation

## Payload Format

The payload consists of three parts:

1. **Platform Letter**: A shortcode used to identify the target platform. For a
   list of supported platforms and their corresponding shortcodes, refer to the
   [Supported Platforms](/docs/grpc.md#supported-platforms) section.
2. **Encrypted Content**: The content to be published, encrypted by an entity.
3. **Device ID**: A unique device identifier for the requesting device.

### Structure of the Payload

- The first 4 bytes represent the length of the encrypted content.
- The 5th byte is the platform letter.
- The next `length of the encrypted content` bytes contain the encrypted
  content.
- The remaining bytes after the encrypted content represent the device ID.

### Detailed Byte Layout

1. **Length of Encrypted Content** (4 bytes)
2. **Platform Letter** (1 byte)
3. **Encrypted Content** (variable length, as indicated by the first 4 bytes)
4. **Device ID** (remaining bytes)

### Example Layout

```
+---------------------+---------------+-------------------------+-----------------+
| 4 bytes             | 1 byte        | Variable length         | Remaining bytes |
| Length of encrypted | Platform      | Encrypted content       | Device ID       |
| content             | Letter        |                         |                 |
+---------------------+---------------+-------------------------+-----------------+
```

### Code Example (Python)

**Encoding Example:**

```python
import struct
import base64

platform_letter = b'g'
encrypted_content=b'...'
device_id=b'...'

payload = struct.pack("<i", len(encrypted_content)) + pl + encrypted_content + device_id
incoming_payload = base64.b64encode(payload)
```

**Decoding Example:**

```python
payload = base64.b64decode(incoming_payload)
len_enc_content = struct.unpack("<i", payload[:4])[0]
platform_letter = chr(payload[4])
encrypted_content = payload[5 : 5 + len_enc_content]
device_id = payload[5 + len_enc_content :]
```
