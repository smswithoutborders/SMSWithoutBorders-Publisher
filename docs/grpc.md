# Publisher gRPC Documentation

## Table of Contents

- [Download Protocol Buffer File](#download-protocol-buffer-file)
  - [Version 1](#version-1)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
  - [OAuth2](#oauth2)
    - [Get Authorization URL](#get-authorization-url)
    - [Exchange OAuth2 Code](#exchange-oauth2-code)

## Download Protocol Buffer File

To use the gRPC functions, download the protocol buffer file from the
[proto](/protos/) directory corresponding to the desired version.

### Version 1

```bash
curl -O -L https://raw.githubusercontent.com/smswithoutborders/SMSWithoutBorders-Publisher/feature/grpc-api/protos/v1/publisher.proto
```

## Prerequisites

### Install Dependencies

If you're using Python, install the necessary dependencies from
`requirements.txt`. For other languages, see
[Supported languages](https://grpc.io/docs/languages/).

> [!TIP]
>
> It's recommended to set up a virtual environment to isolate your project's
> dependencies.

```bash
python3 -m venv venv
source venv/bin/activate
```

```bash
pip install -r requirements.txt
```

### Compile gRPC for Python

If you're using Python, compile the gRPC files with `protoc` to generate the
necessary Python files. For other languages, see
[Supported languages](https://grpc.io/docs/languages/).

```bash
python -m grpc_tools.protoc -I protos/v1 --python_out=. --grpc_python_out=. protos/v1/publisher.proto
```

## Usage

## OAuth2

### Get Authorization URL

This method generates an OAuth2 authorization URL that the client can use to
start the OAuth2 flow.

#### Request

> `request` **GetAuthorizationUrlRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field                  | Type   | Description                                          |
| ---------------------- | ------ | ---------------------------------------------------- |
| redirect_uri           | string | The URI to redirect to after the user authorizes.    |
| client_id              | string | The client ID for the OAuth2 application.            |
| scope                  | array  | The requested scope(s) for the OAuth2 authorization. |
| authorization_endpoint | string | The authorization endpoint of the OAuth2 provider.   |

Optional fields:

| Field                      | Type   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| -------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| state                      | string | An opaque value used to maintain state between the request and the callback.                                                                                                                                                                                                                                                                                                                                                                    |
| prompt                     | string | This parameter is a space-delimited, case-sensitive list of prompts to present to the user, with possible values: `none` (no screens, cannot be combined), `consent` (prompts for consent), and `select_account` (prompts to select an account).                                                                                                                                                                                                |
| code_verifier              | string | A cryptographic random string used in the PKCE flow.                                                                                                                                                                                                                                                                                                                                                                                            |
| autogenerate_code_verifier | bool   | If true, a code verifier will be auto-generated if not provided.                                                                                                                                                                                                                                                                                                                                                                                |
| access_type                | string | This parameter determines if your application can refresh access tokens when the user is not present at the browser. Valid values are `online` (default) and `offline`. Set it to `offline` if your application needs to refresh access tokens without user presence. This instructs the Google authorization server to return both a refresh token and an access token when your application first exchanges an authorization code for tokens. |

---

#### Response

> `response` **GetAuthorizationUrlResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field             | Type   | Description                                                     |
| ----------------- | ------ | --------------------------------------------------------------- |
| authorization_url | string | The generated authorization URL.                                |
| state             | string | The state parameter sent in the request, if provided.           |
| code_verifier     | string | The code verifier used in the PKCE flow, if provided/generated. |
| message           | string | A response message from the server.                             |

---

#### Method

> `method` **GetAuthorizationUrl**

> [!TIP]
>
> The examples below use
> [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

**Sample request**

```bash
grpcurl -plaintext \
    -d @ \
    -proto protos/v1/publisher.proto \
localhost:6000 publisher.v1.Publisher/GetAuthorizationUrl <payload.json
```

---

**Sample payload.json**

```json
{
	"redirect_uri": "https://example.com/callback",
	"client_id": "your_client_id",
	"scope": ["openid", "profile"],
	"authorization_endpoint": "https://accounts.google.com/o/oauth2/auth"
}
```

---

**Sample response**

```json
{
	"authorization_url": "https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=your_client_id&redirect_uri=https://example.com/callback&scope=openid%20profile&state=xyz&code_challenge=abcdef&code_challenge_method=S256",
	"state": "xyz",
	"code_verifier": "abcdef",
	"message": "Successfully generated authorization url"
}
```

### Exchange OAuth2 Code

This method exchanges an OAuth2 authorization code for access and refresh
tokens, and fetches the user's profile information.

#### Request

> `request` **ExchangeOAuth2CodeRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field              | Type   | Description                                               |
| ------------------ | ------ | --------------------------------------------------------- |
| authorization_code | string | The authorization code received from the OAuth2 provider. |
| redirect_uri       | string | The URI to redirect to after the user authorizes.         |
| client_id          | string | The client ID for the OAuth2 application.                 |
| client_secret      | string | The client secret for the OAuth2 application.             |
| token_endpoint     | string | The token endpoint of the OAuth2 provider.                |
| userinfo_endpoint  | string | The userinfo endpoint of the OAuth2 provider.             |

Optional fields:

| Field         | Type   | Description                                          |
| ------------- | ------ | ---------------------------------------------------- |
| code_verifier | string | A cryptographic random string used in the PKCE flow. |

---

#### Response

> `response` **ExchangeOAuth2CodeResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field   | Type   | Description                                              |
| ------- | ------ | -------------------------------------------------------- |
| token   | string | The retrieved access and refresh tokens, in JSON format. |
| profile | string | The user's profile information, in JSON format.          |
| message | string | A response message from the server.                      |

---

#### Method

> `method` **ExchangeOAuth2Code**

> [!TIP]
>
> The examples below use
> [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

**Sample request**

```bash
grpcurl -plaintext \
    -d @ \
    -proto protos/v1/publisher.proto \
localhost:6000 publisher.v1.Publisher/ExchangeOAuth2Code <payload.json
```

---

**Sample payload.json**

```json
{
	"authorization_code": "auth_code",
	"redirect_uri": "https://example.com/callback",
	"client_id": "your_client_id",
	"client_secret": "your_client_secret",
	"token_endpoint": "https://accounts.google.com/o/oauth2/token",
	"userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo"
}
```

---

**Sample response**

```json
{
	"token": "{\"access_token\":\"ya29.a0AfH6SMB...\",\"expires_in\":3599,\"refresh_token\":\"1//06uC...\",\"scope\":\"https://www.googleapis.com/auth/userinfo.profile openid\",\"token_type\":\"Bearer\"}",
	"profile": "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"given_name\":\"John\",\"family_name\":\"Doe\",\"picture\":\"https://example.com/johndoe.jpg\",\"email\":\"johndoe@example.com\",\"email_verified\":true,\"locale\":\"en\"}",
	"message": "Successfully fetched tokens"
}
```
