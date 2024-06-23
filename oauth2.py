"""
OAuth2 Client Module.
"""

import os
import logging
import base64
import json
from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.base_client import OAuthError

from utils import get_configs

OAUTH2_CONFIGURATIONS = {
    "gmail": {
        "urls": {
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "userinfo_uri": "https://www.googleapis.com/oauth2/v3/userinfo",
            "send_message_uri": "https://www.googleapis.com/gmail/v1/users/{}/messages/send",
            "revoke_uri": "https://oauth2.googleapis.com/revoke",
        },
        "default_params": {
            "scope": [
                "openid",
                "https://www.googleapis.com/auth/gmail.send",
                "https://www.googleapis.com/auth/userinfo.profile",
                "https://www.googleapis.com/auth/userinfo.email",
            ],
            "access_type": "offline",
            "prompt": "consent",
        },
    },
}

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("[OAuth2 Client]")


def load_credentials(platform_name):
    """
    Load client credentials from a JSON file specified in environment variables.

    Args:
        platform_name (str): The name of the platform (e.g., 'gmail').

    Returns:
        dict: A dictionary containing client_id, client_secret, and redirect_uri.
    """
    creds_file = get_configs(f"{platform_name.upper()}_CREDENTIALS")

    if not creds_file:
        raise ValueError(
            f"Missing environment variable for {platform_name.upper()}_CREDENTIALS"
        )

    with open(creds_file, "r", encoding="utf-8") as file:
        creds = json.load(file)

    def find_nested_credentials(data):
        for key, value in data.items():
            if isinstance(value, dict):
                nested_creds = find_nested_credentials(value)
                if nested_creds:
                    return nested_creds
            elif key in ["client_id", "client_secret", "redirect_uri", "redirect_uris"]:
                return data
        return None

    creds_data = find_nested_credentials(creds)
    if not creds_data:
        raise ValueError(
            f"Credentials not found in the JSON file for platform: {platform_name}"
        )

    required_fields = {
        "client_id": creds_data.get("client_id"),
        "client_secret": creds_data.get("client_secret"),
        "redirect_uris": creds_data.get("redirect_uris", []),
    }

    redirect_uri = required_fields["redirect_uris"][0]

    return {
        "client_id": required_fields["client_id"],
        "client_secret": required_fields["client_secret"],
        "redirect_uri": redirect_uri,
    }


class OAuth2Client:
    """
    OAuth2 client implementation using Authlib.
    """

    def __init__(self, platform_name, token=None, update_token=None):
        """
        Initialize the OAuth2Client.

        Args:
            platform_name (str): The name of the platform (e.g., 'gmail', 'twitter').
            token (dict, optional): The OAuth 2.0 token containing 'access_token',
                'refresh_token', 'expires_at', and other relevant token information.
                Default is None.
            update_token (callable, optional): A callable function that updates the
                OAuth 2.0 token. Used when refreshing tokens. Default is None.
        """
        oauth2_config = OAUTH2_CONFIGURATIONS.get(platform_name.lower())

        if not oauth2_config:
            raise ValueError(f"Configuration for platform '{platform_name}' not found.")

        self.platform = platform_name
        self.creds = load_credentials(self.platform)
        self.urls = oauth2_config["urls"]
        self.default_params = oauth2_config["default_params"]
        self.session = OAuth2Session(
            client_id=self.creds["client_id"],
            client_secret=self.creds["client_secret"],
            redirect_uri=self.creds["redirect_uri"],
            token_endpoint=self.urls["token_uri"],
            token=token,
            update_token=update_token,
        )

    @staticmethod
    def generate_code_verifier(length=128):
        """
        Generate a code verifier for PKCE.

        Args:
            length (int, optional): Length of the code verifier. Default is 128.

        Returns:
            str: The generated code verifier.
        """
        code_verifier = base64.urlsafe_b64encode(os.urandom(length)).decode("utf-8")
        return "".join(c for c in code_verifier if c.isalnum())

    def get_authorization_url(self, autogenerate_code_verifier=False, **kwargs):
        """
        Get the authorization URL.

        Args:
            autogenerate_code_verifier (bool, optional): Whether to auto-generate
                a code verifier for PKCE. Default is False.
            **kwargs: Additional parameters to include in the authorization URL.

        Returns:
            tuple: A tuple containing the authorization URL (str), state (str), and
                optionally generated code verifier (str).
        """
        code_verifier = kwargs.get("code_verifier")

        if autogenerate_code_verifier and not code_verifier:
            code_verifier = self.generate_code_verifier(48)
            kwargs["code_verifier"] = code_verifier
            self.session.code_challenge_method = "S256"

        if code_verifier:
            kwargs["code_verifier"] = code_verifier
            self.session.code_challenge_method = "S256"

        params = {**self.default_params, **kwargs}

        authorization_url, state = self.session.create_authorization_url(
            self.urls["auth_uri"], **params
        )

        logger.info("Authorization URL generated: %s", authorization_url)
        return authorization_url, state, code_verifier

    def fetch_token(self, code, **kwargs):
        """
        Fetch the access token using the authorization code.

        Args:
            code (str): The authorization code.
            **kwargs: Additional parameters for fetching the token.

        Returns:
            dict: The token response.
        """
        logger.debug("Fetching access token...")
        token_response = self.session.fetch_token(
            self.urls["token_uri"], code=code, **kwargs
        )
        logger.info("Access token fetched successfully.")
        return token_response

    def fetch_userinfo(self):
        """
        Fetch user information using the access token.

        Returns:
            dict: User information response.
        """
        logger.debug("Fetching user information...")
        userinfo = self.session.get(self.urls["userinfo_uri"]).json()
        logger.info("User information fetched successfully.")
        return userinfo

    def revoke_token(self):
        """
        Revoke the given OAuth2 token.

        Returns:
            dict: The response from the revocation endpoint.
        """
        try:
            refreshed_tokens = self.session.refresh_token(self.urls.get("token_uri"))
            self.session.token = refreshed_tokens
            response = self.session.revoke_token(self.urls.get("revoke_uri"))

            if response.status_code != 200:
                response_data = response.json()
                error_message = response_data["error"].get("message", "Unknown error")
                logger.error(
                    "Failed to revoke tokens for %s: %s", self.platform, response_data
                )
                return error_message

            response_data = response.json()
            logger.info("Token revoked successfully.")
            return response_data
        except OAuthError as e:
            logger.error("Error revoking OAuth2 token: %s", e)
            return e

    def send_message(self, user_id, message):
        """
        Send a message.

        Args:
            user_id (str): The ID of the user to send the message on behalf of.
            message (dict): The message payload to be sent. The payload should be a
                properly formatted dictionary according to the platform's specifications.

        Returns:
            dict: The response from the platform.
        """
        logger.debug("Sending message on behalf of user_id: %s", user_id)
        url = self.urls["send_message_uri"].format(user_id)
        response = self.session.post(url, json=message)

        if response.status_code != 200:
            response_data = response.json()
            error_message = response_data["error"].get("message", "Unknown error")
            logger.error(
                "Failed to send message for %s: %s", self.platform, response_data
            )
            return error_message

        response_data = response.json()
        logger.info("Successfully sent message for '%s'", self.platform)

        return f"Successfully sent message to '{self.platform}' on your behalf."
