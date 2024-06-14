"""
OAuth2 Client Module.
"""

import os
import logging
import base64
import json
from authlib.integrations.requests_client import OAuth2Session

from utils import get_configs

PLATFORM_URLS = {
    "gmail": {
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "userinfo_uri": "https://www.googleapis.com/oauth2/v3/userinfo",
    },
}

PLATFORM_DEFAULT_PARAMS = {
    "gmail": {
        "scope": [
            "openid",
            "https://www.googleapis.com/auth/gmail.send",
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
        ],
        "access_type": "offline",
        "prompt": "consent",
    },
}

logging.basicConfig(
    level=logging.INFO, format=("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
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

    def __init__(self, platform_name):
        """
        Initialize the OAuth2Client.

        Args:
            platform_name (str): The name of the platform (e.g., 'gmail').
        """
        urls = PLATFORM_URLS.get(platform_name.lower())

        if not urls:
            raise ValueError(f"URLs for platform '{platform_name}' not found.")

        self.creds = load_credentials(platform_name)
        self.urls = PLATFORM_URLS.get(platform_name.lower())
        self.default_params = PLATFORM_DEFAULT_PARAMS.get(platform_name, {})
        self.session = OAuth2Session(
            client_id=self.creds["client_id"],
            client_secret=self.creds["client_secret"],
            redirect_uri=self.creds["redirect_uri"],
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
