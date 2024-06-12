"""
OAuth2 Client Module.
"""

import os
import logging
import base64
from authlib.integrations.requests_client import OAuth2Session

logging.basicConfig(
    level=logging.INFO, format=("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
)
logger = logging.getLogger("[OAuth2 Client]")


class OAuth2Client:
    """
    OAuth2 client implementation using Authlib.
    """

    def __init__(self, client_id=None, client_secret=None, redirect_uri=None, **kwargs):
        """
        Initialize the OAuth2Client.

        Args:
            client_id (str, optional): The client ID.
            client_secret (str, optional): The client secret.
            redirect_uri (str, optional): The redirect URI.
            **kwargs: Additional parameters.
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.session = OAuth2Session(
            client_id=self.client_id,
            client_secret=self.client_secret,
            redirect_uri=redirect_uri,
            **kwargs,
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

    def get_authorization_url(
        self, auth_uri=None, autogenerate_code_verifier=False, **kwargs
    ):
        """
        Get the authorization URL.

        Args:
            auth_uri (str): The authorization URI.
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

        authorization_url, state = self.session.create_authorization_url(
            auth_uri, **kwargs
        )

        logger.info("Authorization URL generated: %s", authorization_url)
        return authorization_url, state, code_verifier

    def fetch_token(self, token_uri, code, **kwargs):
        """
        Fetch the access token using the authorization code.

        Args:
            token_uri (str): The token URI.
            code (str): The authorization code.
            **kwargs: Additional parameters for fetching the token.

        Returns:
            dict: The token response.
        """
        logger.debug("Fetching access token...")
        token_response = self.session.fetch_token(token_uri, code=code, **kwargs)
        logger.info("Access token fetched successfully.")
        return token_response

    def fetch_userinfo(self, userinfo_uri):
        """
        Fetch user information using the access token.

        Args:
            userinfo_uri (str): The userinfo URI provided by the OAuth2 provider.

        Returns:
            dict: User information response.
        """
        logger.debug("Fetching user information...")
        userinfo = self.session.get(userinfo_uri).json()
        logger.info("User information fetched successfully.")
        return userinfo
