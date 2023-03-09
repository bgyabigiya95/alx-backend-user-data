#!/usr/bin/env python3
"""Class basic Auth"""

from .auth import Auth
import base64
import re
from models.user import User
from typing import TypeVar


class BasicAuth(Auth):
    """Basic Auth inherits Auth"""
    def extract_base64_authorization_header(
        self,
        authorization_header: str
    ) -> str:
        """Extract Base64 authorization"""
        if type(authorization_header) == str:
            pattern = r'Basic (?P<token>.+)'
            f_match = re.fullmatch(pattern, authorization_header.strip())
            if f_match is not None:
                return f_match.group('token')
        return None

    def decode_base64_authorization_header(
        self,
        base64_authorization_header: str
    ) -> str:
        """Decodes the value of Base64 string"""
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None

        try:
            enc = base64_authorization_header.encode('utf-8')
            dec64 = base64.b64decode(enc)
            decoded = dec64.decode('utf-8')
        except BaseException:
            return None

        return decoded

    def extract_user_credentials(
        self,
        decoded_base64_authorization_header: str
    ) -> (str, str):
        """Extracts user email and password"""
        if decoded_base64_authorization_header is None\
           or not isinstance(decoded_base64_authorization_header, str)\
           or ':' not in decoded_base64_authorization_header:
            return None, None

        credentials = decoded_base64_authorization_header.split(':', 1)
        return credentials[0], credentials[1]

    def user_object_from_credentials(
        self,
        user_email: str,
        user_pwd: str
    ) -> TypeVar('User'):
        """Return Instance based on user email and pwd"""
        if user_email is None\
           or user_pwd is None\
           or not isinstance(user_email, str)\
           or not isinstance(user_pwd, str):
            return None
        try:
            users = User.search({'email': user_email})
        except Exception:
            return None

        for user in users:
            if user.is_valid_password(user_pwd):
                return user

        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Have a complete basic authentication"""
        auth_header = self.authorization_header(request)
        enc = self.extract_base64_authorization_header(auth_header)
        dec = self.decode_base64_authorization_header(enc)
        email, pwd = self.extract_user_credentials(dec)

        if not auth_header\
           or not enc\
           or not dec\
           or not email\
           or not pwd:
            return None
        return self.user_object_from_credentials(email, pwd)
