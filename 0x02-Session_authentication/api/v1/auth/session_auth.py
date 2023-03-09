#!/usr/bin/env python3
"""Empty Session"""
from .auth import Auth
from uuid import uuid4
from models.user import User


class SessionAuth(Auth):
    """Session Auth that inherits Auth"""
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Creates a session Id"""
        if not isinstance(user_id, str)\
           or user_id is None:
            return None
        new_key = str(uuid4())
        self. user_id_by_session_id[new_key] = user_id
        return new_key

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """Returns user based on a session ID"""
        if not isinstance(session_id, str)\
           or session_id is None:
            return None
        return self.user_id_by_session_id.get(str(session_id))

    def current_user(self, request=None):
        """returns a user instance based on a cookie"""
        user_id = self.user_id_for_session_id(self.session_cookie(request))
        return User.get(user_id)

    def destroy_session(self, request=None):
        """Delete the user session Logout"""
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        if (request is None or session_id is None) or user_id is None:
            return False
        if session_id in self.user_id_by_session_id:
            del self.user_id_by_session_id[session_id]
        return True
