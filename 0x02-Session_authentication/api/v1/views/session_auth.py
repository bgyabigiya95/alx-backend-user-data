#!/usr/bin/env python3
"""View for Session Authentication"""
from flask import abort, jsonify, request
from api.v1.views import app_views
from models.user import User
from typing import Tuple
import os


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def session_authentication() -> Tuple[str, int]:
    """ POST /api/v1/auth_session/login"""
    not_found_user = {"error": "no user found for this email"}
    email, password = request.form.get('email'), request.form.get('password')
    if email is None or len(email.strip()) == 0:
        return jsonify({"error": "email missing"}), 400
    if password is None or len(password.strip()) == 0:
        return jsonify({"error": "password missing"}), 400
    try:
        user = User.search({'email': email})
    except Exception:
        return jsonify(not_found_user), 404
    if len(user) <= 0:
        return jsonify(not_found_user), 404
    if user[0].is_valid_password(password):
        from api.v1.app import auth
        sessiond_id = auth.create_session(getattr(user[0], 'id'))
        res = jsonify(user[0].to_json())
        res.set_cookie(os.getenv("SESSION_NAME"), sessiond_id)
        return res
    return jsonify({"error": "wrong password"}), 401


@app_views.route(
    '/auth_session/logout',
    methods=['DELETE'],
    strict_slashes=False
)
def delete_session() -> Tuple[str, int]:
    """Delete sessions for user"""
    from api.v1.app import auth
    if not auth.destroy_session(request):
        abort(404)
    return jsonify({}), 200
