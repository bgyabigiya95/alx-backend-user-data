#!/usr/bin/env python3
"""
User passwords should NEVER be stored
in plain text in a database
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Implement a hash_password function that expects one
    string argument name password and returns a salted,
    hashed password, which is a byte string
    """
    hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return(hash)


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Use bcrypt to validate that the provided password
    matches the hashed password
    """
    if bcrypt.checkpw(password.encode(), hashed_password):
        return True

    return False
