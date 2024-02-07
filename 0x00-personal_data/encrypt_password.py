#!/usr/bin/env python3
"""
Encrypting passwords with bcrypt
"""


import bcrypt


def hash_password(password: str) -> bytes:
    """
    Salted pass generation to encrypt password
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ is the password valid?
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
