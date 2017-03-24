
"""Tools to do authentication and authorization with JWT. Based on
https://github.com/davedoesdev/python-jwt."""

import jwt
import time
from datetime import datetime

def verify_json_web_token(auth_header, jwt_secret, required_role=None):
    """Verifies the authenticity of API credentials, as stored in a JSON Web Token
    (see jwt.io for more).

    Details:
    0) Checks for the existence of a token
    1) Checks the cryptographic integrity of the token - that it was obtained from an
    authoritative source with access to the secret key
    2) Extracts the JWT header and the claims
    3) Checks that the role assigned to the user in the db is allowed to perform the action
    4) Checks that the token has not expired - 1 hour is the current lifetime
    """
    try:
        token = auth_header.split(' ')[1]
        header, claims = jwt.verify_jwt(token, jwt_secret, ['HS256'], checks_optional=True)
    except KeyError:
        return {
            'message': 'No JWT provided.',
            'status': False
            }
    except jwt.jws.SignatureError:
        return {
            'message': 'Access forbidden - Unable to verify signature.',
            'status': False
            }
    if claims['role'] != required_role:
        return {
        'message': 'Access forbidden - Your role does not allow this operation.',
        'status': False
        }
    if int(time.time()) > int(claims['exp']):
        return {
            'message': 'Access forbidden - JWT expired.',
            'status': False
            }
    else:
        return { 'message': 'Token OK', 'status': True }


