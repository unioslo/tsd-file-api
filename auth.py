
"""Tools to do authentication and authorization with JWT. Based on
https://github.com/davedoesdev/python-jwt. Offers a python-sqlite
implementation as an alternative to postgresql (which is used by the storage
and retrieval APIs). User info and role is stored in sqlite for persistence,
JWT is generated and validated in this module.
"""

import jwt
import time
from datetime import datetime


def generate_token(email, secret):
    """ATM there is only one role - the app_user role. This allows the client to
    write files into TSD. Default expiry is set to 24 hours from generation.
    Called in main API only _after_ checking a user's role and verification status."""
    claims = {'email': email, 'role': 'app_user'}
    expires = datetime.fromtimestamp(int(time.time()) + (60*60*24))
    token = jwt.generate_jwt(claims, priv_key=secret, algorithm='HS256', expires=expires, jti_size=None)
    return token

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
        return {'message': 'No JWT provided.'}
    except jwt.jws.SignatureError:
        return {'message': 'Access forbidden - Unable to verify signature.'}
    if claims['role'] != required_role:
        return {'message': 'Access forbidden - Your role does not allow this operation.'}
    if int(time.time()) > int(claims['exp']):
        return {'message': 'Access forbidden - JWT expired.'}
    else:
        return True


