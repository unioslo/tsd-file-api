
"""Tools to do authentication and authorization with JWT."""

import json
import time
import logging
from jwcrypto import jwt, jwk, jws
from datetime import datetime

def verify_json_web_token(auth_header, secret, required_role=None):
    """Verifies the authenticity of API credentials, as stored in a JSON Web Token
    (see jwt.io for more).

    Details:
    0) Checks for the existence of a token
    1) Checks the cryptographic integrity of the token - that it was obtained from an
    authoritative source with access to the secret key
    2) Extracts the JWT header and the claims
    3) Checks that the role assigned to the user in the db is allowed to perform the action
    4) Checks that the token has not expired - 1 hour is the current lifetime

    If the JWT authn+z fails in any way we log the reason but do not communicate
    it to the client. The only information they get is that the requested operation
    is forbidden. This sacrifices usability in favour of providing less information
    about the authentication and authorization scheme to potential attackers.
    """
    try:
        raw_token = auth_header.split(' ')[1]
        k = {'k': secret, 'kty': 'oct'}
        key = jwk.JWK(**k)
        token = jwt.JWT(algs=['HS256'])
        token.deserialize(raw_token, key=key)
        # make sure to specify the algorithm
        claims = json.loads(token.claims)
    except KeyError:
        logging.error('No JWT provided')
        return {
            'message': 'Access forbidden',
            'status': False
            }
    except jws.InvalidJWSSignature as e:
        logging.error('Invalid JWT signature')
        return {
            'message': 'Access forbidden',
            'status': False
            }
    except Exception as e:
        logging.error(e)
        logging.error('JWT expired')
        return {
            'message': 'Access forbidden',
            'status': False
           }
    if claims['role'] != required_role:
        logging.error('role not allowed to perform requested operation')
        return {
            'message': 'Access forbidden',
            'status': False
        }
    if int(time.time()) > int(claims['exp']):
        logging.error('JWT expired')
        return {
            'message': 'Access forbidden',
            'status': False
            }
    else:
        return { 'message': 'OK', 'status': True }


