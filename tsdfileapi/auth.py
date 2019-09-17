
"""Tools to do authentication and authorization with JWT."""

import json
import time
import logging
from jwcrypto import jwt, jwk, jws


def verify_json_web_token(auth_header, secret, roles_allowed, pnum):
    """
    Verifies the authenticity of API credentials, as stored in a
    JSON Web Token (see jwt.io for more).

    Parameters
    ----------
    auth_header: string (HTTP header)
    secret: base64 encoded string
    required_role: string (role that should be in the claim)
    pnum: string

    Details
    -------
    0) Checks for the existence of a token
    1) Checks the cryptographic integrity of the token - that it was obtained
       from an authoritative source with access to the secret key
    2) Extracts the JWT header and the claims
    3) Checks that the token grants access to the requested project
    4) Checks that the role assigned to the user in the db is allowed to perform
       the action - the caller passes the authorized list
    5) Checks that the token has not expired - 1 hour is the current lifetime

    If the JWT authn+z fails in any way we log the reason but do not communicate
    it to the client. The only information they get is that the requested
    operation is forbidden. This sacrifices usability in favour of providing
    less information about the authentication and authorization scheme to
    potential attackers.

    Returns
    -------
    dict {message, status, user}

    """
    failure_message = {'message': 'Access forbidden', 'status': False, 'reason': None}
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
        return failure_message
    except jws.InvalidJWSSignature as e:
        logging.error('Invalid JWT signature')
        return failure_message
    except Exception as e:
        logging.error(e.message)
        failure_message['reason'] = e.message
        return failure_message
    if claims['proj'] != pnum:
        # this _should_ be impossible
        logging.error('Access denied to project - mismatch in project numbers')
        return failure_message
    if claims['role'] not in roles_allowed:
        if len(roles_allowed) > 0: # an empty list means we do not specify it here
            logging.error('Role not allowed to perform requested operation')
            return failure_message
    if int(time.time()) > int(claims['exp']):
        logging.error('JWT expired')
        return failure_message
    return {'message': 'OK', 'status': True, 'claims': claims}
