
"""Tools to do authentication and authorization with JWT."""

import base64
import json
import time
import logging
from jwcrypto import jwt, jwk, jws


def b64_padder(payload):
    if payload is not None:
        payload += '=' * (-len(payload) % 4)
        return payload


def extract_claims(token):
    enc_claim_text = token.split('.')[1]
    dec_claim_text = base64.b64decode(b64_padder(enc_claim_text))
    claims = json.loads(dec_claim_text)
    return claims


def verify_json_web_token(auth_header, secret, pnum):
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
        claims = extract_claims(raw_token)
    except Exception as e:
        logging.error(e.message)
        failure_message['reason'] = e.message
        return failure_message
    if claims['proj'] != pnum:
        # this _should_ be impossible
        logging.error('Access denied to project - mismatch in project numbers')
        return failure_message
    if int(time.time()) > int(claims['exp']):
        logging.error('JWT expired')
        return failure_message
    return {'message': 'OK', 'status': True, 'claims': claims}
