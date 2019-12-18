
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


def process_access_token(auth_header, pnum, check_tenant, check_exp):
    """
    Extract claims, check tenant access, and expiry.

    Parameters
    ----------
    auth_header: string (HTTP header)
    pnum: string

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
        logging.error('Access denied to project - mismatch in project numbers')
        return failure_message
    if int(time.time()) > int(claims['exp']):
        logging.error('JWT expired')
        return failure_message
    return {'message': 'OK', 'status': True, 'claims': claims}
