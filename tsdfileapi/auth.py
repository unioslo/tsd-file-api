
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


def process_access_token(
        auth_header,
        tenant,
        check_tenant,
        check_exp,
        tenant_claim_name,
        verify_with_secret=None):
    """
    Extract claims, check tenant access, and expiry.

    Parameters
    ----------
    auth_header: string (HTTP header)
    tenant: string

    Returns
    -------
    dict {message, status, user}

    """
    failure_message = {'message': 'Access forbidden', 'status': False, 'reason': None}
    try:
        raw_token = auth_header.split(' ')[1]
        if not verify_with_secret:
            claims = extract_claims(raw_token)
        else:
            k = {'k': verify_with_secret, 'kty': 'oct'}
            key = jwk.JWK(**k)
            token = jwt.JWT(algs=['HS256'])
            try:
                token.deserialize(raw_token, key=key)
                claims = json.loads(token.claims)
            except jws.InvalidJWSSignature as e:
                return failure_message
    except Exception as e:
        logging.error(e.message)
        failure_message['reason'] = e.message
        return failure_message
    if check_tenant and claims[tenant_claim_name] != tenant:
        logging.error('Access denied to tenant: %s != %s ', claims[tenant_claim_name], tenant)
        return failure_message
    if check_exp and int(time.time()) > int(claims['exp']):
        logging.error('JWT expired')
        return failure_message
    return {'message': 'OK', 'status': True, 'claims': claims}
