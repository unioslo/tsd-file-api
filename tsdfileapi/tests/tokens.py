
"""Helper functions for testing JWT."""

import time
from datetime import datetime, timedelta

from jwcrypto import jwt, jwk

from ..db import load_jwk_store


def tkn(secret, exp=1, role=None, pnum=None, user=None):
    """
    This is the same token generation function as found in tsd-auth-api/auth.py
    """
    allowed_roles = ['app_user', 'full_access_reports_user', 'import_user',
                     'export_user', 'admin_user']
    if role in allowed_roles:
        expiry = datetime.now() + timedelta(hours=exp)
        exp = int(time.mktime(expiry.timetuple()))
        if pnum:
            if not user:
                user = pnum + '-' + role
            claims = {'role': role, 'exp': exp, 'p': pnum,
                      'u': user}
        else:
            claims = {'role': role, 'exp': exp}
    else:
        raise Exception('specified role not allowed')
    k = {'k': secret, 'kty': 'oct'}
    key = jwk.JWK(**k)
    token = jwt.JWT(header={'alg': 'HS256'}, claims=claims, algs=['HS256'])
    token.make_signed_token(key)
    return token.serialize()


def gen_test_tokens(config):
    """
    A set of tokens to be used in tests.
    """
    proj = config['test_project']
    store = load_jwk_store(config)
    secret = store[proj]
    wrong = store['p01']
    return {
        'VALID': tkn(secret, role='app_user', pnum=proj),
        'MANGLED_VALID': tkn(secret, role='app_user', pnum=proj)[:-1],
        'INVALID_SIGNATURE': tkn(wrong, role='app_user', pnum=proj),
        'WRONG_ROLE': tkn(secret, role='full_access_reports_user', pnum=proj),
        'TIMED_OUT': tkn(secret, exp=-1, role='app_user', pnum=proj),
        'WRONG_PROJECT': tkn(wrong, exp=-1, role='app_user', pnum='p01')
    }
