
"""Helper functions for testing JWT."""

import string
import base64
import random
import os
import time
from datetime import datetime, timedelta

from jwcrypto import jwt, jwk

def rand_gen():
    alt1 = string.ascii_letters[random.randint(0, len(string.ascii_letters) - 1)]
    alt2 = string.ascii_letters[random.randint(0, len(string.ascii_letters) - 1)]
    altchars = (alt1 + alt2).encode('utf-8')
    return base64.b64encode(os.urandom(32), altchars).decode('utf-8')


def gen_test_jwt_secrets(config):
    secrets = {}
    for proj in range(1, 2000):
        tenant = 'p%02d' % proj
        secrets[tenant] = rand_gen()
    return secrets


def tkn(secret, exp=1, role=None, tenant=None, user=None):
    allowed_roles = ['import_user', 'export_user', 'admin_user', 'wrong_user']
    if role in allowed_roles:
        expiry = datetime.now() + timedelta(hours=exp)
        exp = int(time.mktime(expiry.timetuple()))
        if tenant:
            if not user:
                user = tenant + '-' + role
            claims = {
                # minimal set of claims
                'role': role,
                'exp': exp,
                'proj': tenant,
                'user': user,
                'groups': [tenant + '-member-group']
            }
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
    store = gen_test_jwt_secrets(config)
    secret = store[proj]
    wrong = store['p01']
    user = config['test_user']
    return {
        'VALID': tkn(secret, role='import_user', tenant=proj),
        'MANGLED_VALID': tkn(secret, role='import_user', tenant=proj)[:-1],
        'INVALID_SIGNATURE': tkn(wrong, role='import_user', tenant=proj),
        'WRONG_ROLE': tkn(secret, role='wrong_user', tenant=proj),
        'TIMED_OUT': tkn(secret, exp=-1, role='import_user', tenant=proj),
        'WRONG_PROJECT': tkn(wrong, exp=-1, role='import_user', tenant='p01'),
        'EXPORT': tkn(secret, role='export_user', tenant=proj, user=user),
        'ADMIN': tkn(secret, role='admin_user', tenant=proj, user=user),
        'TEST_SIG': tkn(config['jwt_test_secret'], role='import_user', user=user, tenant=proj)
    }

def get_test_token_for_p12(config):
    store = gen_test_jwt_secrets(config)
    secret = store['p12']
    return tkn(secret, role='import_user', tenant='p12')

def gen_test_token_for_user(config, user):
    store = gen_test_jwt_secrets(config)
    secret = store['p11']
    return tkn(secret, role='import_user', tenant='p11', user=user)
