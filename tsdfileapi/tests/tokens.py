
import time
from jwcrypto import jwt, jwk
from datetime import datetime, timedelta

from ..db import load_jwk_store


def tk(secret, exp=1, role=None, pnum=None):
    """
    This is the same token generation function as found in tsd-auth-api/auth.py
    """
    allowed_roles = ['app_user', 'full_access_reports_user', 'import_user',
                     'export_user', 'admin_user']
    if role in allowed_roles:
        d = datetime.now() + timedelta(hours=exp)
        exp = int(time.mktime(d.timetuple()))
        if pnum:
            claims = {'role': role, 'exp': exp, 'p': pnum}
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
    p = config['test_project']
    ss = load_jwk_store(config)
    s = ss[p]
    wrong = ss['p01']
    return {
        'VALID': tk(s, role='app_user', pnum=p),
        'MANGLED_VALID': tk(s, role='app_user', pnum=p)[:-1],
        'INVALID_SIGNATURE': tk(wrong, role='app_user', pnum=p),
        'WRONG_ROLE': tk(s, role='admin_user', pnum=p),
        'TIMED_OUT': tk(s, exp=-1, role='app_user', pnum=p)
    }
