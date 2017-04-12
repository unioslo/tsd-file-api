
from jwcrypto import jwt, jwk
from datetime import datetime, timedelta
import time

def generate_token(email, secret, token_type=None, import_role=None, export_role=None, \
                    import_timeout=(datetime.now() + timedelta(hours=24)), \
                    export_timeout=(datetime.now() + timedelta(hours=1))):
    """Import tokens last for 24 hours and export tokens last for one hour."""
    if token_type == 'import':
        exp = int(time.mktime(import_timeout.timetuple()))
        claims =  {'email': email, 'role': import_role, 'exp': exp}
    elif token_type == 'export':
        exp = int(time.mktime(export_timeout.timetuple()))
        claims = {'role': export_role, 'exp': exp}
    else:
        raise Exception('token_type not specified by caller')
    k = {'k': secret, 'kty': 'oct'}
    key = jwk.JWK(**k)
    token = jwt.JWT(header={'alg': 'HS256'}, claims=claims, algs=['HS256'])
    token.make_signed_token(key)
    return token.serialize()


TEST_IMPORT_USER = 'health@check.local'
TEST_EXPORT_USER = '20097000574'
TEST_IMPORT_SECRET = 'dGVzdF9pbXBvcnRfc2VjcmV0'
TEST_EXPORT_SECRET = 'dGVzdF9leHBvcnRfc2VjcmV0'


IMPORT_TOKENS = {
    'VALID': generate_token(TEST_IMPORT_USER, TEST_IMPORT_SECRET, token_type='import', \
        import_role='app_user'),
    'MANGLED_VALID': generate_token(TEST_IMPORT_USER, TEST_IMPORT_SECRET, token_type='import', \
        import_role='app_user')[:-1],
    'INVALID_SIGNATURE': generate_token(TEST_IMPORT_USER, 'WRONG_SECRET', token_type='import', \
        import_role='app_user'),
    'WRONG_ROLE': generate_token(TEST_IMPORT_USER, TEST_IMPORT_SECRET, token_type='import', \
        import_role='WRONG_ROLE'),
    'TIMED_OUT': generate_token(TEST_IMPORT_USER, TEST_IMPORT_SECRET, token_type='import', \
        import_role='app_user', import_timeout=(datetime.utcnow() + timedelta(hours=-1)))
}


EXPORT_TOKENS = {
    'VALID': generate_token(TEST_EXPORT_USER, TEST_EXPORT_SECRET, token_type='export', \
        export_role='full_access_reports_user'),
    'MANGLED_VALID': generate_token(TEST_EXPORT_USER, TEST_EXPORT_SECRET, token_type='export', \
        export_role='full_access_reports_user')[:-1],
    'INVALID_SIGNATURE': generate_token(TEST_EXPORT_USER, 'BAD_SECRET', token_type='export', \
        export_role='full_access_reports_user'),
    'WRONG_ROLE': generate_token(TEST_EXPORT_USER, TEST_EXPORT_SECRET, token_type='export', \
        export_role='full_access_mofo'),
    'TIMED_OUT': generate_token(TEST_EXPORT_USER, TEST_EXPORT_SECRET, token_type='export', \
        export_role='full_access_reports_user', export_timeout=(datetime.utcnow() + timedelta(hours=-1)))
}
