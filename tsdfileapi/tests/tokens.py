
import jwt
from datetime import datetime
import time

def generate_token(email, secret, token_type=None, import_role=None, export_role=None, \
                    import_timeout=(60*60*24), export_timeout=(60*60)):
    """Import tokens last for 24 hours and export tokens last for one hour."""
    if token_type == 'import':
        claims = {'email': email, 'role': import_role}
        timeout = import_timeout
    elif token_type == 'export':
        claims = {'role': export_role}
        timeout = export_timeout
    else:
        raise Exception('token_type not specified by caller')
    expires = datetime.fromtimestamp(int(time.time()) + timeout)
    token = jwt.generate_jwt(claims, priv_key=secret, algorithm='HS256', \
        expires=expires, jti_size=None)
    return token

TEST_IMPORT_USER = 'health@check.local'
TEST_EXPORT_USER = '20097000574'
TEST_SECRET = 'testsecret'

IMPORT_TOKENS = {
    'VALID': generate_token(TEST_IMPORT_USER, TEST_SECRET, token_type='import', \
        import_role='app_user'),
    'MANGLED_VALID': generate_token(TEST_IMPORT_USER, TEST_SECRET, token_type='import', \
        import_role='app_user')[:-1],
    'INVALID_SIGNATURE': generate_token(TEST_IMPORT_USER, 'WRONG_SECRET', token_type='import', \
        import_role='app_user'),
    'WRONG_ROLE': generate_token(TEST_IMPORT_USER, TEST_SECRET, token_type='import', \
        import_role='WRONG_ROLE'),
    'TIMED_OUT': generate_token(TEST_IMPORT_USER, TEST_SECRET, token_type='import', \
        import_role='app_user', import_timeout=(-(60*60*25)))
}

EXPORT_TOKENS = {
    'VALID': generate_token(TEST_EXPORT_USER, TEST_SECRET, token_type='export', \
        export_role='full_access_reports_user'),
    'MANGLED_VALID': generate_token(TEST_EXPORT_USER, TEST_SECRET, token_type='export', \
        export_role='full_access_reports_user')[:-1],
    'INVALID_SIGNATURE': generate_token(TEST_EXPORT_USER, 'BAD_SECRET', token_type='export', \
        export_role='full_access_reports_user'),
    'WRONG_ROLE': generate_token(TEST_EXPORT_USER, TEST_SECRET, token_type='export', \
        export_role='full_access_mofo'),
    'TIMED_OUT': generate_token(TEST_EXPORT_USER, TEST_SECRET, token_type='export', \
        export_role='full_access_reports_user', export_timeout=(-(60*60)))
}
