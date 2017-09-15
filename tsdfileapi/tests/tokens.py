
import time
from jwcrypto import jwt, jwk
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool
from sqlalchemy.orm import sessionmaker
from contextlib import contextmanager

# --- TODO: figure out how to import these from module ----

@contextmanager
def session_scope(engine):
    """Provide a transactional scope around a series of operations."""
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
        session.commit()
    except (OperationalError, IntegrityError, StatementError) as e:
        logging.error("Could not commit data")
        logging.error("Rolling back transaction")
        session.rollback()
        raise e
    finally:
        session.close()


def _postgres_connect_str(config):
    user = config['ss_user']
    pw = config['ss_pw']
    host = config['ss_host']
    db = config['ss_dbname']
    connect_str = ''.join(['postgresql://', user, ':', pw, '@', host, ':5432/', db])
    return connect_str


def _pg_connect(config):
    if config['ss_ssl']:
        args = { 'sslmode':'require' }
    else:
        args = {}
    dburl = _postgres_connect_str(config)
    engine = create_engine(dburl, connect_args=args, poolclass=QueuePool)
    return engine


def load_jwk_store(config):
    secrets = {}
    engine = _pg_connect(config)
    with session_scope(engine) as session:
        res = session.execute('select pnum, secret from project_jwks').fetchall()
    for row in res:
        secrets[row[0]] = row[1]
    return secrets

# ---------------------------------------------------------


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
