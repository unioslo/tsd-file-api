import logging
import sqlite3

import psycopg2.extensions
import psycopg2.pool

logger = logging.getLogger(__name__)


def pg_listen_channel(
    pool: psycopg2.pool.SimpleConnectionPool,
    channel_name: str,
) -> psycopg2.extensions.connection:
    conn = pool.getconn()
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    curs = conn.cursor()
    curs.execute(f"listen {channel_name};")
    logger.info(f"listening on postgres channel: {channel_name}")
    return conn


def sqlite_init(
    path: str,
    name: str = "api-data.db",
    builtin: bool = False,
) -> sqlite3.Connection:
    engine = sqlite3.connect(f"{path}/{name}")
    return engine


def postgres_init(
    dbconfig: dict, min_conn: int = 1, max_conn: int = 2
) -> psycopg2.pool.SimpleConnectionPool:
    dsn = f"dbname={dbconfig['dbname']} user={dbconfig['user']} password={dbconfig['pw']} host={dbconfig['host']}"
    pool = psycopg2.pool.SimpleConnectionPool(min_conn, max_conn, dsn)
    return pool
