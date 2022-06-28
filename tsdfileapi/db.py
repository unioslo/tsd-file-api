
import datetime
import logging
import re
import json
import sqlite3

from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import Union, ContextManager, Iterable, Optional

import psycopg2
import psycopg2.extensions
import psycopg2.pool
import sqlalchemy

from pysquril.backends import postgres_session
from sqlalchemy.pool import QueuePool
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError, IntegrityError, StatementError


def pg_listen_channel(
    pool: psycopg2.pool.SimpleConnectionPool,
    channel_name: str,
) -> psycopg2.extensions.connection:
    conn = pool.getconn()
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    curs = conn.cursor()
    curs.execute(f"listen {channel_name};")
    logging.info(f'listening on postgres channel: {channel_name}')
    return conn


def get_projects_migration_status(conn: psycopg2.extensions.connection,) -> dict:
    if not conn:
        return {}
    out = {}
    with postgres_session(conn) as session:
        session.execute(
            """select
                    project_number,
                    case when project_metadata->>'storage_backend' is null then 'hnas'
                    else project_metadata->>'storage_backend' end
                from projects
            """
        )
        data = session.fetchall()
    for row in data:
        out[row[0]] = row[1]
    return out


def sqlite_init(
    path: str,
    name: str = 'api-data.db',
    builtin: bool = False,
) -> Union[sqlalchemy.engine.Engine, sqlite3.Connection]:
    dbname = name
    if not builtin:
        dburl = 'sqlite:///' + path + '/' + dbname
        engine = create_engine(dburl, poolclass=QueuePool)
    else:
        engine = sqlite3.connect(path + '/' + dbname)
    return engine


def postgres_init(dbconfig: dict) -> psycopg2.pool.SimpleConnectionPool:
    min_conn = 2
    max_conn = 4
    dsn = f"dbname={dbconfig['dbname']} user={dbconfig['user']} password={dbconfig['pw']} host={dbconfig['host']}"
    pool = psycopg2.pool.SimpleConnectionPool(
        min_conn, max_conn, dsn
    )
    return pool


@contextmanager
def session_scope(
    engine: sqlalchemy.engine.Engine,
) -> ContextManager[sqlalchemy.orm.session.Session]:
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
        session.commit()
    except (OperationalError, IntegrityError, StatementError) as e:
        session.rollback()
        raise e
    finally:
        session.close()
