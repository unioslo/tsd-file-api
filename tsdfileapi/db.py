
"""sqlite db backend designed for JSON data."""

# pylint: disable=missing-docstring

import logging
import re
import json
import sqlite3
from contextlib import contextmanager

from sqlalchemy.pool import QueuePool
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError, IntegrityError, StatementError

# pylint: disable=relative-import
from utils import check_filename, IllegalFilenameException
from parser import SqlStatement


def sqlite_init(path, name='api-data.db', builtin=False):
    dbname = name
    if not builtin:
        dburl = 'sqlite:///' + path + '/' + dbname
        engine = create_engine(dburl, poolclass=QueuePool)
    else:
        engine = sqlite3.connect(path + '/' + dbname)
    return engine


@contextmanager
def session_scope(engine):
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


@contextmanager
def sqlite_session(engine):
    session = engine.cursor()
    try:
        yield session
        session.close()
    except Exception as e:
        session.close()
        engine.rollback()
        raise e
    finally:
        session.close()
        engine.commit()

# TODO: add a Backend ABC

class SqliteBackend(object):

    def __init__(self, engine, verbose=False):
        self.engine = engine
        self.verbose = verbose
        self.table_definition = '(data json unique not null)'

    def tables_list(self):
        query = "select name FROM sqlite_master where type = 'table'"
        with sqlite_session(self.engine) as session:
            res = session.execute(query).fetchall()
        if not res:
            return []
        else:
            out = []
            for row in res:
                name = row[0]
                if not name.endswith('_metadata'):
                    out.append(row[0])
            return out

    def table_insert(self, table_name, data):
        try:
            dtype = type(data)
            insert_stmt = f'insert into "{table_name}" (data) values (?)'
            target = []
            if dtype is list:
                for element in data:
                    target.append((json.dumps(element),))
            elif dtype is dict:
                target.append((json.dumps(data),))
            try:
                with sqlite_session(self.engine) as session:
                    session.executemany(insert_stmt, target)
                return True
                pass
            except (sqlite3.ProgrammingError, sqlite3.OperationalError) as e:
                with sqlite_session(self.engine) as session:
                    session.execute(f'create table if not exists "{table_name}" {self.table_definition}')
                    session.executemany(insert_stmt, target)
                return True
        except sqlite3.ProgrammingError as e:
            logging.error('Syntax error?')
            raise e
        except sqlite3.IntegrityError as e:
            logging.error('Duplicate row')
            raise e
        except sqlite3.OperationalError as e:
            logging.error('Database issue')
            raise e
        except Exception as e:
            logging.error('Not sure what went wrong')
            raise e

    def table_update(self, table_name, uri, data):
        sql = SqlStatement(table_name, uri, data=data)
        if self.verbose:
            print(sql.update_query)
        with sqlite_session(self.engine) as session:
            session.execute(sql.update_query)
        return True

    def table_delete(self, table_name, uri):
        sql = SqlStatement(table_name, uri)
        if self.verbose:
            print(sql.delete_query)
        with sqlite_session(self.engine) as session:
            session.execute(sql.delete_query)
        return True

    def table_select(self, table_name, uri):
        sql = SqlStatement(table_name, uri)
        if self.verbose:
            print(sql.select_query)
        with sqlite_session(self.engine) as session:
            for row in session.execute(sql.select_query):
                yield row[0]


class PostgresBackend(object):

    def __init__(self, engine, verbose=False):
        self.engine = engine
        self.verbose = verbose
        self.table_definition = '(data jsonb unique not null)'

    def tables_list(self):
        pass

    def table_insert(self, table_name, data):
        # try insert
        # if fail, create schema, create table (if not exists)
        # try again
        # caller needs to pass in the schema as part of the table name
        pass
