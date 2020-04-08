
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


_VALID_COLNAME = re.compile(r'([0-9a-z])')
_VALID_TABLE_NAME = re.compile(r'([0-9a-z_])')


class ColumnNameException(Exception):
    message = 'Column name contains illegal characters'


class TableCreationException(Exception):
    message = 'table cannot be created'


class InsertException(Exception):
    message = 'Data insert failed - check URL and JSON'


class DuplicateRowException(Exception):
    message = 'Duplicate row - submission already stored'


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
        logging.error(e)
        logging.error("Could not commit data")
        logging.error("Rolling back transaction")
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


def sqlite_insert(engine, table_name, data):
    """
    Inserts data into a table - either one row or in bulk.
    Create the table if not exists.

    Parameters
    ----------
    engine: sqlalchemy engine for sqlite
    uri: string
    data: dict

    Returns
    -------
    bool

    """
    dtype = type(data)
    try:
        with session_scope(engine) as session:
            try:
                conditionally_create_generic_table(engine, table_name)
            except TableCreationException:
                pass # most likely because it already exists, ignore
            if dtype is list:
                for row in data:
                    session.execute('insert into "' + table_name + '" (data) values (:values)',
                        {'values': json.dumps(row)})
            elif dtype is dict:
                # investigate: http://docs.sqlalchemy.org/en/latest/faq/performance.html
                # Bulk_insert_mappings or use raw sqlite3
                row = data
                session.execute('insert into "' + table_name + '" (data) values (:values)',
                        {'values': json.dumps(row)})
        return True
    except IntegrityError as e:
        logging.error(e)
        raise DuplicateRowException
    except (OperationalError, StatementError) as e:
        logging.error(e)
        raise InsertException
    except Exception as e:
        logging.error(e)
        raise Exception('not sure what went wrong - could not insert data')


def conditionally_create_generic_table(engine, table_name):
    """
    A generic table has one column named data, with a json type.

    Parameters
    ----------
    engine: sqlite engine
    table_name: str, name

    Returns
    -------
    bool

    """
    try:
        table_name = check_filename(table_name)
    except (KeyError, IllegalFilenameException) as e:
        logging.error(e)
        raise TableCreationException
    try:
        with session_scope(engine) as session:
            session.execute('create table if not exists "%s" (data json unique not null)' % table_name)
    except Exception as e:
        logging.error(e)
        raise TableCreationException
    return True


def sqlite_list_tables(engine):
    query = "select name FROM sqlite_master where type = 'table'"
    with sqlite_session(engine) as session:
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


def sqlite_get_data(engine, table_name, uri, verbose=False):
    sql = SqlStatement(table_name, uri)
    if verbose:
        print(sql.select_query)
    with sqlite_session(engine) as session:
        res = session.execute(sql.select_query).fetchall()
    data = []
    for row in res:
        data.append(json.loads(row[0]))
    return data


def sqlite_update_data(engine, table_name, uri, data, verbose=False):
    sql = SqlStatement(table_name, uri, data)
    if verbose:
        print(sql.update_query)
    try:
        session = engine.cursor()
        session.execute(sql.update_query)
        engine.commit()
    except Exception as e:
        logging.error(sql.update_query)
        logging.error(e)
        return False
    finally:
        session.close()
        engine.rollback()
        engine.close()
    return True


def sqlite_delete_data(engine, table_name, uri, verbose=False):
    sql = SqlStatement(table_name, uri)
    if verbose:
        print(sql.delete_query)
    try:
        session = engine.cursor()
        session.execute(sql.delete_query)
        engine.commit()
    except Exception as e:
        logging.error(sql.delete_query)
        logging.error(e)
        return False
    finally:
        session.close()
        engine.rollback()
        engine.close()
    return True
