
"""A _simple_ sqlite db backend designed for JSON data, primarily from nettskjema"""

import re
import os
import logging
import sqlalchemy
from utils import secure_filename
from sqlalchemy.pool import QueuePool
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from contextlib import contextmanager
from sqlalchemy.exc import OperationalError, IntegrityError, StatementError


_valid_id = re.compile(r'([0-9])')
_valid_pnum = re.compile(r'([0-9a-z])')


class TableNameException(Exception):
    message = 'Illegal character or encoding in table name'


class ColumnNameException(Exception):
    message = 'Column name contains illegal characters'


class MalformedCodebookException(Exception):
    message = 'codebook definition cannot be parsed'


class TableCreationException(Exception):
    message = 'table cannot be created'


class UnsupportedTypeException(Exception):
    message = 'Nettskjema codebook type not supported'


class DbCreationException(Exception):
    message = 'Cannot create sqlite db for project'


class InsertException(Exception):
    message = 'Data insert failed - check URL and JSON'


class DuplicateRowException(Exception):
    message = 'Duplicate row - submission already stored'


def sqlite_init(path, pnum):
    try:
        assert _valid_pnum.match(pnum)
    except AssertionError as e:
        logging.error(e)
        raise DbCreationException
    dbname = pnum + '-forms.db'
    dburl = 'sqlite:///' + path + '/' + dbname
    engine = create_engine(dburl, poolclass=QueuePool)
    return engine


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


def _table_name_from_form_id(form_id):
    """Return a secure and legal table name, given a nettskjema form id."""
    try:
        assert type(form_id) is int
    except AssertionError:
        logging.error('form id not int')
        raise TableNameException
    _id = str(form_id)
    if _valid_id.match(_id):
        return 'form_' + _id
    else:
        logging.error('problem with form id - unknown what the issue is')
        raise TableNameException


def _statement_from_data(table_name, data):
    """
    Construct a safe and correct SQL insert statement from data. Avoids parsing data.

    Security measures
    -----------------
    All user inputs are sanitised - illegal or dangerous charachers are removed,
    e.g. ';'. If any are fund execution is stopped and the request is rejected.
    The statement is constructed solely on the information contained in the data.
    The secure_filename function is very strict :)

    Potentially dangerous elements are: 1) table name, 2) column name, 3) values.
    1) Table names are constructed in code after sanitisation, not directly.
    2) Column names are sanitised individually too.
    3) Values might contain nonsense data and it is up to the DB to decide.

    Parameters
    ----------
    table_name: string
        This is not direct user input - it is constructed in code, after being sanitised
    data: dict
        This input comes from the HTTP client in the request body. JSON is deserialised
        into a dictionary.

    Returns
    -------
    string
    """
    cols = data.keys()
    cols.sort()
    sanitised_cols = []
    for col in cols:
        sanitised_cols.append(secure_filename(col))
    try:
        assert cols == sanitised_cols
    except AssertionError:
        raise ColumnNameException
    columns = ''
    values = ''
    for i in range(len(sanitised_cols)):
        if i < len(sanitised_cols) - 1:
            columns += '%s, '
        else:
            columns += '%s'
    for i in range(len(sanitised_cols)):
        if i < len(sanitised_cols) - 1:
            values += ':%s, '
        else:
            values += ':%s'
    _cols = tuple(sanitised_cols)
    stmt = 'insert into %s(' % table_name + columns % _cols + ') values (' + values % _cols + ')'
    return stmt


def insert_into(engine, table_name, data):
    """
    Inserts data into a table - either one row or in bulk.

    Parameters
    ----------
    engine: sqlalchemy engine for sqlite
    table_name: string
    data: dict

    Returns
    -------
    bool
    """
    dtype = type(data)
    try:
        with session_scope(engine) as session:
            if dtype is list:
                stmt = _statement_from_data(table_name, data[0])
                for row in data:
                    session.execute(stmt, row)
            elif dtype is dict:
                stmt = _statement_from_data(table_name, data)
                session.execute(stmt, data)
        return True
    except (OperationalError, StatementError) as e:
        logging.error(e.message)
        raise InsertException
    except IntegrityError as e:
        logging.error(e.message)
        raise DuplicateRowException


def _sqltype_from_nstype(t):
    type_map = {
        'QUESTION': 'text',
        'QUESTION_MULTILINE': 'text',
        'RADIO': 'text',
        'CHECKBOX': 'text',
        'MATRIX_RADIO': 'text',
        'MATRIX_CHECKBOX': 'text',
        'NATIONAL_ID_NUMBER': 'text',
        'ATTACHMENT': 'text',
        'NUMBER': 'real',
        'DATE': 'text',
        'EMAIL': 'text',
        'SELECT': 'text'
    }
    try:
        return type_map[t]
    except KeyError:
        raise UnsupportedTypeException


def create_table_from_codebook(definition, form_id, engine):
    """
    Create a new table in SQLite based on a codebook definition.
    Is idempotent, so sending a definition with new columns will
    add them to the table. Columns cannot be removed.

    Parameters
    ----------
    definition: dict
    form_id: int

    Returns
    -------
    bool
    """
    try:
        table_name = _table_name_from_form_id(form_id)
    except TableNameException as e:
        logging.error(e.message)
        raise e
    with session_scope(engine) as session:
        try:
            session.execute('create table if not exists %s(submission_id int primary key)' % table_name)
        except Exception as e:
            logging.error(e.message)
            raise TableCreationException
        try:
            elements = definition['pages'][0]['elements']
        except KeyError as e:
            logging.error(e.message)
            raise MalformedCodebookException
        for el in elements:
            try:
                dtype = _sqltype_from_nstype(el['elementType'])
                questions = el['questions']
            except (UnsupportedTypeException, KeyError) as e:
                logging.error(e.message)
                raise e
            for q in questions:
                colname = q['externalQuestionId']
                sanitised_colname = secure_filename(colname)
                try:
                    assert colname == sanitised_colname
                except ColumnNameException as e:
                    logging.error(e.message)
                    raise e
                try:
                    session.execute('alter table %s add column %s %s' % (table_name, sanitised_colname, dtype))
                except OperationalError as e:
                    logging.info('duplicate column - skipping creation')
    return True
