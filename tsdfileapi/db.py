
"""A _simple_ sqlite db backend designed for JSON data, primarily from nettskjema"""

import re
import os
import logging
import sqlalchemy
from utils import secure_filename
from sqlalchemy import create_engine


class TableNameException(Exception):
    message = 'Illegal character or encoding in table name'


class ColumnNameException(Exception):
    message = 'Column name contains illegal characters'


def _table_name_from_form_id(form_id):
    """Return a secure and legal table name, given a nettskjema form id."""
    try:
        assert type(form_id) is int
    except AssertionError:
        logging.error('form id not int')
        raise TableNameException
    _id = str(form_id)
    _valid_id = re.compile(r'([0-9])')
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


def insert_into(table_name, data):
    stmt = _statement_from_data(table_name, data)
    print stmt
    return
    engine = create_engine('sqlite:///testdb1')
    conn = engine.connect()
    conn.execute('create table if not exists %s(x int, y int, z text)' % table)
    conn.execute(stmt, data)
    print conn.execute('select * from %s' % table_name).fetchall()
    conn.execute('delete from %s' % table_name)
    conn.close()


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
        return type_map(t)
    except KeyError:
        raise Exception('Nettskjema codebook type not supported')


def create_table_from_codebook(data):
    """
    data = { definition: json, type: text <codebook, generic>, form_id: int }

    Should be idempotent.
    """
    pass
    # get table name safely
    # 'create table if not exists %s()'
    # alter table %s add column submission_id int primary key (catch exception)
    # definition->pages->0->elements
    # for el in elements
        # type : el->elementType
        # el->questions
        # for q in el->questions
            # colname : q->externalQuestionId
            # alter table %(table)s add column %(colname)s type (catching exception)
    # set owner correctly if relevant
    # also leep track of definitions in a codebooks table? I think no

def main():
    data = {'x': 99, 'y': 10, 'z': 'afbhew'}
    table_name = _table_name_from_form_id(121298979)
    insert_into(table_name, data)


if __name__ == '__main__':
    main()
