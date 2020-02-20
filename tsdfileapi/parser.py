
"""Parse URIs and translate them into SQL."""

import os
import logging
import json


class SqlStatement(object):

    """
    SqlStatement constructs a safe SQL query from a URI query,
    using the https://www.sqlite.org/json1.html extension.

    URI queries have the following generic structures, e.g.:

        GET /table_name?select=col1,col2&col3=eq.5&col2=not.is.null&order=col1.desc
        PATCH /table_name?set=col1.5&col3=eq.5
        DELETE /table_name?col3=eq.5

    Limitation: currently, reserved tokens are: ',.&' and all URI query terms are
    reserved words. To allow these to be used in query values, the parser will
    have to be reimplemented to support quoting values in the URI. The current
    implementation without such support will, however, satisfy enough queries.

    The constructor takes the URI, and generates three SQL query parts:

    1) columns, if specified
    2) the elements of the where clause, if present
    3) ordering of the resultset, if specified

    Finally, it combines these three parts into a safe query which
    can be executed.

    """

    def __init__(self, uri):
        self.operators = {
            'eq': '=',
            'gt': '>',
            'gte': '>=',
            'lt': '<',
            'lte': '<=',
            'neq': '!=',
            'like': 'like', # * replaces % in the URI
            'ilike': 'ilike', # * replaces % in the URI
            'not': 'not',
            'is': 'is'
        }
        self.query_columns = self.parse_columns(uri)
        self.query_conditions = self.parse_row_clauses(uri)
        self.query_ordering = self.parse_ordering_clause(uri)
        self.update_details = self.parse_update_clause(uri)
        self.select_query = self.build_select_query(uri)
        self.update_query = self.build_update_query(uri)
        self.delete_query = self.build_delete_query(uri)


    def build_select_query(self, uri):
        if '?' not in uri:
            table_name = os.path.basename(uri)
            return 'select * from %s' % table_name
        table_name = os.path.basename(uri.split('?')[0])
        stmt_select ="select %(columns)s " % {'columns': self.query_columns}
        stmt_from = "from %(table_name)s " % {'table_name': table_name}
        stmt_where = "where %(conditions)s " % {'conditions': self.query_conditions} if self.query_conditions else ''
        stmt_order = "order by %(ordering)s " % {'ordering': self.query_ordering} if self.query_ordering else None
        query = stmt_select + stmt_from + stmt_where
        if stmt_order:
            # given the correct usage of json_object for selection
            # and the necessary use of json_extract in order clauses
            # this is not longer necessary
            query = "select * from (%s)a " % query + stmt_order
        return query


    def build_update_query(self, uri):
        if '?' not in uri:
            return None
        table_name = os.path.basename(uri.split('?')[0])
        stmt_update = "update %(table_name)s " % {'table_name': table_name}
        stmt_set = "set %(update_details)s " % {'update_details': self.update_details} if self.update_details else ''
        stmt_where = "where %(conditions)s " % {'conditions': self.query_conditions} if self.query_conditions else ''
        query = stmt_update + stmt_set + stmt_where
        return query if self.update_details else None


    def parse_update_clause(self, uri):
        update_clause = None
        if '?' not in uri:
            return None
        uri_query = uri.split('?')[-1]
        parts = uri_query.split('&')
        set_count = 0
        for part in parts:
            if part.startswith('set'):
                part = part.replace('set=', '')
                settings = part.split(',')
                new_values = {}
                for setting in settings:
                    col, val = setting.split('.')
                    try:
                        new_values[col] = int(val)
                    except ValueError:
                        new_values[col] = val
                update_clause = "data = json_patch(data, '%s')" % json.dumps(new_values)
        return update_clause


    def build_delete_query(self, uri):
        # seems broken too
        if '?' not in uri:
            table_name =  uri.split('/')[-1]
            return "delete from %(table_name)s" % {'table_name': table_name}
        uri_path = uri.split('?')[0]
        table_name = os.path.basename(uri_path.split('/')[-1])
        stmt_delete = "delete from %(table_name)s " % {'table_name': table_name}
        stmt_where = "where %(conditions)s " % {'conditions': self.query_conditions} if self.query_conditions else ''
        query = stmt_delete + stmt_where
        return query


    def parse_nested_column_selection(self, name):
        nested_extract_col_str = "\"%s\", json_extract(data, '$.%s')"
        nested_cols = name.split('.')
        # quote cols for value extraction
        quoted_nested_cols = []
        for col in nested_cols:
            if col.startswith('"') and col.endswith('"'):
                quoted_nested_cols.append(col)
            else:
                col = '"%s"' % col
                quoted_nested_cols.append(col)
        quoted_name = '.'.join(quoted_nested_cols)
        # data selection piece
        inner_col = nested_cols[-1]
        selection_extract = nested_extract_col_str % (inner_col, quoted_name)
        # now reconstruct the origin shape
        quoted_nested_cols.reverse()
        current_inner = selection_extract
        for col in quoted_nested_cols[1:]: # already have the last one
            current_inner = "%s, json_object(%s)" % (col, current_inner)
        extract = current_inner
        return extract


    def parse_columns(self, uri):
        if '?' not in uri:
            return '*'
        uri_query = uri.split('?')[-1]
        columns = '*'
        parts = uri_query.split('&')
        for part in parts:
            if part.startswith('select'):
                columns = part.split('=')[-1]
        # TODO (question): support x.y[1] ?
        extract_col_str = "\"%s\", json_extract(data, '$.\"%s\"')"
        fmt_str = "json_object(%s)"
        if ',' in columns:
            names = columns.split(',')
            inner_cols = ''
            first = True
            for name in names:
                if '.' in name:
                    extract = self.parse_nested_column_selection(name)
                else:
                    extract = extract_col_str % (name, name)
                if first:
                    inner_cols += extract
                else:
                    inner_cols += ', %s' % extract
                first = False
            columns = fmt_str % (inner_cols)
        else:
            if columns != '*':
                name = columns
                if '.' in name:
                    extract = self.parse_nested_column_selection(name)
                else:
                    extract = extract_col_str % (name, name)
                columns = fmt_str % (extract)
        return columns


    def construct_safe_where_clause_part(self, part, num_part):
        op_and_val = part.split('=')[1]
        col = part.split('=')[0]
        if 'not' in op_and_val:
            op = op_and_val.split('.')[1]
            val = op_and_val.split('.')[2]
            if 'is' in op_and_val:
                col_and_opt_str = "json_extract(data, '$.\"%(col)s\"') %(op)s not"
            else:
                col_and_opt_str = "json_extract(data, '$.\"%(col)s\"') not %(op)s"
        else:
            op = op_and_val.split('.')[0]
            val = op_and_val.split('.')[1]
            col_and_opt_str = "json_extract(data, '$.\"%(col)s\"') %(op)s"
        assert op in self.operators.keys()
        try:
            int(val)
            val_str = ' %(val)s'
        except ValueError:
            val_str = ' "%(val)s"'
            if op == 'like' or op == 'ilike':
                val = val.replace('*', '%')
        final = col_and_opt_str + val_str
        safe_part = final % {'col': col, 'op': op, 'val': val}
        if num_part > 0:
            safe_part = ' and ' + safe_part
        return safe_part


    def parse_row_clauses(self, uri):
        if '?' not in uri:
            return None
        uri_query = uri.split('?')[-1]
        conditions = ''
        num_part = 0
        parts = uri_query.split('&')
        for part in parts:
            if (not part.startswith('select') and not part.startswith('order') and not part.startswith('set')):
                safe_part = self.construct_safe_where_clause_part(part, num_part)
                conditions += safe_part
                num_part += 1
        if len(conditions) > 0:
            for op in self.operators.keys():
                conditions = conditions.replace(op, self.operators[op])
        else:
            conditions = None
        return conditions


    # needs to be: order by json_extract(data, '$."x"') desc, e.g.
    #
    def construct_safe_order_clause(self, part):
        targets = part.replace('order=', '')
        tokens = targets.split('.')
        col = tokens[0]
        direction = tokens[1]
        ordering = '"%s" %s' % (col, direction)
        return ordering


    def parse_ordering_clause(self, uri):
        if '?' not in uri:
            return None
        uri_query = uri.split('?')[-1]
        ordering = ''
        parts = uri_query.split('&')
        for part in parts:
            if part.startswith('order'):
                safe_part = self.construct_safe_order_clause(part)
                ordering += safe_part
        return ordering if len(ordering) > 0 else None


if __name__ == '__main__':
    test_data = [
        {'x': 0, 'y': 1, 'z': 5},
        {'y': 11, 'z': 1},
        {'a': {'k1': {'r1': [1, 2], 'r2': 2}, 'k2': ['val', 9]}},
    ]
    from db import sqlite_init, sqlite_insert, sqlite_get_data, sqlite_delete_data
    create_engine = sqlite_init('/tmp', name='file-api-test.db')
    query_engine = sqlite_init('/tmp', name= 'file-api-test.db', builtin=True)
    sqlite_delete_data(query_engine, 'mytable', '/mytable')
    sqlite_insert(create_engine, 'mytable', test_data)
    uris = [
        '/mytable', # simple select *
        '/mytable?select=x', # simple select col
        '/mytable?select=x&z=eq.5&y=gt.0', # select col with conditions
        '/mytable?select=x,y', # select two cols
        '/mytable?select=x,a.k1', # nested json key selection (1-level), all with shape preservation
        '/mytable?select=x,a.k1.r1', # nested json key selection (n-level)
        '/mytable?select=a.k1.r1', # nested selection, on one column
        # TODO
        #'/mytable?x=not.like.*zap&y=not.is.null',
        #'/mytable?set=x.5,y.6&z=eq.5',
        #'/mytable?set=x.5&z=eq.5',
        #'/mytable?z=not.is.null'
    ]
    for uri in uris:
        try:
            print(uri)
            query_engine = sqlite_init('/tmp', name= 'file-api-test.db', builtin=True)
            print(sqlite_get_data(query_engine, 'mytable', uri, verbose=True))
            print()
        except Exception:
            pass
        # TODO
        #print(sql.update_query)
        #print(sql.delete_query)
