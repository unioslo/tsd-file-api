
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
        if '?' not in uri:
            return None
        table_name = os.path.basename(uri.split('?')[0])
        stmt_delete = "delete from %(table_name)s " % {'table_name': table_name}
        stmt_where = "where %(conditions)s " % {'conditions': self.query_conditions} if self.query_conditions else ''
        query = stmt_delete + stmt_where
        return query


    def parse_columns(self, uri):
        if '?' not in uri:
            return '*'
        uri_query = uri.split('?')[-1]
        columns = '*'
        parts = uri_query.split('&')
        for part in parts:
            if part.startswith('select'):
                columns = part.split('=')[-1]
        fmt_str = "json_object(\"%s\", json_extract(data, '$.\"%s\"')) as \"%s\""
        if ',' in columns:
            names = columns.split(',')
            for name in names:
                quoted_column = fmt_str % (name, name, name)
                columns = columns.replace(name, quoted_column)
        else:
            if columns != '*':
                name = columns
                columns = fmt_str % (name, name, name)
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
    uris = ['/mytable?select=x,y&z=eq.5&y=gt.4&order=x.desc',
            '/mytable?x=not.like.*zap&y=not.is.null',
            '/mytable?set=x.5,y.6&z=eq.5',
            '/mytable?set=x.5&z=eq.5',
            '/mytable?z=not.is.null']
    for uri in uris:
        sql = SqlStatement(uri)
        print sql.select_query
        print sql.update_query
        print sql.delete_query
