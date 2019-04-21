
"""Parse URIs and translate them into SQL."""

import os
import logging


class SqlStatement(object):

    """
    SqlStatement constructs a safe SQL query from a URI query.
    URI queries have the following generic structure:

    /table_name?select=col1,col2&col3=eq.5&col2=not.is.null&order=col1.desc

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
        self.query = self.build_sql(uri)


    def build_sql(self, uri):
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


    def parse_columns(self, uri):
        if '?' not in uri:
            return '*'
        uri_query = uri.split('?')[-1]
        columns = '*'
        parts = uri_query.split('&')
        for part in parts:
            if 'select' in part:
                columns = part.split('=')[-1]
        fmt_str = "json_object(\"%s\", json_extract(data, '$.\"%s\"')) as \"%s\""
        if ',' in columns:
            names = columns.split(',')
            for name in names:
                quoted_column = fmt_str % (name, name, name)
                columns = columns.replace(name, quoted_column)
        else:
            name = columns
            columns = fmt_str % (name, name, name)
        return columns


    def construct_safe_where_clause_part(self, part, num_part):
        op_and_val = part.split('=')[1]
        col = part.split('=')[0]
        # add support for not - two '.' in that case
        # if 'not in op_and_val...'
        op = op_and_val.split('.')[0]
        assert op in self.operators.keys()
        val = op_and_val.split('.')[1]
        col_and_opt_str = "json_extract(data, '$.\"%(col)s\"') %(op)s"
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
            if ('select' not in part and 'order' not in part):
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
            if 'order' in part:
                safe_part = self.construct_safe_order_clause(part)
                ordering += safe_part
        return ordering if len(ordering) > 0 else None


if __name__ == '__main__':
    uri = '/mytable?select=x,y&z=eq.5&y=gt.4&x=like.*5&order=x.desc'
    sql = SqlStatement(uri)
    print sql.query
