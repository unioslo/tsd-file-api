
"""
Parse URIs and translate them into SQL.

target:
select * from (
    select json_extract(data, '$.key2') from mytest1
    where json_extract(data, '$.key2') = 'bla')a
order by bla;
"""

import os
import logging

ROW_TOKENS = {
    'eq': '=',
    'gt': '>'
}

class SqlStatement(object):


    def __init__(self, uri):
        self.expression = self.build_sql(uri)


    def build_sql(self, uri):
        table_name = os.path.basename(uri.split('?')[0])
        uri_query = uri.split('?')[-1]
        # TODO: check for unsafe tokens here
        columns = self.parse_column_qualifiers(uri_query)
        conditions = self.parse_row_qualifiers(uri_query)
        ordering = self.parse_ordering_qualifiers(uri_query)
        stmt_select = 'select %(columns)s ' % {'columns': columns}
        stmt_from = 'from %(table_name)s ' % {'table_name': table_name}
        stmt_where = 'where %(conditions)s ' % {'conditions': conditions} if conditions else ''
        stmt_order =  'order by %(ordering)s ' % {'ordering': ordering} if ordering else ''
        expression = stmt_select + stmt_from + stmt_where + stmt_order
        return expression


    def parse_column_qualifiers(self, uri_query):
        # TODO: this has to be modified for json1 columns
        columns = '*'
        parts = uri_query.split('&')
        for part in parts:
            if 'select' in part:
                columns = part.split('=')[-1]
        if ',' in columns:
            names = columns.split(',')
            for name in names:
                quoted_column = '"%s"' % name
                columns = columns.replace(name, quoted_column)
        else:
            columns = '"%s"' % columns
        return columns


    def construct_safe_condition_part(self, part, num_part):
        """
        Condition parts have the following structure: col=op.val
        This method produces a safe SQL equivalent.

        """
        op_and_val = part.split('=')[1]
        col = part.split('=')[0]
        op = op_and_val.split('.')[0]
        assert op in ROW_TOKENS.keys()
        val = op_and_val.split('.')[1]
        if num_part > 0:
            safe_part = ' and "%(col)s" %(op)s "%(val)s"' % {'col': col, 'op': op, 'val': val}
        else:
            safe_part = ' "%(col)s" %(op)s "%(val)s"' % {'col': col, 'op': op, 'val': val}
        return safe_part


    def parse_row_qualifiers(self, uri_query):
        # TODO: this has to be modified for json1 columns
        conditions = ''
        num_part = 0
        parts = uri_query.split('&')
        for part in parts:
            if ('select' not in part and 'order' not in part):
                safe_part = self.construct_safe_condition_part(part, num_part)
                conditions += safe_part
                num_part += 1
        if len(conditions) > 0:
            for op in ROW_TOKENS.keys():
                conditions = conditions.replace(op, ROW_TOKENS[op])
        else:
            conditions = None
        return conditions


    def construct_safe_order_part(self, part):
        # structure order=age.desc - only support singular
        targets = part.replace('order=', '')
        tokens = targets.split('.')
        col = tokens[0]
        direction = tokens[1]
        ordering = '"%s" %s' % (col, direction)
        return ordering


    def parse_ordering_qualifiers(self, uri_query):
        # wrap the inner query in an outer one, so we can use column names without json manipulation
        # select * from (inner)a order by ...
        ordering = ''
        parts = uri_query.split('&')
        for part in parts:
            if 'order' in part:
                safe_part = self.construct_safe_order_part(part)
                ordering += safe_part
        return ordering if len(ordering) > 0 else None


if __name__ == '__main__':
    uri = '/mytable?select=x,y&z=eq.5&y=gt.4&order=x.desc'
    statement = SqlStatement(uri)
    print statement.expression
