
"""Parse URIs and translate them into SQL."""

import os
import logging
import json
import re


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
        """
        Regexes to determine data selection type for a specific nested column,
        which is a combination of two things:

        1) slicing
        2) column sub-selection

        example         slice   sub-selection
        -------         -----   -------------
        x[1]            single  none
        x[1:3]          range   none
        x[1].k          single  single
        x[1:3].k        range   single
        x[1].(k,d)      single  multiple
        x[1:3].(k,d)    range   multiple
        x               all     none
        x[#].y          all     single
        x[#].(y,z)      all     multiple

        """
        self.idx_present = re.compile(r'(.+)\[[0-9#:]+\](.*)')
        self.idx_single = re.compile(r'(.+)\[[0-9]+\](.*)')
        self.idx_range = re.compile(r'(.+)\[[0-9]+:[0-9]+\](.*)')
        self.idx_all = re.compile(r'(.+)\[[#]\](.*)')
        self.subselect_present = re.compile(r'(.+)\[[0-9#:]+\].(.+)$')
        self.subselect_single = re.compile(r'(.+)\[[0-9#:]+\].([^,])$')
        self.subselect_multiple = re.compile(r'(.+)\[[0-9#:]+\].\((.+),(.+)\)$')

        self.specific_idx_selection = re.compile(r'(.+)\[[0-9]\]')
        self.all_idxs_selection = re.compile(r'(.+)\[[#]\]')
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


    # TODO: support nesting, and slicing
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


    def quote_column_selection(self, name):
        nested_cols = name.split('.')
        # quote cols for value extraction
        quoted_nested_cols = []
        for col in nested_cols:
            parts = None
            if self.specific_idx_selection.match(col):
                parts = col.split('[')
                col = parts[0]
            if not (col.startswith('"') and col.endswith('"')):
                col = '"%s"' % col
            if parts:
                col = '%s[%s' % (col, parts[1])
            quoted_nested_cols.append(col)
        quoted_name = '.'.join(quoted_nested_cols)
        return quoted_name, quoted_nested_cols


    def construct_data_selection_str(self, inner_col, table_name):
        pass

    def parse_column_selection(self, name):
        # all_idxs_selection = re.match(r'(.+)\[[#]\]', col)
        # if ^ replace # with %
        # construct tree query
        # try to make this dryer
        data_select_str = "%s, json_extract(data, '$.%s')"
        data_select_str_with_slice = "%s, json_array(json_extract(data, '$.%s'))"
        data_select_str_with_slice_and_select = """
            select json_group_array(target) from
                (select path, json_group_object(key, value) as target from
                    (select key, value, fullkey, path from
                     %(table_name)s, json_tree(%(table_name)s.data)
                     where %(where_clause)s))
                 group by path)""" # table
        slide_and_select_where_clause = "fullkey like '$.%(slice_and_select)s'" # '$.c[idx].h' where idx == % forall
        # need to support having one or more where conditions
        # and need to use unquoted selections
        # and need support for selecting more than one column
        # and for either a specific index, or all
        quoted_name, quoted_nested_cols = self.quote_column_selection(name)
        print(quoted_name, quoted_nested_cols)
        # data selection piece - could be a slice...
        inner_col = quoted_nested_cols[-1]
        if self.specific_idx_selection.match(inner_col):
            selection_extract = data_select_str_with_slice % (inner_col.split('[')[0], quoted_name)
        # if the parent selection is a slice...
        elif self.specific_idx_selection.match(inner_col):
            print('!!!!!! detected selection on a slice')
            # will need to decide if this is done recursively
            # will have to in order to support [0].k.r[0] etc
        else:
            selection_extract = data_select_str % (inner_col, quoted_name)
        # now reconstruct the original shape
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
        fmt_str = "json_object(%s)"
        if ',' in columns:
            names = columns.split(',')
            inner_cols = ''
            first = True
            for name in names:
                extract = self.parse_column_selection(name)
                if first:
                    inner_cols += extract
                else:
                    inner_cols += ', %s' % extract
                first = False
            columns = fmt_str % (inner_cols)
        else:
            if columns != '*':
                name = columns
                extract = self.parse_column_selection(name)
                columns = fmt_str % (extract)
        return columns


    def construct_safe_where_clause_part(self, part, num_part):
        op_and_val = part.split('=')[1]
        col = part.split('=')[0]
        if 'not' in op_and_val:
            op = op_and_val.split('.')[1]
            val = op_and_val.split('.')[2]
            if 'is' in op_and_val:
                col_and_opt_str = "json_extract(data, '$.%(col)s') %(op)s not"
            else:
                col_and_opt_str = "json_extract(data, '$.%(col)s') not %(op)s"
        else:
            op = op_and_val.split('.')[0]
            val = op_and_val.split('.')[1]
            col_and_opt_str = "json_extract(data, '$.%(col)s') %(op)s"
        try:
            assert op in self.operators.keys()
        except AssertionError:
            raise Exception('operator not found/supported')
        try:
            int(val)
            val_str = ' %(val)s'
        except ValueError:
            val_str = ' "%(val)s"'
            if op == 'like' or op == 'ilike':
                val = val.replace('*', '%')
        final = col_and_opt_str + val_str
        quoted_col, _ = self.quote_column_selection(col)
        safe_part = final % {'col': quoted_col, 'op': op, 'val': val}
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
        direction = tokens[-1]
        ordering = "json_extract(data, '$.\"%s\"') %s" % (col, direction)
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
