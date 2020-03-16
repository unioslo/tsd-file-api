
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
        # base regexes to identify data selections
        self.idx_present = re.compile(r'(.+)\[[0-9#:]+\](.*)')
        self.idx_single = re.compile(r'(.+)\[[0-9]+\](.*)')
        self.idx_all = re.compile(r'(.+)\[[#]\](.*)')
        self.subselect_present = re.compile(r'(.+)\[[0-9#:]+\].(.+)$')
        self.subselect_single = re.compile(r'(.+)\[[0-9#:]+\].([^,])$')
        self.subselect_multiple = re.compile(r'(.+)\[[0-9#:]+\].\((.+),(.+)\)$')
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


    def quote_column(self, name):
        out = ''
        quote = '"'
        key_in = '.'
        slice_open = '['
        slice_close = ']'
        grouped_keys_start = '('
        grouped_keys_end = ')'
        grouped_keys_sep = ','
        tokens = [key_in, slice_open, slice_close,
                  grouped_keys_start, grouped_keys_end, grouped_keys_sep]
        # in general a selection has...
        for idx, char_curr in enumerate(name):
            char_prev = name[idx - 1] if idx > 0 else None
            char_next = name[idx + 1] if idx < (len(name) - 1) else None
            # pad start
            if idx == 0:
                if char_curr in tokens:
                    err = f'format error - cannot start selection with: "{char_curr}"'
                    raise Exception(err)
                if char_curr == quote:
                    out += char_curr
                    continue
                else:
                    out += quote
                    out += char_curr
                    if not char_next: # then len == 1
                        out += quote
                    continue
            # pad end
            if idx == len(name) - 1:
                if char_curr == grouped_keys_end:
                    if char_prev != quote:
                        out += quote
                    out += char_curr
                    continue
                elif char_curr == slice_close:
                    out += char_curr
                    continue
                else:
                    if char_curr == quote:
                        out += char_curr
                        continue
                    else:
                        out += char_curr
                        out += quote
                        continue
            # handle rest
            # chars
            if char_curr not in tokens:
                out += char_curr
                continue
            # then one or more .
            if char_curr == key_in:
                if char_prev == slice_close:
                    out += char_curr # then do not quote before .
                    if char_next == grouped_keys_start:
                        continue
                    if char_next != quote:
                        out += quote
                    continue
                if char_prev and char_prev != quote:
                    out += quote
                    out += char_curr
                elif char_prev and char_prev == quote:
                    out += char_curr
                if char_next != quote:
                    out += quote
                    continue
            # followed by more chars
            # until maybe [
            if char_curr == slice_open:
                if char_prev != quote:
                    out += quote
                    out += char_curr
                    continue
                else:
                    out += char_curr
                    continue
            # until ]
            if char_curr == slice_close:
                out += char_curr
            # optionally followed by . handed above
            # then either chars or (
            if char_curr == grouped_keys_start:
                out += char_curr
                if char_next != quote:
                    out += quote
                continue
            # after which chars handled above or ,
            if char_curr == grouped_keys_sep:
                if char_prev != quote:
                    out += quote
                    out += char_curr
                else:
                    out += char_curr
                if char_next != quote:
                    out += quote
                continue
            # and eventually ) - last char, handled above
        return out


    def quote_column_selection(self, name):
        quoted_name = self.quote_column(name)
        quoted_name_list = quoted_name.split('.')
        return quoted_name, quoted_name_list, name


    def construct_data_selection_str(self, inner_col, quoted_name, unquoted_name, table_name):
        """
        Regexes to determine data selection type for a specific nested column,
        which is a combination of two things:

        1) slicing
        2) column sub-selection

        example         slice   sub-selection
        -------         -----   -------------
        x               NA      NA
        x[1]            single  none
        x[1].k          single  single
        x[1].(k,d)      single  multiple
        x[#].y          all     single
        x[#].(y,z)      all     multiple

        """
        def destructure_grouped_selection(selection):
            """
            E.g. x[1].(k,d) -> [x[1].k, x[1].d]
            """
            out = []
            res = selection.split('(')
            base = res[0].replace(')', '')
            group = res[1].replace(')', '')
            elements = group.split(',')
            for element in elements:
                out.append(f'{base}{element}')
            return out
        def gen_sliced_key_selection_sql(unquoted_name, table_name, idx):
            sliced_select_str_mult = """
                "%(col)s",
                (case when json_extract(data, '$.%(data_selection)s') is not null then (
                    select json_group_array(vals) from (
                        select json_object(
                            %(sub_selections)s) as vals
                        from (
                            select key, value, fullkey, path
                            from %(table_name)s, json_tree(%(table_name)s.data)
                            where path = '$.%(path)s'
                            %(idx)s
                            )
                        )
                    )
                else null end)
            """
            if '(' not in unquoted_name and ')' not in unquoted_name:
                multiples = [unquoted_name]
            else:
                multiples = destructure_grouped_selection(unquoted_name)
            selection_on = unquoted_name.split('[')[0]
            keys = []
            for multiple in multiples:
                key = multiple.split('.')[-1]
                subkey = re.sub(r'(.+)\[.+\].(.+)', r'\2', multiple)
                keys.append("\"%s\", json_extract(value, '$.%s')" % (key, subkey))
            sub_selections = ','.join(keys)
            params = {
                'col': selection_on,
                'data_selection': selection_on,
                'table_name': table_name,
                'sub_selections': sub_selections,
                'path': selection_on,
                'idx': idx
            }
            return sliced_select_str_mult % params, True
        na_na = (
            '[' not in unquoted_name and ']' not in unquoted_name
        )
        single_none = (
            self.idx_single.match(unquoted_name) and
            not self.subselect_present.match(unquoted_name)
        )
        single_single = (
            self.idx_single.match(unquoted_name) and
            self.subselect_single.match(unquoted_name)
        )
        single_multiple = (
            self.idx_single.match(unquoted_name) and
            self.subselect_multiple.match(unquoted_name)
        )
        all_single = (
            self.idx_all.match(unquoted_name) and
            self.subselect_single.match(unquoted_name)
        )
        all_multiple = (
            self.idx_all.match(unquoted_name) and
            self.subselect_multiple.match(unquoted_name)
        )
        # three different SQL generation strategies
        if na_na:
            data_select_str = "%s, json_extract(data, '$.%s')"
            return data_select_str % (inner_col, quoted_name), False
        if single_none:
            data_select_str = """
                %s,
                case when json_extract(data, '$.%s') is not null then
                    json_array(json_extract(data, '$.%s'))
                else null end
                """
            return data_select_str % (inner_col.split('[')[0], quoted_name, quoted_name), False
        if single_single or single_multiple:
            slice_on = re.sub(r'(.+\[.+\]).(.+)', r'\1', unquoted_name)
            idx = "and fullkey = '$.%s'" % slice_on
        if all_single or all_multiple:
            idx = ''
            unquoted_name = unquoted_name.replace('#', '%')
        return gen_sliced_key_selection_sql(unquoted_name, table_name, idx)


    def parse_column_selection(self, name, table_name):
        quoted_name, quoted_nested_cols, unquoted_name = self.quote_column_selection(name)
        inner_col = quoted_nested_cols[-1]
        selection_extract, tree_builder = self.construct_data_selection_str(inner_col, quoted_name, unquoted_name, table_name)
        quoted_nested_cols.reverse()
        current_inner = selection_extract
        remaining_cols = quoted_nested_cols[1:]
        for idx, col in enumerate(remaining_cols): # already have the last one
            if re.match(r'.+\[.+\]', col):
                if idx == 0:
                    continue # this is part of the data selection
                else:
                    current_inner = "json_object(%s, %s)" % (col, current_inner)
            else:
                current_inner = "%s, json_object(%s)" % (col, current_inner)
        extract = current_inner
        return extract


    def smart_split(self, columns):
        has_group = r'(.+)\[(.+)\].(.+,).*'
        if re.match(has_group, columns):
            out = []
            acc = ''
            inside_group = False
            for char in columns:
                if char == '(':
                    inside_group = True
                if char == ')':
                    inside_group = False
                if not inside_group and char == ',':
                    acc += '|'
                    continue
                acc += char
            return acc.split('|')
        else:
            return columns.split(',')


    def parse_columns(self, uri):
        if '?' not in uri:
            return '*'
        uri_parts = uri.split('?')
        uri_query = uri_parts[-1]
        table_name = os.path.basename(uri_parts[0].split('/')[-1])
        columns = '*'
        parts = uri_query.split('&')
        for part in parts:
            if part.startswith('select'):
                columns = part.split('=')[-1]
        fmt_str = "json_object(%s)"
        if ',' in columns:
            # need to ensure we do not split on the comma between ()
            # if there is a sub-select inside an array
            names = self.smart_split(columns)
            inner_cols = ''
            first = True
            for name in names:
                extract = self.parse_column_selection(name, table_name)
                if first:
                    inner_cols += extract
                else:
                    inner_cols += ', %s' % extract
                first = False
            columns = fmt_str % (inner_cols)
        else:
            if columns != '*':
                name = columns
                extract = self.parse_column_selection(name, table_name)
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
        quoted_col, _, _ = self.quote_column_selection(col)
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
        col = '.'.join(tokens[:-1])
        direction = tokens[-1]
        ordering = "json_extract(data, '$.%s') %s" % (self.quote_column(col), direction)
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
