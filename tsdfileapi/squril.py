
"""SQURIL - Structured Query URI Language."""

import re

from abc import ABC, abstractmethod


class SelectElement(ABC):
    @property
    @abstractmethod
    def name(self):
        pass
    @property
    @abstractmethod
    def regex(self):
        pass


class BaseSelectElement(SelectElement):
    name = None
    regex = None
    def __init__(self, element):
        self.element = element
    def create_bare_key(self, element):
        return element.split('[')[0] if '[' in element else None
    def create_sub_selections(self, element):
        return element.split('|')[1].replace(']', '').split(',') if '|' in element else []
    def create_idx(self, element):
        return re.sub(r'.+\[(.)\|(.*)\]', r'\1', element) if '[' in element else None


class Key(BaseSelectElement):
    name = 'key'
    regex = r'[^\[\]]+$'
    def __init__(self, element):
        self.element = element
        self.bare_key = self.create_bare_key(element)
        self.sub_selections = self.create_sub_selections(element)
        self.idx = self.create_idx(element)


class ArraySpecific(BaseSelectElement):
    name = 'array.specific'
    regex = r'.+\[[0-9]+\]$'
    def __init__(self, element):
        self.element = element
        self.bare_key = self.create_bare_key(element)
        self.sub_selections = self.create_sub_selections(element)
        self.idx = self.create_idx(element)


class ArraySpecificSingle(BaseSelectElement):
    name = 'array.specific.single'
    regex = r'.+\[[0-9]+\|[^,]+\]$'
    def __init__(self, element):
        self.element = element
        self.bare_key = self.create_bare_key(element)
        self.sub_selections = self.create_sub_selections(element)
        self.idx = self.create_idx(element)


class ArraySpecificMultiple(BaseSelectElement):
    name = 'array.specific.multiple'
    regex = r'.+\[[0-9]+\|.+,.+\]$'
    def __init__(self, element):
        self.element = element
        self.bare_key = self.create_bare_key(element)
        self.sub_selections = self.create_sub_selections(element)
        self.idx = self.create_idx(element)


class ArrayBroadcastSingle(BaseSelectElement):
    name = 'array.broadcast.single'
    regex = r'.+\[\*\|[^,]+\]$'
    def __init__(self, element):
        self.element = element
        self.bare_key = self.create_bare_key(element)
        self.sub_selections = self.create_sub_selections(element)
        self.idx = self.create_idx(element)


class ArrayBroadcastMultiple(BaseSelectElement):
    name = 'array.broadcast.multiple'
    regex = r'.+\[\*\|.+,.+\]$'
    def __init__(self, element):
        self.element = element
        self.bare_key = self.create_bare_key(element)
        self.sub_selections = self.create_sub_selections(element)
        self.idx = self.create_idx(element)


class SelectTerm(object):

    def __init__(self, original):
        self.original = original
        self.bare_term = original.split('[')[0]
        self.parsed = self.parse_elements()

    def parse_elements(self):
        out = []
        parts = self.original.split('.')
        for element in parts:
            element_instance = None
            found = False
            for ElementClass in [
                Key,
                ArraySpecific,
                ArraySpecificSingle,
                ArraySpecificMultiple,
                ArrayBroadcastSingle,
                ArrayBroadcastMultiple
            ]:
                if re.match(ElementClass.regex, element):
                    if found:
                        msg = f'Could not uniquely identify {element} - already matched with {found}'
                        raise Exception(msg)
                    element_instance = ElementClass(element)
                    found = ElementClass.name
            if not element_instance:
                raise Exception(f'Could not parse {element}')
            out.append(element_instance)
        return out


class WhereElement(object):

    def __init__(self, groups, combinator, term, op, val):
        self.groups_start, self.groups_end = self.categorise_groups(groups)
        self.combinator = combinator
        self.select_term = SelectTerm(term)
        self.op = op
        self.val = val

    def categorise_groups(self, groups):
        start, end = [], []
        for bracket in groups:
            if bracket == '(':
                start.append(bracket)
            elif bracket == ')':
                end.append(bracket)
        return start, end


class WhereTerm(object):

    def __init__(self, original):
        self.original = original
        self.parsed = self.parse_elements()

    def parse_elements(self):
        element = self.original
        groups = []
        for char in self.original:
            if char in ['(', ')']:
                groups.append(char)
        element = element.replace('(', '')
        element = element.replace(')', '')
        combinators = ['and:', 'or:']
        combinator = None
        for c in combinators:
            if element.startswith(c):
                combinator = c.replace(':', '')
                element = element.replace(c, '')
        term, op_and_val = element.split('=')
        if 'not' in op_and_val:
            _parts = op_and_val.split('.')
            if 'is' in _parts:
                op = '.'.join([_parts[1], _parts[0]])
            else:
                op = '.'.join([_parts[0], _parts[1]])
            val = op_and_val.split('.')[2]
        else:
            op, val = op_and_val.split('.')
        return [WhereElement(groups, combinator, term, op, val)]


class OrderElement(object):

    def __init__(self, term, direction):
        self.select_term = SelectTerm(term)
        self.direction = direction


class OrderTerm(object):

    def __init__(self, original):
        self.original = original
        self.parsed = self.parse_elements()

    def parse_elements(self):
        parts = self.original.split('.')
        term = '.'.join(parts[:-1])
        direction = parts[-1]
        return [OrderElement(term, direction)]


class RangeElement(object):

    def __init__(self, start, end):
        self.start = start
        self.end = end


class RangeTerm(object):

    def __init__(self, original):
        self.original = original
        self.parsed = self.parse_elements()

    def parse_elements(self):
        start, end = self.original.split('.')
        return [RangeElement(start, end)]


class SetElement(object):

    def __init__(self, term):
        self.select_term = SelectTerm(term)
        type_msg = f'{term} must be an instance of Key'
        assert isinstance(self.select_term.parsed[0], Key), type_msg
        len_msg = f'SetElements can only be top level keys - {term} is nested'
        assert len(self.select_term.parsed) == 1, len_msg


class SetTerm(object):

    def __init__(self, original):
        self.original = original
        self.parsed = self.parse_elements()

    def parse_elements(self):
        return [SetElement(self.original)]


class Clause(object):

    def __init__(self, original, term_class=None):
        self.term_class = term_class
        self.original = original
        self.parsed = self.parse_terms()

    def split_clause(self):
        out = []
        brace_open = False
        brace_closed = False
        temp = ''
        for token in self.original:
            if token == '[':
                brace_open = True
                brace_closed = False
            if token == ']':
                brace_open = False
                brace_closed = True
            if token == ',' and brace_open and not brace_closed:
                token = ';'
            temp += token
        parts = temp.split(',')
        for part in parts:
            if ';' in part:
                part = part.replace(';', ',')
            out.append(part)
        return out

    def parse_terms(self):
        out = []
        terms = self.split_clause()
        for term in terms:
            out.append(self.term_class(term))
        return out


class SelectClause(Clause):

    def __init__(self, original, term_class=SelectTerm):
        self.term_class = term_class
        self.original = original
        self.parsed = self.parse_terms()


class WhereClause(Clause):

    def __init__(self, original, term_class=WhereTerm):
        self.term_class = term_class
        self.original = original
        self.parsed = self.parse_terms()


class OrderClause(Clause):

    def __init__(self, original, term_class=OrderTerm):
        self.term_class = term_class
        self.original = original
        self.parsed = self.parse_terms()


class RangeClause(Clause):

    def __init__(self, original, term_class=RangeTerm):
        self.term_class = term_class
        self.original = original
        self.parsed = self.parse_terms()


class SetClause(Clause):

    def __init__(self, original, term_class=SetTerm):
        self.term_class = term_class
        self.original = original
        self.parsed = self.parse_terms()


class UriQuery(object):

    """
    Lex and parse a URI query into a UriQuery object:

        Query
            -> Clause(s)
                -> [Term(s)]
                    -> [Element(s)]

    """

    def __init__(self, table_name, uri_query):
        self.table_name = table_name # need the table name here? not sure...
        self.original = uri_query
        self.select = self.parse_clause(prefix='select=', Cls=SelectClause)
        self.where = self.parse_clause(prefix='where=', Cls=WhereClause)
        self.order = self.parse_clause(prefix='order=', Cls=OrderClause)
        self.range = self.parse_clause(prefix='range=', Cls=RangeClause)
        self.set = self.parse_clause(prefix='set=', Cls=SetClause)

    def parse_clause(self, prefix=None, Cls=None):
        if not prefix:
            raise Exception('prefix not specified')
        if not Cls:
            raise Exception('Cls not specified')
        parts = self.original.split('&')
        for part in parts:
            if part.startswith(prefix):
                return Cls(part.replace(prefix, ''))


class SqlGenerator(object):

    def __init__(self, table_name, uri_query):
        self.table_name = table_name
        self.uri_query = uri_query
        self.parsed_uri_query = UriQuery(table_name, uri_query)
        self.operators = {
            'eq': '=',
            'gt': '>',
            'gte': '>=',
            'lt': '<',
            'lte': '<=',
            'neq': '!=',
            'like': 'like',
            'ilike': 'ilike',
            'not': 'not',
            'is': 'is',
            'in': 'in'
        }
        self.select_query = self.gen_sql_select()
        self.update_query = self.gen_sql_update()
        self.delete_query = self.gen_sql_delete()

    def clause_map_terms(self, clause, map_func):
        # apply a function to all Terms in a clause
        out = []
        for term in clause.parsed:
            res = map_func(term)
            out.append(res)
        return out

    def select_map(self, map_func):
        return self.clause_map_terms(self.parsed_uri_query.select, map_func) \
            if self.parsed_uri_query.select else None

    def where_map(self, map_func):
        return self.clause_map_terms(self.parsed_uri_query.where, map_func) \
            if self.parsed_uri_query.where else None

    def order_map(self, map_func):
        return self.clause_map_terms(self.parsed_uri_query.order, map_func) \
            if self.parsed_uri_query.order else None

    def range_map(self, map_func):
        return self.clause_map_terms(self.parsed_uri_query.range, map_func) \
            if self.parsed_uri_query.range else None

    def set_map(self, map_func):
        return self.clause_map_terms(self.parsed_uri_query.set, map_func) \
            if self.parsed_uri_query.set else None

    # mandatory methods

    def gen_sql_select(self):
        pass

    def gen_sql_update(self):
        pass

    def gen_sql_delete(self):
        pass


class SqliteQueryGenerator(SqlGenerator):

    """Generate SQL for SQLite json1 backed tables, from a given UriQuery."""

    def _gen_sql_array_sub_selection(self, term, parsed, specific=None):
        if specific:
            fullkey = f"and fullkey = '$.{parsed.bare_key}[{parsed.idx}]'"
        else:
            fullkey = ''
        temp = []
        for key in parsed.sub_selections:
            temp.append(f"\"{key}\", json_extract(value, '$.{key}')")
        sub_selections = ','.join(temp)
        selection = f"""
                \"{parsed.bare_key}\",
                (case when json_extract(data, '$.{term.bare_term}') is not null then (
                    select json_group_array(vals) from (
                        select json_object(
                            {sub_selections}) as vals
                        from (
                            select key, value, fullkey, path
                            from \"{self.table_name}\", json_tree(\"{self.table_name}\".data)
                            where path = '$.{parsed.bare_key}'
                            {fullkey}
                            )
                        )
                    )
                else null end)
            """
        return selection

    def _gen_sql_data_selection(self, term):
        rev = term.parsed.copy()
        rev.reverse()
        out = []
        first_done = False
        for parsed in rev:
            if isinstance(parsed, Key):
                if not first_done:
                    selection = f"\"{parsed.element}\", json_extract(data, '$.{term.original}')"
                else:
                    selection = f"\"{parsed.element}\", json_object({selection})"
            elif isinstance(parsed, ArraySpecific):
                selection = f"""
                    \"{parsed.bare_key}\",
                    case when json_extract(data, '$.{term.original}') is not null then
                        json_array(json_extract(data, '$.{term.original}'))
                    else null end
                    """
            elif isinstance(parsed, ArraySpecificSingle):
                selection = self._gen_sql_array_sub_selection(term, parsed, specific=True)
            elif isinstance(parsed, ArraySpecificMultiple):
                selection = self._gen_sql_array_sub_selection(term, parsed, specific=True)
            elif isinstance(parsed, ArrayBroadcastSingle):
                selection = self._gen_sql_array_sub_selection(term, parsed, specific=False)
            elif isinstance(parsed, ArrayBroadcastMultiple):
                selection = self._gen_sql_array_sub_selection(term, parsed, specific=False)
            else:
                raise Exception(f'Could not parse {term.original}')
            first_done = True
        return selection

    def _gen_sql_select_clause(self):
        out = self.select_map(self._gen_sql_data_selection)
        if not out:
            sql_select = f'select * from "{self.table_name}"'
        else:
            joined = ",".join(out)
            sql_select = f"select json_object({joined}) from \"{self.table_name}\""
        return sql_select

    def _gen_sql_where_expressions(self, term):
        groups_start = ''.join(term.parsed[0].groups_start)
        groups_end = ''.join(term.parsed[0].groups_end)
        combinator = term.parsed[0].combinator if term.parsed[0].combinator else ''
        if len(term.parsed[0].select_term.parsed) > 1:
            test_select_term = term.parsed[0].select_term.parsed[-1]
            if isinstance(test_select_term, ArraySpecific):
                target = term.parsed[0].select_term.original
            elif isinstance(test_select_term, ArraySpecificSingle):
                _key = term.parsed[0].select_term.bare_term
                _idx = term.parsed[0].select_term.parsed[-1].idx
                _col = term.parsed[0].select_term.parsed[-1].sub_selections[0]
                target = f'{_key}[{_idx}].{_col}'
            else:
                raise Exception(f'Unsupported term {term.original}')
        else:
            if not isinstance(term.parsed[0].select_term.parsed[0], Key):
                raise Exception(f'Invalid term {term.original}')
            target = term.parsed[0].select_term.parsed[0].element
        col = f"json_extract(data, '$.{target}')"
        op = term.parsed[0].op
        val = term.parsed[0].val
        try:
            int(val)
            val = f'{val}'
        except ValueError:
            if val == 'null' or op == 'in':
                val = f'{val}'
            else:
                val = f'"{val}"'
        if op.endswith('.not'):
            op = op.replace('.', ' ')
        elif op.startswith('not.'):
            op = op.replace('.', ' ')
        elif op == 'in':
            val = val.replace('[', '')
            val = val.replace(']', '')
            values = val.split(',')
            new_values = []
            for v in values:
                new = "'%s'" % v
                new_values.append(new)
            joined = ','.join(new_values)
            val = "(%s)" % joined
        else:
            op = self.operators[op]
        if 'like' in op or 'ilike' in op:
            val = val.replace('*', '%')
        out = f'{groups_start} {combinator} {col} {op} {val} {groups_end}'
        return out

    def _gen_sql_where_clause(self):
        out = self.where_map(self._gen_sql_where_expressions)
        if not out:
            sql_where = ''
        else:
            joined = ' '.join(out)
            sql_where = f'where {joined}'
        return sql_where

    def gen_sql_order_clause(self):
        pass

    def gen_sql_range_clause(self):
        pass

    def gen_sql_select(self):
        _select = self._gen_sql_select_clause()
        _where = self._gen_sql_where_clause()
        return f'{_select} {_where}'

    def gen_sql_delete(self):
        return 'hi'

    def gen_sql_update(self):
        return 'hi'


class PostgresQueryGenerator(SqlGenerator):
    pass # TODO
