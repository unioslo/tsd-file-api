
"""SQURIL - Structured Query URI Language."""

import json
import re

from abc import ABC, abstractmethod
from typing import Optional, Union, Callable

class SelectElement(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass
    @property
    @abstractmethod
    def regex(self) -> str:
        pass


class BaseSelectElement(SelectElement):
    name = None
    regex = None
    def __init__(self, element: str) -> None:
        self.element = element
    def create_bare_key(self, element: str) -> Optional[list]:
        return element.split('[')[0] if '[' in element else None
    def create_sub_selections(self, element: str) -> list:
        return element.split('|')[1].replace(']', '').split(',') if '|' in element else []
    def create_idx(self, element: str) -> Optional[str]:
        if '[' in element and '|' in element:
            return re.sub(r'.+\[(.*)\|(.*)\]', r'\1', element)
        elif '[' in element and '|' not in element:
            return re.sub(r'.+\[(.*)\]', r'\1', element)
        else:
            return None

class Key(BaseSelectElement):
    name = 'key'
    regex = r'[^\[\]]+$'
    def __init__(self, element: str) -> None:
        self.element = element
        self.bare_key = self.create_bare_key(element)
        self.sub_selections = self.create_sub_selections(element)
        self.idx = self.create_idx(element)


class ArraySpecific(BaseSelectElement):
    name = 'array.specific'
    regex = r'.+\[[0-9]+\]$'
    def __init__(self, element: str) -> None:
        self.element = element
        self.bare_key = self.create_bare_key(element)
        self.sub_selections = self.create_sub_selections(element)
        self.idx = self.create_idx(element)


class ArraySpecificSingle(BaseSelectElement):
    name = 'array.specific.single'
    regex = r'.+\[[0-9]+\|[^,]+\]$'
    def __init__(self, element: str) -> None:
        self.element = element
        self.bare_key = self.create_bare_key(element)
        self.sub_selections = self.create_sub_selections(element)
        self.idx = self.create_idx(element)


class ArraySpecificMultiple(BaseSelectElement):
    name = 'array.specific.multiple'
    regex = r'.+\[[0-9]+\|.+,.+\]$'
    def __init__(self, element: str) -> None:
        self.element = element
        self.bare_key = self.create_bare_key(element)
        self.sub_selections = self.create_sub_selections(element)
        self.idx = self.create_idx(element)


class ArrayBroadcastSingle(BaseSelectElement):
    name = 'array.broadcast.single'
    regex = r'.+\[\*\|[^,]+\]$'
    def __init__(self, element: str) -> None:
        self.element = element
        self.bare_key = self.create_bare_key(element)
        self.sub_selections = self.create_sub_selections(element)
        self.idx = self.create_idx(element)


class ArrayBroadcastMultiple(BaseSelectElement):
    name = 'array.broadcast.multiple'
    regex = r'.+\[\*\|.+,.+\]$'
    def __init__(self, element: str) -> None:
        self.element = element
        self.bare_key = self.create_bare_key(element)
        self.sub_selections = self.create_sub_selections(element)
        self.idx = self.create_idx(element)


class SelectTerm(object):

    def __init__(self, original: str) -> None:
        self.original = original
        self.bare_term = original.split('[')[0]
        self.parsed = self.parse_elements()

    def parse_elements(self) -> list:
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

    def __init__(
        self,
        groups: list,
        combinator: str,
        term: str,
        op: str,
        val: str,
    ) -> None:
        self.groups_start, self.groups_end = self.categorise_groups(groups)
        self.combinator = combinator
        self.select_term = SelectTerm(term)
        self.op = op
        self.val = val

    def categorise_groups(self, groups: list) -> tuple:
        start, end = [], []
        for bracket in groups:
            if bracket == '(':
                start.append(bracket)
            elif bracket == ')':
                end.append(bracket)
        return start, end


class WhereTerm(object):

    def __init__(self, original: str) -> None:
        self.original = original
        self.parsed = self.parse_elements()

    def parse_elements(self) -> list:
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

    def __init__(self, term: str, direction: str) -> None:
        self.select_term = SelectTerm(term)
        self.direction = direction


class OrderTerm(object):

    def __init__(self, original: str) -> None:
        self.original = original
        self.parsed = self.parse_elements()

    def parse_elements(self) -> list:
        parts = self.original.split('.')
        term = '.'.join(parts[:-1])
        direction = parts[-1]
        return [OrderElement(term, direction)]


class RangeElement(object):

    def __init__(self, start: str, end: str) -> None:
        self.start = start
        self.end = end


class RangeTerm(object):

    def __init__(self, original: str) -> None:
        self.original = original
        self.parsed = self.parse_elements()

    def parse_elements(self) -> list:
        start, end = self.original.split('.')
        return [RangeElement(start, end)]


class SetElement(object):

    def __init__(self, term: str) -> None:
        self.select_term = SelectTerm(term)
        type_msg = f'{term} must be an instance of Key'
        assert isinstance(self.select_term.parsed[0], Key), type_msg
        len_msg = f'SetElements can only be top level keys - {term} is nested'
        assert len(self.select_term.parsed) == 1, len_msg


class SetTerm(object):

    def __init__(self, original: str) -> None:
        self.original = original
        self.parsed = self.parse_elements()

    def parse_elements(self) -> list:
        return [SetElement(self.original)]


class Clause(object):

    term_class = None

    def __init__(self, original: str) -> None:
        self.original = original
        self.parsed = self.parse_terms()

    def split_clause(self) -> list:
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

    def parse_terms(self) -> list:
        out = []
        terms = self.split_clause()
        for term in terms:
            out.append(self.term_class(term))
        return out


class SelectClause(Clause):
    term_class = SelectTerm

class WhereClause(Clause):
    term_class=WhereTerm

class OrderClause(Clause):
    term_class = OrderTerm

class RangeClause(Clause):
    term_class = RangeTerm

class SetClause(Clause):
    term_class = SetTerm


class UriQuery(object):

    """
    Lex and parse a URI query into a UriQuery object:

        Query
            -> Clause(s)
                -> [Term(s)]
                    -> [Element(s)]

    """

    def __init__(
        self,
        table_name: str,
        uri_query: str,
        data: Union[list, dict] = None,
    ) -> None:
        self.table_name = table_name
        self.original = uri_query
        self.data = data
        self.select = self.parse_clause(prefix='select=', Cls=SelectClause)
        self.where = self.parse_clause(prefix='where=', Cls=WhereClause)
        self.order = self.parse_clause(prefix='order=', Cls=OrderClause)
        self.range = self.parse_clause(prefix='range=', Cls=RangeClause)
        self.set = self.parse_clause(prefix='set=', Cls=SetClause)

    def parse_clause(self, *, prefix: str, Cls: Clause) -> Clause:
        if not prefix:
            raise Exception('prefix not specified')
        if not Cls:
            raise Exception('Cls not specified')
        parts = self.original.split('&')
        for part in parts:
            if part.startswith(prefix):
                return Cls(part.replace(prefix, ''))


class SqlGenerator(object):

    """
    Generic class, used to implement SQL code generation.

    """

    db_init_sql = None
    json_array_sql = None

    def __init__(
        self,
        table_name: str,
        uri_query: str,
        data: Union[list, dict] = None,
    ) -> None:
        self.table_name = table_name
        self.uri_query = uri_query
        self.data = data
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
        if not self.json_array_sql:
            msg = 'Extending the SqlGenerator requires setting the class level property: json_array_sql'
            raise Exception(msg)
        self.select_query = self.sql_select()
        self.update_query = self.sql_update()
        self.delete_query = self.sql_delete()

    # Classes that extend the SqlGenerator must implement the following methods
    # they are called by functions that are mapped over terms in clauses
    # for each term, an appropriate piece of SQL needs to be returned.
    # What is appropriate, depends on the backend.

    def _gen_sql_key_selection(self, term: SelectTerm, parsed: Key) -> str:
        """
        Generate SQL for selecting a Key element.

        Called by _term_to_sql_select when generating the select
        part of the SQL.

        """
        raise NotImplementedError

    def _gen_sql_array_selection(self, term: SelectTerm, parsed: ArraySpecific) -> str:
        """
        Generate SQL for selecting an ArraySpecific element.

        Called by _term_to_sql_select when generating the select
        part of the SQL.

        """
        raise NotImplementedError

    def _gen_sql_array_sub_selection(
        self,
        term: SelectTerm,
        parsed: Union[
            ArraySpecificSingle,
            ArraySpecificMultiple,
            ArrayBroadcastSingle,
            ArrayBroadcastMultiple,
        ],
    ) -> str:
        """
        Generate SQL for selecting inside arrays.

        Called by _term_to_sql_select when generating the select
        part of the SQL.

        """
        raise NotImplementedError

    def _gen_sql_col(self, term: Union[SelectTerm, WhereTerm, OrderTerm]) -> str:
        """
        Generate a column reference from a term,
        used in where and order clauses.

        """
        raise NotImplementedError

    def _gen_sql_update(self, term: Key) -> str:
        """
        Generate an update expression, from a term
        using the data passed to the constructor.

        """
        raise NotImplementedError

    def _clause_map_terms(self, clause: Clause, map_func: Callable) -> list:
        # apply a function to all Terms in a clause
        out = []
        for term in clause.parsed:
            res = map_func(term)
            out.append(res)
        return out

    # methods for mapping functions over terms in different types of clauses

    def select_map(self, map_func: Callable) -> Optional[list]:
        return self._clause_map_terms(self.parsed_uri_query.select, map_func) \
            if self.parsed_uri_query.select else None

    def where_map(self, map_func: Callable) -> Optional[list]:
        return self._clause_map_terms(self.parsed_uri_query.where, map_func) \
            if self.parsed_uri_query.where else None

    def order_map(self, map_func: Callable) -> Optional[list]:
        return self._clause_map_terms(self.parsed_uri_query.order, map_func) \
            if self.parsed_uri_query.order else None

    def range_map(self, map_func: Callable) -> Optional[list]:
        return self._clause_map_terms(self.parsed_uri_query.range, map_func) \
            if self.parsed_uri_query.range else None

    def set_map(self, map_func: Callable) -> Optional[list]:
        return self._clause_map_terms(self.parsed_uri_query.set, map_func) \
            if self.parsed_uri_query.set else None

    # term handler functions
    # mapped over terms in a clause
    # generates SQL for each term
    # SQL is generated by calling other functions
    # which are implemented for specific SQL backend implementations

    def _term_to_sql_select(self, term: SelectTerm) -> str:
        rev = term.parsed.copy()
        rev.reverse()
        out = []
        first_done = False
        for parsed in rev:
            if isinstance(parsed, Key):
                if not first_done:
                    selection = self._gen_sql_key_selection(term, parsed)
            elif isinstance(parsed, ArraySpecific):
                selection = self._gen_sql_array_selection(term, parsed)
            elif (
                isinstance(parsed, ArraySpecificSingle)
                or isinstance(parsed, ArraySpecificMultiple)
                or isinstance(parsed, ArrayBroadcastSingle)
                or isinstance(parsed, ArrayBroadcastMultiple)
            ):
                selection = self._gen_sql_array_sub_selection(term, parsed)
            else:
                raise Exception(f'Could not parse {term.original}')
            first_done = True
        return selection

    def _term_to_sql_where(self, term: WhereTerm) -> str:
        groups_start = ''.join(term.parsed[0].groups_start)
        groups_end = ''.join(term.parsed[0].groups_end)
        combinator = term.parsed[0].combinator if term.parsed[0].combinator else ''
        col = self._gen_sql_col(term)
        op = term.parsed[0].op
        val = term.parsed[0].val
        try:
            int(val)
            val = f'{val}'
        except ValueError:
            if val == 'null' or op == 'in':
                val = f'{val}'
            else:
                val = f"'{val}'"
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

    def _term_to_sql_order(self, term: OrderTerm) -> str:
        selection = self._gen_sql_col(term)
        direction = term.parsed[0].direction
        return f'order by {selection} {direction}'

    def _term_to_sql_range(self, term: RangeTerm) -> str:
        return f'limit {term.parsed[0].end} offset {term.parsed[0].start}'

    def _term_to_sql_update(self, term: SelectTerm) -> str:
        if not self.data:
            return None
        out = self._gen_sql_update(term)
        return out

    # mapper methods - used by public methods

    def _gen_sql_select_clause(self) -> str:
        out = self.select_map(self._term_to_sql_select)
        if not out:
            sql_select = f'select * from {self.table_name}'
        else:
            joined = ",".join(out)
            sql_select = f"select {self.json_array_sql}({joined}) from {self.table_name}"
        return sql_select

    def _gen_sql_where_clause(self) -> str:
        out = self.where_map(self._term_to_sql_where)
        if not out:
            sql_where = ''
        else:
            joined = ' '.join(out)
            sql_where = f'where {joined}'
        return sql_where

    def _gen_sql_order_clause(self) -> str:
        out = self.order_map(self._term_to_sql_order)
        if not out:
            return ''
        else:
            return out[0]

    def _gen_sql_range_clause(self) -> str:
        out = self.range_map(self._term_to_sql_range)
        if not out:
            return ''
        else:
            return out[0]

    # public methods - called by constructor

    def sql_select(self) -> str:
        _select = self._gen_sql_select_clause()
        _where = self._gen_sql_where_clause()
        _order = self._gen_sql_order_clause()
        _range = self._gen_sql_range_clause()
        return f'{_select} {_where} {_order} {_range}'

    def sql_update(self) -> str:
        out = self.set_map(self._term_to_sql_update)
        if not out:
            return ''
        else:
            _set = out[0]
            _where = self._gen_sql_where_clause()
            return f'update {self.table_name} {_set} {_where}'

    def sql_delete(self) -> str:
        _where = self._gen_sql_where_clause()
        return f'delete from {self.table_name} {_where}'


class SqliteQueryGenerator(SqlGenerator):

    """Generate SQL for SQLite json1 backed tables, from a given UriQuery."""

    db_init_sql = None
    json_array_sql = 'json_array'

    # Helper functions - used by mappers

    def _gen_sql_key_selection(self, term: SelectTerm, parsed: Key) -> str:
        return f"json_extract(data, '$.{term.original}')"

    def _gen_sql_array_selection(self, term: SelectTerm, parsed: ArraySpecific) -> str:
        return f"json_extract(data, '$.{term.original}')"

    def _gen_sql_array_sub_selection(
        self,
        term: SelectTerm,
        parsed: Union[
            ArraySpecificSingle,
            ArraySpecificMultiple,
            ArrayBroadcastSingle,
            ArrayBroadcastMultiple,
        ],
    ) -> str:
        if (
            isinstance(parsed, ArraySpecificSingle)
            or isinstance(parsed, ArraySpecificMultiple)
        ):
            fullkey = f"and fullkey = '$.{term.bare_term}[{parsed.idx}]'"
            vals = 'vals'
        else:
            fullkey = ''
            vals = 'json_group_array(vals)'
        temp = []
        for key in parsed.sub_selections:
            temp.append(f"json_extract(value, '$.{key}')")
        sub_selections = ','.join(temp)
        sub_selections = f'json_array({sub_selections})' if len(temp) > 1 else f'{sub_selections}'
        selection = f"""
                (case when json_extract(data, '$.{term.bare_term}') is not null then (
                    select {vals} from (
                        select
                            {sub_selections} as vals
                        from (
                            select key, value, fullkey, path
                            from {self.table_name}, json_tree({self.table_name}.data)
                            where path = '$.{term.bare_term}'
                            {fullkey}
                            )
                        )
                    )
                else null end)
            """
        return selection

    def _gen_sql_col(self, term: Union[SelectTerm, WhereTerm, OrderTerm]) -> str:
        if isinstance(term, WhereTerm) or isinstance(term, OrderTerm):
            select_term = term.parsed[0].select_term
        elif isinstance(term, SelectTerm):
            select_term = term
        if len(select_term.parsed) > 1:
            test_select_term = select_term.parsed[-1]
            if isinstance(test_select_term, ArraySpecific):
                target = select_term.original
            elif isinstance(test_select_term, ArraySpecificSingle):
                _key = select_term.bare_term
                _idx = select_term.parsed[-1].idx
                _col = select_term.parsed[-1].sub_selections[0]
                target = f'{_key}[{_idx}].{_col}'
            else:
                target = select_term.bare_term
        else:
            if not isinstance(select_term.parsed[0], Key):
                raise Exception(f'Invalid term {term.original}')
            target = select_term.parsed[0].element
        col = f"json_extract(data, '$.{target}')"
        return col

    def _gen_sql_update(self, term: Key) -> str:
        key = term.parsed[0].select_term.bare_term
        assert self.data.get(key) is not None, f'Target key of update: {key} not found in payload'
        assert len(self.data.keys()) == 1, f'Cannot update more than one key per statement'
        new = json.dumps(self.data)
        return f"set data = json_patch(data, '{new}')"


class PostgresQueryGenerator(SqlGenerator):

    json_array_sql = 'jsonb_build_array'
    db_init_sql = [
        """
        create or replace function filter_array_elements(data jsonb, keys text[])
            returns jsonb as $$
            declare key text;
            declare element jsonb;
            declare filtered jsonb;
            declare out jsonb;
            declare val jsonb;
            begin
                create temporary table if not exists info(v jsonb) on commit drop;
                for element in select jsonb_array_elements(data) loop
                    for key in select unnest(keys) loop
                        if filtered is not null then
                            filtered := filtered || jsonb_extract_path(element, key);
                        else
                            filtered := jsonb_extract_path(element, key);
                        end if;
                    if filtered is null then
                        filtered := '[]'::jsonb;
                    end if;
                    end loop;
                insert into info values (filtered);
                filtered := null;
                end loop;
                out := '[]'::jsonb;
                for val in select * from info loop
                    out := out || jsonb_build_array(val);
                end loop;
                return out;
            end;
        $$ language plpgsql;
        """,
        """
        create or replace function unique_data()
        returns trigger as $$
            begin
                NEW.uniq := md5(NEW.data::text);
                return new;
            end;
        $$ language plpgsql;
        """
    ]

    def _gen_select_target(self, term_attr: str) -> str:
        return term_attr.replace('.', ',') if '.' in term_attr else term_attr

    def _gen_sql_key_selection(self, term: SelectTerm, parsed: Key) -> str:
        target = self._gen_select_target(term.original)
        selection = f"data#>'{{{target}}}'"
        return selection

    def _gen_sql_array_selection(self, term: SelectTerm, parsed: ArraySpecific) -> str:
        target = self._gen_select_target(term.bare_term)
        selection = f"""
            case when data#>'{{{target}}}'->{parsed.idx} is not null then
                data#>'{{{target}}}'->{parsed.idx}
            else null end
            """
        return selection

    def _gen_sql_array_sub_selection(
        self,
        term: SelectTerm,
        parsed: Union[
            ArraySpecificSingle,
            ArraySpecificMultiple,
            ArrayBroadcastSingle,
            ArrayBroadcastMultiple,
        ],
    ) -> str:
        target = self._gen_select_target(term.bare_term)
        sub_selections = ','.join(parsed.sub_selections)
        data_selection_expr = f"filter_array_elements(data#>'{{{target}}}','{{{sub_selections}}}')"
        if (
            isinstance(parsed, ArraySpecificSingle)
            or isinstance(parsed, ArraySpecificMultiple)
        ):
            data_selection_expr = f'{data_selection_expr}->{parsed.idx}'
        selection = f"""
            case
                when data#>'{{{target}}}' is not null
                and jsonb_typeof(data#>'{{{target}}}') = 'array'
            then {data_selection_expr}
            else null end
            """
        return selection

    def _gen_sql_col(self, term: Union[SelectTerm, WhereTerm, OrderTerm]) -> str:
        if isinstance(term, WhereTerm) or isinstance(term, OrderTerm):
            select_term = term.parsed[0].select_term
        elif isinstance(term, SelectTerm):
            select_term = term
        if isinstance(term, WhereTerm):
            final_select_op = '#>>' # due to integer comparisons
        else:
            final_select_op = '#>'
        if len(select_term.parsed) > 1:
            test_select_term = select_term.parsed[-1]
            if isinstance(test_select_term, ArraySpecific):
                target = self._gen_select_target(select_term.bare_term)
                _idx = select_term.parsed[-1].idx
                col = f"data#>'{{{target}}}'{final_select_op}'{{{_idx}}}'"
            elif isinstance(test_select_term, ArraySpecificSingle):
                target = self._gen_select_target(select_term.bare_term)
                _idx = select_term.parsed[-1].idx
                _col = select_term.parsed[-1].sub_selections[0]
                col = f"data#>'{{{target}}}'#>'{{{_idx}}}'#>'{{{_col}}}'"
            else:
                target = self._gen_select_target(select_term.bare_term)
                col = f"data{final_select_op}'{{{target}}}'"
        else:
            if not isinstance(select_term.parsed[0], Key):
                raise Exception(f'Invalid term {term.original}')
            target = select_term.parsed[0].element
            col = f"data{final_select_op}'{{{target}}}'"
        if isinstance(term, WhereTerm):
            try:
                integer_ops = ['eq', 'gt', 'gte', 'lt', 'lte', 'neq']
                int(term.parsed[0].val)
                if term.parsed[0].op in integer_ops:
                    col = f'({col})::int'
            except ValueError:
                pass
        return col

    def _gen_sql_update(self, term: Key) -> str:
        key = term.parsed[0].select_term.bare_term
        assert self.data.get(key) is not None, f'Target key of update: {key} not found in payload'
        assert len(self.data.keys()) == 1, f'Cannot update more than one key per statement'
        val = self.data[key]
        return f"set data = jsonb_set(data, '{{{key}}}', '{val}')"
