
from db import sqlite_init, sqlite_insert, sqlite_get_data, sqlite_update_data, sqlite_delete_data
from parser import SqlStatement

if __name__ == '__main__':
    test_data = [
        {
            'x': 0,
            'y': 1,
            'z': 5,
            'b':[1, 2, 5, 1],
            'c': None
        },
        {
            'y': 11,
            'z': 1,
            'c': [
                {
                    'h': 3,
                    'p': 99,
                    'w': False
                },
                {
                    'h': 32,
                    'p': False,
                    'w': True,
                    'i': {
                        't': [1,2,3]
                    }
                }
            ]
        },
        {
            'a': {
                'k1': {
                    'r1': [1, 2],
                    'r2': 2
                },
                'k2': ['val', 9]
            },
            'z': 0
        },
        {
            'a': {
                'k1': {
                    'r1': [33, 200],
                    'r2': 90
                },
                'k2': ['val222', 90],
                'k3': [{'h': 0}]
            },
            'z': 10
        },
    ]
    create_engine = sqlite_init('/tmp', name='file-api-test.db')
    query_engine = sqlite_init('/tmp', name= 'file-api-test.db', builtin=True)
    sqlite_delete_data(query_engine, 'mytable', '/mytable')
    sqlite_insert(create_engine, 'mytable', test_data)
    select_uris = [
        # selections
        #
        # TODO: shape
        # add &simplify=true for optional result simplification
        # default to shape preservation
        #
        # TODO: slicing, use ; to leave space for future range slices
        # d[1] - done
        # r.d[1] - done
        # d[1;k1]
        # d[1;k1,k2]
        # d[1:2]
        # d[1:2;k1,k2]
        #
        # POC: map selection of two keys over a whole array
        # select json_group_array(target) from
        #   (select path, json_group_object(key, value) as target from
        #       (select key, value, fullkey, path from
        #           mytable, json_tree(mytable.data)
        #           where fullkey like '$.c[%].h' or fullkey like '$.c[%].p')
        #        group by path);
        '/mytable',
        '/mytable?select=x',
        '/mytable?select=x,y',
        '/mytable?select=x,a.k1',
        '/mytable?select=x,a.k1.r1',
        '/mytable?select=a.k1.r1',
        '/mytable?select=a.k1.r1',
        '/mytable?select=b[1]',
        '/mytable?select=a,b[1]',
        '/mytable?select=a.k1.r1[0]',
        # more slices, and subselects
        #'/mytable?select=c[0].h',
        # conditional filtering
        '/mytable?select=x&z=eq.5&y=gt.0',
        '/mytable?x=not.like.*zap&y=not.is.null',
        '/mytable?select=z&a.k1.r2=eq.2',
        '/mytable?select=z&a.k1.r1[0]=eq.1',
        '/mytable?select=z&a.k3[0].h=eq.0', # works - but this is unfortunately inconsistent with selection syntax - can we live with it?
        # ordering - TODO: support nesting, and slicing
        '/mytable?order=y.desc',
        # todo add
        # range=20.100 - limit 100 offset 20; - for pagination
        # simplify
    ]
    update_uris = [
        # updates
        '/mytable?set=x.5,y.6&z=eq.5',
        '/mytable?set=a.k1.r2.5&z=eq.0', # need slicing here
    ]
    delete_uris = [
        # deletion
        #'/mytable?z=not.is.null'
    ]
    # test regexes for single column selection strategies
    sql = SqlStatement('')
    # slice present
    assert not sql.idx_present.match('x')
    assert sql.idx_present.match('x[11]')
    assert sql.idx_present.match('x[1]')
    assert sql.idx_present.match('x[1:3]')
    assert sql.idx_present.match('x[#]')
    assert sql.idx_present.match('x[1:3].y')
    assert sql.idx_present.match('x[1:3].(y,z)')
    # single slice
    assert not sql.idx_single.match('x[1:3]')
    assert not sql.idx_single.match('x[#]')
    assert sql.idx_single.match('x[1]')
    assert sql.idx_single.match('x[12]')
    # range slice
    assert not sql.idx_range.match('x[1]')
    assert not sql.idx_range.match('x[#]')
    assert sql.idx_range.match('x[1:3]')
    # all slice
    assert not sql.idx_all.match('x[1]')
    assert not sql.idx_all.match('x[1:10]')
    assert sql.idx_all.match('x[#]')
    # subselect present
    assert not sql.subselect_present.match('x[1]')
    assert sql.subselect_present.match('x[#].k')
    assert sql.subselect_present.match('x[1:9].(k,j)')
    # subselect single
    assert not sql.subselect_single.match('x[1:9].(k,j)')
    assert sql.subselect_single.match('x[#].k')
    # subselect mutliple
    assert not sql.subselect_multiple.match('x[#].k')
    assert sql.subselect_multiple.match('x[1:9].(k,j)')
    for uri in select_uris:
        try:
            print(uri)
            query_engine = sqlite_init('/tmp', name= 'file-api-test.db', builtin=True)
            print(sqlite_get_data(query_engine, 'mytable', uri, verbose=True))
            print()
        except Exception:
            pass
    for uri in update_uris:
        try:
            print(uri)
            query_engine = sqlite_init('/tmp', name= 'file-api-test.db', builtin=True)
            print(sqlite_update_data(query_engine, 'mytable', uri, verbose=True))
            query_engine = sqlite_init('/tmp', name= 'file-api-test.db', builtin=True)
            print(sqlite_get_data(query_engine, 'mytable', '/mytable'))
            print()
        except Exception:
            pass
