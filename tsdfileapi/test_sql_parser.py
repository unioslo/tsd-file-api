
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
                },
                {
                    'h': 0
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
        # with slices
        '/mytable?select=c[0].h',
        '/mytable?select=a.k3[0].h',
        '/mytable?select=x,y,c[0].h,b[1]',
        # TODO: impl
        '/mytable?select=c[0].(h,p)',
        '/mytable?select=c[#].h',
        #'/mytable?select=c[#].(h,p)',
        # conditional filtering
        '/mytable?select=x&z=eq.5&y=gt.0',
        '/mytable?x=not.like.*zap&y=not.is.null',
        '/mytable?select=z&a.k1.r2=eq.2',
        '/mytable?select=z&a.k1.r1[0]=eq.1',
        '/mytable?select=z&a.k3[0].h=eq.0',
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
    assert sql.idx_present.match('x[#]')
    # single slice
    assert not sql.idx_single.match('x[#]')
    assert sql.idx_single.match('x[1]')
    assert sql.idx_single.match('x[12]')
    # subselect present
    assert not sql.subselect_present.match('x[1]')
    assert sql.subselect_present.match('x[#].k')
    assert sql.subselect_present.match('x[1:9].(k,j)')
    # subselect single
    assert sql.subselect_single.match('x[#].k')
    # subselect mutliple
    assert not sql.subselect_multiple.match('x[#].k')
    # column quoting
    print(sql.quote_column_selection('x'))
    print(sql.quote_column_selection('x.y'))
    print(sql.quote_column_selection('y[1]'))
    print(sql.quote_column_selection('y[1].z'))
    print(sql.quote_column_selection('y[1].(z,a)'))
    print(sql.quote_column('erd.ys[1].(z,a)'))
    print(sql.quote_column('erd.ys[1].z'))
    print(sql.quote_column('"erd"."ys"[1]."z"'))
    print(sql.smart_split('x,y[1].(f,m,l),z')) # desired: ['x', 'y[1].(f,m,l)', 'z']
    print(sql.smart_split('x,y[1].k'))
    #print(sql.quote_column(',x,y[1].(z,a)')) - should error
    example_data_selections = [
        'x',            # NA      NA
        'x[1]',         # single  none
        'x[1].k',       # single  single
        'x[1].(k,d)',   # single  multipl
        'x[#].y',       # all     single
        'x[#].(y,z)',   # all     multiple
    ]
    for selection in example_data_selections:
        quoted_name = sql.quote_column(selection)
        table_name = 'mytable'
        print(selection, '|', sql.construct_data_selection_str(selection, quoted_name, selection, table_name))
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
