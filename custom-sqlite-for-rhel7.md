
# Compiling sqlite for json1 support on rhel7

Default rhel7 compile options:
```txt
DISABLE_DIRSYNC
ENABLE_COLUMN_METADATA
ENABLE_FTS3
ENABLE_RTREE
ENABLE_UNLOCK_NOTIFY
SECURE_DELETE
TEMP_STORE=1
THREADSAFE=1
```

```bash
git clone https://github.com/azadkuh/sqlite-amalgamation.git
cd sqlite-amalgamation

yum install readline readline-devel

gcc -DSQLITE_ENABLE_JSON1 -DHAVE_READLINE -ldl -lreadline -lncurses -c -fPIC sqlite3.c
gcc -DSQLITE_ENABLE_JSON1 -DHAVE_READLINE -ldl -lreadline -lncurses -shared -o libsqlite3.so -fPIC sqlite3.o -ldl -lpthread
gcc -DSQLITE_ENABLE_JSON1 -DHAVE_READLINE -ldl -lreadline -lncurses shell.c sqlite3.c -lpthread -ldl -o sqlite3
```

# Replace system library

```
unlink /usr/lib64/libsqlite3.so.0
mv /usr/lib64/libsqlite3.so.0.8.6 /usr/lib64/libsqlite3.so.0.8.5
cp libsqlite3.so /usr/lib64/libsqlite3.so.0.8.6
ln -s /usr/lib64/libsqlite3.so.0.8.6 /usr/lib64/libsqlite3.so.0
```

# Test in python

```python
import sqlite3
conn = sqlite3.connect('test.db')
c = conn.cursor()
c.execute('create table t(d json)')
conn.commit()
c.execute('insert into t values (\'{"f": 1}\')')
conn.commit()
c.execute('select json_extract(d, \'$.f\') from t')
c.fetchone()
exit()
```

# references

https://charlesleifer.com/blog/using-the-sqlite-json1-and-fts5-extensions-with-python/
https://www.sqlite.org/compile.html
https://www.sqlite.org/howtocompile.html
https://github.com/azadkuh/sqlite-amalgamation#build--install
