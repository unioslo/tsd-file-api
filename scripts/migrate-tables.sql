
-- https://github.com/unioslo/tsd-file-api/issues/233
-- https://github.com/unioslo/pysquril/pull/74

drop function if exists migrate_tables(text);
create or replace function migrate_tables(target text)
    returns void as $$
    declare _schema text;
    declare _table_name text;
    declare _new_name text;
    begin
        if target = 'survey' then
            for _schema, _table_name in
                select table_schema, table_name from information_schema.tables
                    where table_schema ~ 'p|ec[0-9]+'
                    and table_name ~ '.+_(audit|metadata)'
            loop
                raise info 'migrating: %', _table_name;
                _new_name := replace(_table_name, '_', '/');
                execute format(
                    'alter table $1."$2" rename to "$3"'
                ) using _schema, _table_name, _new_name;
            end loop;
        elsif target = 'apps' then
            for _schema, _table_name in
                select table_schema, table_name from information_schema.tables
                    where table_schema ~ 'p|ec[0-9]+_.+'
                    and table_name ~ '.+_audit' -- for all
                    or table_name ~ 'persons_.+' -- mvh
                    or table_name ~ '.+_memos' -- tables | ros
            loop
                raise info 'migrating: %', _table_name;
                _new_name := replace(_table_name, '_', '/');
                execute format(
                    'alter table $1."$2" rename to "$3"',
                 ) using _schema, _table_name, _new_name;
            end loop;
        end if;
    end;
$$ language plpgsql;

select migrate_tables('survey');
select migrate_tables('apps');
drop function if exists migrate_tables(text);
