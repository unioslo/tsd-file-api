
import logging

from db import session_scope

def resumable_db_insert_new_for_user(engine, resumable_id, user, group):
    resumable_table = 'resumable_%s' % resumable_id
    with session_scope(engine) as session:
        session.execute('create table if not exists resumable_uploads(id text, upload_group text)')
        session.execute('insert into resumable_uploads (id, upload_group) values (:resumable_id, :upload_group)',
                        {'resumable_id': resumable_id, 'upload_group': group})
        session.execute('create table "%s"(chunk_num int, chunk_size int)' % resumable_table) # want an exception if exists
    return True


def resumable_db_update_with_chunk_info(engine, resumable_id, chunk_num, chunk_size):
    resumable_table = 'resumable_%s' % resumable_id
    with session_scope(engine) as session:
        session.execute('insert into "%s"(chunk_num, chunk_size) values (:chunk_num, :chunk_size)' % resumable_table,
                        {'chunk_num': chunk_num, 'chunk_size': chunk_size})
    return True


def resumable_db_pop_chunk(engine, resumable_id, chunk_num):
    resumable_table = 'resumable_%s' % resumable_id
    with session_scope(engine) as session:
        res = session.execute('delete from "%s" where chunk_num = :chunk_num' % resumable_table,
                              {'chunk_num': chunk_num})
    return True


def resumable_db_get_total_size(engine, resumable_id):
    resumable_table = 'resumable_%s' % resumable_id
    with session_scope(engine) as session:
        res = session.execute('select sum(chunk_size) from "%s"' % resumable_table).fetchone()[0]
    return res


def resumable_db_get_group(engine, resumable_id):
    resumable_table = 'resumable_%s' % resumable_id
    with session_scope(engine) as session:
        res = session.execute('select upload_group from resumable_uploads where id = :resumable_id',
                              {'resumable_id': resumable_id}).fetchone()[0]
    return res


def resumable_db_upload_belongs_to_user(engine, resumable_id, user):
    with session_scope(engine) as session:
        res = session.execute('select count(1) from resumable_uploads where id = :resumable_id',
                              {'resumable_id': resumable_id}).fetchone()[0]
    return True if res > 0 else False


def resumable_db_get_all_resumable_ids_for_user(engine, user):
    with session_scope(engine) as session:
        res = session.execute('select id from resumable_uploads').fetchall()
    return res # [(id,), (id,)]


def resumable_db_remove_completed_for_user(engine, resumable_id, user):
    resumable_table = 'resumable_%s' % resumable_id
    with session_scope(engine) as session:
        session.execute('delete from resumable_uploads where id = :resumable_id',
                        {'resumable_id': resumable_id})
        session.execute('drop table "%s"' % resumable_table)
    return True
