

import logging

from db import session_scope

class Resumable(object):

    def __init__(self):
        pass

    @classmethod
    def db_insert_new_for_user(self, engine, resumable_id, user, group):
        resumable_table = 'resumable_%s' % resumable_id
        with session_scope(engine) as session:
            session.execute('create table if not exists resumable_uploads(id text, upload_group text)')
            session.execute('insert into resumable_uploads (id, upload_group) values (:resumable_id, :upload_group)',
                            {'resumable_id': resumable_id, 'upload_group': group})
            session.execute('create table "%s"(chunk_num int, chunk_size int)' % resumable_table) # want an exception if exists
        return True

    @classmethod
    def db_update_with_chunk_info(self, engine, resumable_id, chunk_num, chunk_size):
        resumable_table = 'resumable_%s' % resumable_id
        with session_scope(engine) as session:
            session.execute('insert into "%s"(chunk_num, chunk_size) values (:chunk_num, :chunk_size)' % resumable_table,
                            {'chunk_num': chunk_num, 'chunk_size': chunk_size})
        return True

    @classmethod
    def db_pop_chunk(self, engine, resumable_id, chunk_num):
        resumable_table = 'resumable_%s' % resumable_id
        with session_scope(engine) as session:
            res = session.execute('delete from "%s" where chunk_num = :chunk_num' % resumable_table,
                                  {'chunk_num': chunk_num})
        return True

    @classmethod
    def db_get_total_size(self, engine, resumable_id):
        resumable_table = 'resumable_%s' % resumable_id
        with session_scope(engine) as session:
            res = session.execute('select sum(chunk_size) from "%s"' % resumable_table).fetchone()[0]
        return res

    @classmethod
    def db_get_group(self, engine, resumable_id):
        resumable_table = 'resumable_%s' % resumable_id
        with session_scope(engine) as session:
            res = session.execute('select upload_group from resumable_uploads where id = :resumable_id',
                                  {'resumable_id': resumable_id}).fetchone()[0]
        return res

    @classmethod
    def db_upload_belongs_to_user(self, engine, resumable_id, user):
        with session_scope(engine) as session:
            res = session.execute('select count(1) from resumable_uploads where id = :resumable_id',
                                  {'resumable_id': resumable_id}).fetchone()[0]
        return True if res > 0 else False

    @classmethod
    def db_get_all_resumable_ids_for_user(self, engine, user):
        try:
            with session_scope(engine) as session:
                res = session.execute('select id from resumable_uploads').fetchall()
        except Exception:
            return []
        return res # [(id,), (id,)]

    @classmethod
    def db_remove_completed_for_user(self, engine, resumable_id, user):
        resumable_table = 'resumable_%s' % resumable_id
        with session_scope(engine) as session:
            session.execute('delete from resumable_uploads where id = :resumable_id',
                            {'resumable_id': resumable_id})
            session.execute('drop table "%s"' % resumable_table)
        return True

