
import re
import logging
import os
import shutil

from db import session_scope
from utils import md5sum

_IS_VALID_UUID = re.compile(r'([a-f\d0-9-]{32,36})')

def atoi(text):
    return int(text) if text.isdigit() else text


def natural_keys(text):
    """
    alist.sort(key=natural_keys) sorts in human order
    http://nedbatchelder.com/blog/200712/human_sorting.html
    """
    return [ atoi(c) for c in re.split(r'(\d+)', text) ]


def resumables_cmp(a, b):
    a_time = a[0]
    b_time = b[0]
    if a_time > b_time:
        return -1
    elif a_time < b_time:
        return 1
    else:
        return 1


def find_nth_chunk(project_dir, upload_id, filename, n):
    n = n - 1 # chunk numbers start at 1, but keep 0-based for the signaure
    current_resumable = '%s/%s' % (project_dir, upload_id)
    files = os.listdir(current_resumable)
    files.sort(key=natural_keys)
    completed_chunks = [ f for f in files if '.part' not in f ]
    return completed_chunks[n]


def find_relevant_resumable_dir(project_dir, filename, upload_id, res_db=None, user=None):
    """
    If the client provides an upload_id, then the exact folder is returned.
    If no upload_id is provided, e.g. when the upload_id is lost, then
    the server will try to find a match, based on the filename, returning
    the most recent entry.

    Returns
    -------
    str, upload_id (name of the directory)

    """
    relevant = None
    potential_resumables = Resumable.db_get_all_resumable_ids_for_user(res_db, user)
    if not upload_id:
        logging.info('Trying to find a matching resumable for %s', filename)
        candidates = []
        for item in potential_resumables:
            pr = item[0]
            current_pr = '%s/%s' % (project_dir, pr)
            if _IS_VALID_UUID.match(pr) and os.path.lexists(current_pr):
                candidates.append((os.stat(current_pr).st_size, pr))
        candidates.sort(resumables_cmp)
        for cand in candidates:
            upload_id = cand[1]
            first_chunk = find_nth_chunk(project_dir, upload_id, filename, 1)
            if filename in first_chunk:
                relevant = cand[1]
                break
    else:
        for item in potential_resumables:
            pr = item[0]
            current_pr = '%s/%s' % (project_dir, pr)
            if _IS_VALID_UUID.match(pr) and str(upload_id) == str(pr):
                relevant = pr
    return relevant


def list_all_resumables(project_dir, res_db=None, user=None):
    potential_resumables = Resumable.db_get_all_resumable_ids_for_user(res_db, user)
    resumables = []
    info = []
    for item in potential_resumables:
        chunk_size = None
        pr = item[0]
        current_pr = '%s/%s' % (project_dir, pr)
        if _IS_VALID_UUID.match(pr):
            try:
                chunk_size, max_chunk, md5sum, \
                    previous_offset, next_offset, \
                    warning, recommendation, \
                    filename = get_resumable_chunk_info(current_pr, project_dir, res_db=res_db)
                if recommendation == 'end':
                    next_offset = 'end'
            except (OSError, Exception):
                pass
            if chunk_size:
                group = Resumable.db_get_group(res_db, pr)
                info.append({'chunk_size': chunk_size, 'max_chunk': max_chunk,
                             'md5sum': md5sum, 'previous_offset': previous_offset,
                             'next_offset': next_offset, 'id': pr,
                             'filename': filename, 'group': group})
    return {'resumables': info}


def repair_inconsistent_resumable(merged_file, chunks, merged_file_size,
                                  sum_chunks_size):
    """
    If the server process crashed after a chunk was uploaded,
    but while a merge was taking place, it is likey that
    the merged file will be smaller than the sum of the chunks.

    In that case, we try to re-merge the last chunk into the file
    and return the resumable info after that. If the merged file
    is _larger_ than the sum of the chunks, then a merge has taken
    place more than once, and it is best for the client to either
    end or delete the upload. If nothing can be done then the client
    is encouraged to end the upload.

    """
    logging.info('current merged file size: %d, current sum of chunks in db %d', merged_file_size, sum_chunks_size)
    if len(chunks) == 0:
        return False
    else:
        last_chunk = chunks[-1]
        last_chunk_size = os.stat(last_chunk).st_size
    if merged_file_size == sum_chunks_size:
        logging.info('server-side data consistent')
        return chunks
    try:
        warning = None
        recommendation = None
        diff = sum_chunks_size - merged_file_size
        if (merged_file_size < sum_chunks_size) and (diff <= last_chunk_size):
            target_size = sum_chunks_size - last_chunk_size
            with open(merged_file, 'ab') as f:
                f.truncate(target_size)
            with open(merged_file, 'ab') as fout:
                with open(last_chunk, 'rb') as fin:
                    shutil.copyfileobj(fin, fout)
            new_merged_size = os.stat(merged_file).st_size
            logging.info('merged file after repair: %d sum of chunks: %d', new_merged_size, sum_chunks_size)
            if new_merged_size == sum_chunks_size:
                return chunks, warning, recommendation
            else:
                raise Exception('could not repair data')
    except (Exception, OSError) as e:
        logging.error(e)
        return chunks, 'not sure what to do', 'end'


def get_resumable_chunk_info(resumable_dir, project_dir, res_db=None):
    """
    Get information needed to resume an upload.
    If the server-side data is inconsistent, then
    we try to fix it by successively dropping the last
    chunk and truncating the merged file.

    Returns
    -------
    tuple, (size, chunknum, md5sum, previous_offset, next_offset)

    """
    def info(chunks, recommendation=None, warning=None):
        num = int(chunks[-1].split('.')[-1])
        latest_size = bytes(chunks[-1])
        upload_id = os.path.basename(resumable_dir)
        next_offset = Resumable.db_get_total_size(res_db, upload_id)
        previous_offset = next_offset - latest_size
        filename = os.path.basename(chunks[-1].split('.chunk')[0])
        merged_file = os.path.normpath(project_dir + '/' + filename + '.' + upload_id)
        try:
            # check that the size of the merge file
            # matches what we calculate from the
            # chunks recorded in the resumable db
            assert bytes(merged_file) == next_offset
        except AssertionError:
            try:
                logging.info('trying to repair inconsistent data')
                chunks, wanring, recommendation = repair_inconsistent_resumable(merged_file,
                                                                        chunks, bytes(merged_file),
                                                                        next_offset)
                return info(chunks)
            except Exception as e:
                logging.error(e)
                return None, None, None, None, None, None, None, None
        return latest_size, num, md5sum(chunks[-1]), \
               previous_offset, next_offset, recommendation, \
               warning, filename
    def bytes(chunk):
        size = os.stat(chunk).st_size
        return size
    # may contain partial files, due to failed requests
    all_chunks = [ '%s/%s' % (resumable_dir, i) for i in os.listdir(resumable_dir) ]
    all_chunks.sort(key=natural_keys)
    chunks = [ c for c in all_chunks if '.part' not in c ]
    return info(chunks)


def get_resumable_info(project_dir, filename, upload_id, res_db=None, user=None):
    relevant_dir = find_relevant_resumable_dir(project_dir, filename, upload_id, res_db=res_db, user=user)
    if not relevant_dir:
        raise Exception('No resumable found for: %s', filename)
    resumable_dir = '%s/%s' % (project_dir, relevant_dir)
    chunk_size, max_chunk, md5sum, \
        previous_offset, next_offset, \
        warning, recommendation, filename = get_resumable_chunk_info(resumable_dir, project_dir, res_db=res_db)
    group = Resumable.db_get_group(res_db, upload_id)
    if recommendation == 'end':
        next_offset = 'end'
    info = {'filename': filename, 'id': relevant_dir,
            'chunk_size': chunk_size, 'max_chunk': max_chunk,
            'md5sum': md5sum, 'previous_offset': previous_offset,
            'next_offset': next_offset, 'warning': warning,
            'filename': filename, 'group': group}
    return info


def delete_resumable(project_dir, filename, upload_id, res_db=None, user=None):
    try:
        assert Resumable.db_upload_belongs_to_user(res_db, upload_id, user)
        relevant_dir = project_dir + '/' + upload_id
        relevant_merged_file = project_dir + '/' + filename + '.' + upload_id
        shutil.rmtree(relevant_dir)
        os.remove(relevant_merged_file)
        assert Resumable.db_remove_completed_for_user(res_db, upload_id, user)
        return True
    except Exception as e:
        logging.error(e)
        logging.error('could not complete resumable deletion')
        return False


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

