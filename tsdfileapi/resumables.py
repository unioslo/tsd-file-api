
import re
import logging
import os
import shutil
import uuid
import stat

from abc import ABC, abstractmethod

from db import session_scope, sqlite_init
from utils import md5sum

_IS_VALID_UUID = re.compile(r'([a-f\d0-9-]{32,36})')
_RW______ = stat.S_IREAD | stat.S_IWRITE

def _atoi(text):
    return int(text) if text.isdigit() else text


def _natural_keys(text):
    """
    alist.sort(key=_natural_keys) sorts in human order
    http://nedbatchelder.com/blog/200712/human_sorting.html
    """
    return [ _atoi(c) for c in re.split(r'(\d+)', text) ]


def _resumables_cmp(a, b):
    a_time = a[0]
    b_time = b[0]
    if a_time > b_time:
        return -1
    elif a_time < b_time:
        return 1
    else:
        return 1


class AbstractResumable(ABC):

    def __init__(self, work_dir=None, owner=None):
        super(AbstractResumable, self).__init__()
        self.work_dir = work_dir
        self.owner = owner

    @abstractmethod
    def prepare(self, work_dir, in_filename, url_chunk_num, url_upload_id, url_group, owner):
        pass

    @abstractmethod
    def open_file(self, filename, mode):
        pass

    @abstractmethod
    def add_chunk(self, fd, chunk):
        pass

    @abstractmethod
    def close_file(self, filename):
        pass

    @abstractmethod
    def merge_chunk(self, work_dir, last_chunk_filename, upload_id, owner):
        pass

    @abstractmethod
    def finalise(self, work_dir, last_chunk_filename, upload_id, owner):
        pass

    @abstractmethod
    def list_all(self, work_dir, owner):
        pass

    @abstractmethod
    def info(self, work_dir, filename, upload_id, owner):
        pass

    @abstractmethod
    def delete(self, work_dir, filename, upload_id, owner):
        pass


class Resumable(AbstractResumable):

    """
    Class for creating files in a piecemeal fashion,
    useful for resumable uploads, for example.

    The following public methods are exposed:

        a) for creating files incrementally:

            prepare
            open_file
            add_chunk
            close_file
            merge_chunk
            finalise

        b) for managing files which are still being finalised:

            list_all
            info
            delete

    """

    def __init__(self, work_dir=None, owner=None):
        super(Resumable, self).__init__(work_dir, owner)
        self.work_dir = work_dir
        self.owner = owner

    def _init_db(self, owner, work_dir):
        dbname = '{0}{1}{2}'.format('.resumables-', owner, '.db')
        rdb = sqlite_init(work_dir, name=dbname)
        os.chmod('{0}/{1}'.format(work_dir, dbname), _RW______)
        return rdb

    def prepare(self, work_dir, in_filename, url_chunk_num, url_upload_id, url_group, owner):
        """
        The following cases are handled:

        1. First chunk
            - check that the chunk has not already been uploaded
            - a new upload id is generated
            - the upload id is recorded as beloning to the authenticated owner
            - a new working directory is created
            - set completed_resumable_file to None

        2. Rest of the chunks
            - ensure monotonically increasing chunk order
            - set completed_resumable_file to None

        3. End request
            - set completed_resumable_file to True

        In all cases the function returns:
        upload_id/filename.extention.chunk.num

        """
        chunk_num = int(url_chunk_num) if url_chunk_num != 'end' else url_chunk_num
        upload_id = str(uuid.uuid4()) if url_upload_id == 'None' else url_upload_id
        chunk_filename = in_filename + '.chunk.' + url_chunk_num
        filename = upload_id + '/' + chunk_filename
        res_db = self._init_db(owner, work_dir)
        if chunk_num == 'end':
            completed_resumable_file = True
            chunk_order_correct = True
        elif chunk_num == 1:
            os.makedirs(work_dir + '/' + upload_id)
            assert self._db_insert_new_for_owner(res_db, upload_id, url_group)
            chunk_order_correct = True
            completed_resumable_file = None
        elif chunk_num > 1:
            chunk_order_correct = self._refuse_upload_if_not_in_sequential_order(work_dir, upload_id, chunk_num)
            completed_resumable_file = None
        return chunk_num, upload_id, completed_resumable_file, chunk_order_correct, filename

    def open_file(self, filename, mode):
        fd = open(filename, mode)
        os.chmod(filename, _RW______)
        return fd

    def add_chunk(self, fd, chunk):
        if not fd:
            return
        else:
            fd.write(chunk)

    def close_file(self, fd):
        fd.close()

    def _refuse_upload_if_not_in_sequential_order(self, work_dir, upload_id, chunk_num):
        chunk_order_correct = True
        full_chunks_on_disk = self._get_full_chunks_on_disk(work_dir, upload_id, chunk_num)
        previous_chunk_num = int(full_chunks_on_disk[-1].split('.chunk.')[-1])
        if chunk_num <= previous_chunk_num or (chunk_num - previous_chunk_num) >= 2:
            chunk_order_correct = False
            logging.error('chunks must be uploaded in sequential order')
        return chunk_order_correct

    def _find_nth_chunk(self, work_dir, upload_id, filename, n):
        n = n - 1 # chunk numbers start at 1, but keep 0-based for the signaure
        current_resumable = '%s/%s' % (work_dir, upload_id)
        files = os.listdir(current_resumable)
        files.sort(key=_natural_keys)
        completed_chunks = [ f for f in files if '.part' not in f ]
        return completed_chunks[n]

    def _find_relevant_resumable_dir(self, work_dir, filename, upload_id, res_db):
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
        potential_resumables = self._db_get_all_resumable_ids_for_owner(res_db)
        if not upload_id:
            logging.info('Trying to find a matching resumable for %s', filename)
            candidates = []
            for item in potential_resumables:
                pr = item[0]
                current_pr = '%s/%s' % (work_dir, pr)
                if _IS_VALID_UUID.match(pr) and os.path.lexists(current_pr):
                    candidates.append((os.stat(current_pr).st_size, pr))
            candidates.sort(_resumables_cmp)
            for cand in candidates:
                upload_id = cand[1]
                first_chunk = self._find_nth_chunk(work_dir, upload_id, filename, 1)
                if filename in first_chunk:
                    relevant = cand[1]
                    break
        else:
            for item in potential_resumables:
                pr = item[0]
                current_pr = '%s/%s' % (work_dir, pr)
                if _IS_VALID_UUID.match(pr) and str(upload_id) == str(pr):
                    relevant = pr
        return relevant


    def list_all(self, work_dir, owner):
        res_db = self._init_db(owner, work_dir)
        potential_resumables = self._db_get_all_resumable_ids_for_owner(res_db)
        resumables = []
        info = []
        for item in potential_resumables:
            chunk_size = None
            pr = item[0]
            current_pr = '%s/%s' % (work_dir, pr)
            if _IS_VALID_UUID.match(pr):
                try:
                    chunk_size, max_chunk, md5sum, \
                        previous_offset, next_offset, \
                        warning, recommendation, \
                        filename = self._get_resumable_chunk_info(current_pr, work_dir, res_db=res_db)
                    if recommendation == 'end':
                        next_offset = 'end'
                except (OSError, Exception):
                    pass
                if chunk_size:
                    group = self._db_get_group(res_db, pr)
                    info.append({'chunk_size': chunk_size, 'max_chunk': max_chunk,
                                 'md5sum': md5sum, 'previous_offset': previous_offset,
                                 'next_offset': next_offset, 'id': pr,
                                 'filename': filename, 'group': group})
        return {'resumables': info}

    def _repair_inconsistent_resumable(self, merged_file, chunks, merged_file_size,
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


    def _get_resumable_chunk_info(self, resumable_dir, work_dir, res_db=None):
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
            next_offset = self._db_get_total_size(res_db, upload_id)
            previous_offset = next_offset - latest_size
            filename = os.path.basename(chunks[-1].split('.chunk')[0])
            merged_file = os.path.normpath(work_dir + '/' + filename + '.' + upload_id)
            try:
                # check that the size of the merge file
                # matches what we calculate from the
                # chunks recorded in the resumable db
                assert bytes(merged_file) == next_offset
            except AssertionError:
                try:
                    logging.info('trying to repair inconsistent data')
                    chunks, wanring, recommendation = self._repair_inconsistent_resumable(merged_file,
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
        all_chunks.sort(key=_natural_keys)
        chunks = [ c for c in all_chunks if '.part' not in c ]
        return info(chunks)


    def info(self, work_dir, filename, upload_id, owner):
        res_db = self._init_db(owner, work_dir)
        relevant_dir = self._find_relevant_resumable_dir(work_dir, filename, upload_id, res_db)
        if not relevant_dir:
            raise Exception('No resumable found for: %s', filename)
        resumable_dir = '%s/%s' % (work_dir, relevant_dir)
        chunk_size, max_chunk, md5sum, \
            previous_offset, next_offset, \
            warning, recommendation, filename = self._get_resumable_chunk_info(resumable_dir, work_dir, res_db=res_db)
        group = self._db_get_group(res_db, upload_id)
        if recommendation == 'end':
            next_offset = 'end'
        info = {'filename': filename, 'id': relevant_dir,
                'chunk_size': chunk_size, 'max_chunk': max_chunk,
                'md5sum': md5sum, 'previous_offset': previous_offset,
                'next_offset': next_offset, 'warning': warning,
                'filename': filename, 'group': group}
        return info

    def _get_full_chunks_on_disk(self, work_dir, upload_id, chunk_num):
        chunks_on_disk = os.listdir(work_dir + '/' + upload_id)
        chunks_on_disk.sort(key=_natural_keys)
        full_chunks_on_disk = [ c for c in chunks_on_disk if '.part' not in c ]
        return full_chunks_on_disk

    def delete(self, work_dir, filename, upload_id, owner):
        try:
            res_db = self._init_db(owner, work_dir)
            assert self._db_upload_belongs_to_owner(res_db, upload_id)
            relevant_dir = work_dir + '/' + upload_id
            relevant_merged_file = work_dir + '/' + filename + '.' + upload_id
            shutil.rmtree(relevant_dir)
            os.remove(relevant_merged_file)
            assert self._db_remove_completed_for_owner(res_db, upload_id)
            return True
        except Exception as e:
            logging.error(e)
            logging.error('could not complete resumable deletion')
            return False

    def finalise(self, work_dir, last_chunk_filename, upload_id, owner):
        assert '.part' not in last_chunk_filename
        filename = os.path.basename(last_chunk_filename.split('.chunk')[0])
        out = os.path.normpath(work_dir + '/' + filename + '.' + upload_id)
        final = out.replace('.' + upload_id, '')
        chunks_dir = work_dir + '/' + upload_id
        if '.chunk.end' in last_chunk_filename:
            logging.info('deleting: %s', chunks_dir)
            os.rename(out, final)
            try:
                shutil.rmtree(chunks_dir) # do not need to fail upload if this does not work
            except OSError as e:
                logging.error(e)
            res_db = self._init_db(owner, work_dir)
            assert self._db_remove_completed_for_owner(res_db, upload_id)
        else:
            logging.error('finalise called on non-end chunk')
        return final

    def merge_chunk(self, work_dir, last_chunk_filename, upload_id, owner):
        """
        Merge chunks into one file, _in order_.

        Sequence
        --------
        1. Check that the chunk is not partial
        2. If last request
            - remove any remaining chunks, and the working directory
            - continue to the chowner: move file, set permissions
        3. If new chunk
            - if chunk_num > 1, create a lockfile - link to a unique file (NFS-safe method)
            - append it to the merge file
            - remove chunks older than 5 requests back in the sequence
              to avoid using lots of disk space for very large files
            - update the resumable's info table
        4. If a merge fails
            - remove the chunk
            - reset the file to its prior size
            - end the request
        5. Finally
            - unlink any existing lock

        Note
        ----
        This will produce bizarre files if clients send chunks out of order,
        which rules out multi-threaded senders. That can be supported by delaying
        the merge until the final request. Until a feature request arrives,
        it remain unimplemented.

        """
        assert '.part' not in last_chunk_filename
        filename = os.path.basename(last_chunk_filename.split('.chunk')[0])
        out = os.path.normpath(work_dir + '/' + filename + '.' + upload_id)
        out_lock = out + '.lock'
        final = out.replace('.' + upload_id, '')
        chunks_dir = work_dir + '/' + upload_id
        chunk_num = int(last_chunk_filename.split('.chunk.')[-1])
        chunk = chunks_dir + '/' + last_chunk_filename
        try:
            if chunk_num > 1:
                os.link(out, out_lock)
            with open(out, 'ab') as fout:
                with open(chunk, 'rb') as fin:
                    size_before_merge = os.stat(out).st_size
                    shutil.copyfileobj(fin, fout)
            chunk_size = os.stat(chunk).st_size
            res_db = self._init_db(owner, work_dir)
            assert self._db_update_with_chunk_info(res_db, upload_id, chunk_num, chunk_size)
        except Exception as e:
            logging.error(e)
            try:
                os.remove(chunk)
                with open(out, 'ab') as fout:
                    fout.truncate(size_before_merge)
            except (Exception, OSError) as e:
                raise Exception('could not merge %s', chunk)
        finally:
            try:
                os.unlink(out_lock)
            except OSError:
                pass
        if chunk_num >= 5:
            target_chunk_num = chunk_num - 4
            old_chunk = chunk.replace('.chunk.' + str(chunk_num), '.chunk.' + str(target_chunk_num))
            os.remove(old_chunk)
        return final

    def _db_insert_new_for_owner(self, engine, resumable_id, group):
        resumable_table = 'resumable_%s' % resumable_id
        with session_scope(engine) as session:
            session.execute('create table if not exists resumable_uploads(id text, upload_group text)')
            session.execute('insert into resumable_uploads (id, upload_group) values (:resumable_id, :upload_group)',
                            {'resumable_id': resumable_id, 'upload_group': group})
            session.execute('create table "%s"(chunk_num int, chunk_size int)' % resumable_table) # want an exception if exists
        return True

    def _db_update_with_chunk_info(self, engine, resumable_id, chunk_num, chunk_size):
        resumable_table = 'resumable_%s' % resumable_id
        with session_scope(engine) as session:
            session.execute('insert into "%s"(chunk_num, chunk_size) values (:chunk_num, :chunk_size)' % resumable_table,
                            {'chunk_num': chunk_num, 'chunk_size': chunk_size})
        return True

    def _db_pop_chunk(self, engine, resumable_id, chunk_num):
        resumable_table = 'resumable_%s' % resumable_id
        with session_scope(engine) as session:
            res = session.execute('delete from "%s" where chunk_num = :chunk_num' % resumable_table,
                                  {'chunk_num': chunk_num})
        return True

    def _db_get_total_size(self, engine, resumable_id):
        resumable_table = 'resumable_%s' % resumable_id
        with session_scope(engine) as session:
            res = session.execute('select sum(chunk_size) from "%s"' % resumable_table).fetchone()[0]
        return res

    def _db_get_group(self, engine, resumable_id):
        resumable_table = 'resumable_%s' % resumable_id
        with session_scope(engine) as session:
            res = session.execute('select upload_group from resumable_uploads where id = :resumable_id',
                                  {'resumable_id': resumable_id}).fetchone()[0]
        return res

    def _db_upload_belongs_to_owner(self, engine, resumable_id):
        with session_scope(engine) as session:
            res = session.execute('select count(1) from resumable_uploads where id = :resumable_id',
                                  {'resumable_id': resumable_id}).fetchone()[0]
        return True if res > 0 else False

    def _db_get_all_resumable_ids_for_owner(self, engine):
        try:
            with session_scope(engine) as session:
                res = session.execute('select id from resumable_uploads').fetchall()
        except Exception:
            return []
        return res # [(id,), (id,)]

    def _db_remove_completed_for_owner(self, engine, resumable_id):
        resumable_table = 'resumable_%s' % resumable_id
        with session_scope(engine) as session:
            session.execute('delete from resumable_uploads where id = :resumable_id',
                            {'resumable_id': resumable_id})
            session.execute('drop table "%s"' % resumable_table)
        return True

