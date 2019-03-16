
"""API for uploading files and data streams to TSD."""

# tornado RequestHandler classes are simple enough to grok
# pylint: disable=attribute-defined-outside-init
# pylint tends to be too pedantic regarding docstrings - we can decide in code review
# pylint: disable=missing-docstring

import base64
import logging
import os
import pwd
import datetime
import hashlib
import subprocess
import stat
import shutil
import fileinput

from uuid import uuid4
from sys import argv
from collections import OrderedDict

import yaml
import magic
import tornado.queues
from tornado.escape import json_decode, url_unescape
from tornado import gen
from tornado.httpclient import AsyncHTTPClient
from tornado.ioloop import IOLoop
from tornado.options import parse_command_line, define, options
from tornado.web import Application, RequestHandler, stream_request_body, \
                        HTTPError, MissingArgumentError

# pylint: disable=relative-import
from auth import verify_json_web_token
from utils import secure_filename, project_import_dir, project_sns_dir, \
                  IS_VALID_GROUPNAME, check_filename, _IS_VALID_UUID, \
                  md5sum
from db import insert_into, create_table_from_codebook, sqlite_init, \
               create_table_from_generic, _table_name_from_form_id, \
               _VALID_PNUM, _table_name_from_table_name, TableNameException, \
               load_jwk_store
from pgp import decrypt_pgp_json, _import_keys


_RW______ = stat.S_IREAD | stat.S_IWRITE
_RW_RW___ = stat.S_IREAD | stat.S_IWRITE | stat.S_IRGRP | stat.S_IWGRP


def read_config(filename):
    with open(filename) as f:
        conf = yaml.load(f)
    return conf


try:
    CONFIG_FILE = argv[1]
    CONFIG = read_config(CONFIG_FILE)
except Exception as e:
    logging.error(e)
    raise e


define('port', default=CONFIG['port'])
define('debug', default=CONFIG['debug'])
define('server_delay', default=CONFIG['server_delay'])
define('num_chunks', default=CONFIG['num_chunks'])
define('max_body_size', CONFIG['max_body_size'])
define('user_authorization', default=CONFIG['user_authorization'])
define('api_user', CONFIG['api_user'])
define('uploads_folder', CONFIG['uploads_folder'])
define('sns_uploads_folder', CONFIG['sns_uploads_folder'])
define('secret_store', load_jwk_store(CONFIG))
define('set_owner', CONFIG['set_owner'])
define('chowner_path', CONFIG['chowner_path'])


class AuthRequestHandler(RequestHandler):

    def validate_token(self, roles_allowed=None):
        """
        Token validation is about authorization. Clients and/or users authenticate
        themselves with the auth-api to obtain tokens. When performing requests
        against the file-api these tokens are presented in the Authorization header
        of the HTTP request as a Bearer token.

        Before the body of each request is processed this method is called in 'prepare'.
        The caller passes a list of roles that should be authorized to perform the HTTP
        request(s) in the request handler.

        The verify_json_web_token method will check whether the authenticated client/user
        belongs to a role that is authorized to perform the request. If not, the request
        will be terminated with 401 not authorized. Otherwise it will continue.

        For more details about the full authorization check the docstring of
        verify_json_web_token.

        Parameters
        ----------
        roles_allowed: list
            should contain the names of the roles that are allowed to
            perform the operation on the resource.

        Returns
        -------
        bool or dict

        """
        self.status = None
        try:
            try:
                assert roles_allowed
            except AssertionError as e:
                logging.error(e)
                logging.error('No roles specified, cannot do authorization')
                self.set_status(500)
                raise Exception('Authorization not possible: caller must specify roles')
            try:
                auth_header = self.request.headers['Authorization']
            except (KeyError, UnboundLocalError) as e:
                self.message = 'Missing authorization header'
                logging.error(self.message)
                self.set_status(400)
                raise Exception('Authorization not possible: missing header')
            try:
                self.jwt = auth_header.split(' ')[1]
            except IndexError as e:
                self.message = 'Malformed authorization header'
                logging.error(self.message)
                self.set_status(400)
                raise Exception('Authorization not possible: malformed header')
            try:
                if not CONFIG['use_secret_store']:
                    project_specific_secret = options.secret
                else:
                    try:
                        pnum = self.request.uri.split('/')[1]
                        assert _VALID_PNUM.match(pnum)
                        self.pnum = pnum
                    except AssertionError as e:
                        logging.error(e.message)
                        logging.error('pnum invalid')
                        self.set_status(400)
                        raise e
                    project_specific_secret = options.secret_store[pnum]
            except Exception as e:
                logging.error(e)
                logging.error('Could not get project specific secret key for JWT validation')
                self.set_status(500)
                raise Exception('Authorization not possible: server error')
            try:
                authnz = verify_json_web_token(auth_header, project_specific_secret,
                                                              roles_allowed, pnum)
                self.claims = authnz['claims']
                self.user = self.claims['user']
                if not authnz['status']:
                    self.set_status(401)
                    raise Exception('JWT verification failed')
                elif authnz['status']:
                    return authnz
            except Exception as e:
                self.message = authnz['reason']
                logging.error(e)
                self.set_status(401)
                raise Exception('Authorization failed')
        except Exception as e:
            if not self.status:
                self.set_status(401)
            raise Exception


class FileStreamerHandler(AuthRequestHandler):

    """List the export directory, or serve files from it."""

    CHUNK_SIZE = CONFIG['export_chunk_size']


    def enforce_export_policy(self, policy_config, filename):
        """
        Check file to ensure it meets the requirements of the export policy

        Checks
        ------
        1. file name follows conventions
        2. file size does not exceed max allowed for export
        3. checks that MIME types conform to allowed types, if policy enabled

        Returns
        -------
        (bool, <str,None>, <int,None>),
        (is_conformant, mime-type, size)

        """
        try:
            check_filename(os.path.basename(filename))
        except Exception as e:
            logging.error(e)
            self.message = 'Illegal export filename: %s' % filename
            logging.error(self.message)
            return False, None, None
        subprocess.call(['sudo', 'chmod', 'go+r', filename])
        with magic.Magic(flags=magic.MAGIC_MIME_TYPE) as m:
            mime_type = m.id_filename(filename)
        size = os.path.getsize(self.path)
        if size > CONFIG['export_max_size']:
            logging.error('%s tried to export a file exceeding the maximum size limit', self.user)
            maxsize = CONFIG['export_max_size'] / 1024 / 1024 / 1024
            self.message = 'File size exceeds maximum allowed: %d Gigabyte, create a zip archive, or use the s3 API' % maxsize
            return False, mime_type, size
        if not policy_config['enabled']:
            return True, mime_type, size
        if mime_type in policy_config['allowed_mime_types']:
            return True, mime_type, size
        else:
            self.message = 'not allowed to export file with MIME type: %s' % mime_type
            logging.error(self.message)
            return False, mime_type, size


    def list_files(self, path):
        """
        Lists files in the export directory.

        Returns
        -------
        dict,
        {
            'filename': <name>,
            'modified_date': <mtime>,
            'href': <url reference to resource>,
            'exportable': <bool, indication of whether file is exportible>,
            'reason': <str, explanation of exporable>
        }

        """
        files = os.listdir(path)
        if len(files) > CONFIG['export_max_num_list']:
            self.set_status(400)
            self.message = 'too many files, create a zip archive'
            raise Exception
        times = []
        exportable = []
        reasons = []
        sizes = []
        for file in files:
            filepath = os.path.normpath(path + '/' + file)
            latest = os.stat(filepath).st_mtime
            date_time = str(datetime.datetime.fromtimestamp(latest).isoformat())
            times.append(date_time)
            try:
                status, _, size = self.enforce_export_policy(CONFIG['export_policy'], filepath)
                if status:
                    reason = None
                else:
                    reason = self.message
            except Exception as e:
                logging.error(e)
                logging.error('could not enforce export policy when listing dir')
                raise Exception
            exportable.append(status)
            reasons.append(reason)
            sizes.append(size)
        file_info = []
        for f, t, e, r, s in zip(files, times, exportable, reasons, sizes):
            href = '%s/%s' % (self.request.uri, f)
            file_info.append({'filename': f,
                              'size': s,
                              'modified_date': t,
                              'href': href,
                              'exportable': e,
                              'reason': r})
        logging.info('%s listed %s', self.user, path)
        self.write({'files': file_info})


    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self, pnum, filename=None):
        """
        List the export dir, or serve a file, asynchronously.

        1. check token claims
        2. check the pnum

        If listing the dir:

        3. run the list_files method

        If serving a file:

        3. check the filename
        4. check that file exists
        5. enforce the export policy
        6. set the mime type
        7. serve the file

        """
        self.message = 'Unknown error, please contact TSD'
        try:
            try:
                self.authnz = self.validate_token(roles_allowed=['export_user', 'admin_user'])
                self.user = self.authnz['claims']['user']
            except Exception:
                if not self.message:
                    self.message = 'Not authorized to export data'
                self.set_status(401)
                raise Exception
            assert _VALID_PNUM.match(pnum)
            self.path = CONFIG['export_path'].replace('pXX', pnum)
            if not filename:
                self.list_files(self.path)
                return
            try:
                secured_filename = check_filename(url_unescape(filename))
            except Exception as e:
                logging.error(e)
                logging.error('%s tried to access files in sub-directories', self.user)
                self.set_status(403)
                self.message = 'Not allowed to access files in sub-directories, create a zip archive'
                raise Exception
            self.filepath = '%s/%s' % (self.path, secured_filename)
            if not os.path.lexists(self.filepath):
                logging.error('%s tried to access a file that does not exist', self.user)
                self.set_status(404)
                self.message = 'File does not exist'
                raise Exception
            status, mime_type, size = self.enforce_export_policy(CONFIG['export_policy'], self.filepath)
            assert status
            self.set_header('Content-Type', mime_type)
            # TODO: send the file size
            #self.set_header('Content-Length', size)
            self.flush()
            fd = open(self.filepath, "rb")
            data = fd.read(self.CHUNK_SIZE)
            while data:
                self.write(data)
                yield tornado.gen.Task(self.flush)
                data = fd.read(self.CHUNK_SIZE)
            fd.close()
            logging.info('user: %s, exported file: %s , with MIME type: %s', self.user, self.filepath, mime_type)
        except Exception as e:
            logging.error(self.message)
            self.write({'message': self.message})
        finally:
            try:
                fd.close()
            except (OSError, UnboundLocalError) as e:
                pass
            self.finish()


class GenericFormDataHandler(AuthRequestHandler):

    def prepare(self):
        try:
            self.authnz = self.validate_token(roles_allowed=['import_user', 'export_user', 'admin_user'])
            if not self.authnz:
                self.set_status(401)
                raise Exception
            if not self.request.files['file']:
                logging.error('No file(s) supplied with upload request')
                self.set_status(400)
                raise Exception
        except Exception as e:
            if self._status_code != 401:
                self.set_status(400)
            self.finish({'message': 'request failed'})

    def write_files(self,
                    filemode,
                    pnum,
                    uploads_folder=options.uploads_folder,
                    folder_func=project_import_dir,
                    keyid=None,
                    formid=None,
                    copy_to_hidden_tsd_subfolder=False):
        try:
            for i in range(len(self.request.files['file'])):
                filename = secure_filename(self.request.files['file'][i]['filename'])
                filebody = self.request.files['file'][i]['body']
                if len(filebody) == 0:
                    logging.error('Trying to upload an empty file: %s - not allowed, since nonsensical', filename)
                    raise Exception('EmptyFileBodyError')
                # add all optional parameters to file writer
                # this is used for nettskjema specific backend
                written = self.write_file(filemode, filename, filebody, pnum,
                                uploads_folder, folder_func, keyid, formid,
                                copy_to_hidden_tsd_subfolder)
                assert written
            return True
        except Exception as e:
            logging.error(e)
            logging.error('Could not process files')
            return False


    def write_file(self,
                   filemode,
                   filename,
                   filebody,
                   pnum,
                   uploads_folder=options.uploads_folder,
                   folder_func=project_import_dir,
                   keyid=None,
                   formid=None,
                   copy_to_hidden_tsd_subfolder=False):
        try:
            project_dir = folder_func(uploads_folder, pnum, keyid, formid)
            self.path = os.path.normpath(project_dir + '/' + filename)
            # add the partial file indicator, check existence
            self.path_part = self.path + '.' + str(uuid4()) + '.part'
            if os.path.lexists(self.path_part):
                logging.error('trying to write to partial file - killing request')
                raise Exception
            if os.path.lexists(self.path):
                logging.info('%s already exists, renaming to %s', self.path, self.path_part)
                os.rename(self.path, self.path_part)
                assert os.path.lexists(self.path_part)
                assert not os.path.lexists(self.path)
            self.path, self.path_part = self.path_part, self.path
            with open(self.path, filemode) as f:
                f.write(filebody)
                os.rename(self.path, self.path_part)
                os.chmod(self.path_part, _RW_RW___)
            if copy_to_hidden_tsd_subfolder:
                tsd_hidden_folder = folder_func(uploads_folder, pnum, keyid, formid,
                                                use_hidden_tsd_folder=True)
                subfolder_path = os.path.normpath(tsd_hidden_folder + '/' + filename)
                try:
                    shutil.copy(self.path_part, subfolder_path)
                    os.chmod(subfolder_path, _RW_RW___)
                except Exception as e:
                    logging.error(e)
                    logging.error('Could not copy file %s to .tsd folder', self.path_part)
                    return False
            return True
        except Exception as e:
            logging.error(e)
            logging.error('Could not write to file')
            return False


class FormDataHandler(GenericFormDataHandler):

    def handle_data(self, filemode, pnum):
        try:
            assert self.write_files(filemode, pnum)
            self.set_status(201)
            self.write({'message': 'data uploaded'})
        except Exception:
            self.set_status(400)
            self.write({'message': 'could not upload data'})

    # TODO: drop this
    def post(self, pnum):
        self.handle_data('ab+', pnum)

    # TODO: drop this
    def patch(self, pnum):
        self.handle_data('ab+', pnum)

    def put(self, pnum):
        self.handle_data('wb+', pnum)

    def head(self, pnum):
        self.set_status(201)


class SnsFormDataHandler(GenericFormDataHandler):

    """Used to upload nettskjema files to fx dir."""

    def handle_data(self, filemode, pnum, keyid, formid):
        try:
            assert self.write_files(filemode,
                         pnum,
                         uploads_folder=options.sns_uploads_folder,
                         folder_func=project_sns_dir,
                         keyid=keyid,
                         formid=formid,
                         copy_to_hidden_tsd_subfolder=True)
            self.set_status(201)
            self.write({'message': 'data uploaded'})
        except Exception:
            self.set_status(400)
            self.write({'message': 'could not upload data'})

    # TODO: drop this
    def post(self, pnum, keyid, formid):
        self.handle_data('ab+', pnum, keyid, formid)

    # TODO: drop this
    def patch(self, pnum, keyid, formid):
        self.handle_data('ab+', pnum, keyid, formid)

    def put(self, pnum, keyid, formid):
        self.handle_data('wb+', pnum, keyid, formid)

    def head(self, pnum, keyid, formid):
        self.set_status(201)


class ResumablesListHandler(AuthRequestHandler):

    """
    List information necessary to resume an upload.

    Implementation
    --------------
    To continue a resumable upload which has stopped, clients
    can get information about data stored by the server.

    This class provides a GET method, which returns the relevant
    information to the client, for a given upload_id, and/or file.

    This information is:

    - filename
    - sequence number of last chunk
    - chunk size
    - upload id
    - mdsum of the last chunk

    There are two possible scenarios: 1) the client knows the upload_id
    associated with the file which needs to be resumed, or 2) the client
    only knows the name of the file which needs to be resumed.

    Scenario 1
    ----------
    In scenario #1, the upload_id is provided, and the server returns
    the information.

    Scenario 2
    ----------
    In scenario #2, the server will look at all potential resumables,
    and try to find a match based on the filename. If there are multiple
    resumable uploads that could be associated with a given filename,
    the most recent one will be chosen.

    If a match has been found, the server will try to ensure that
    the chunk size is consistent across the chunks it currently has,
    by comparing the sizes of the last three chunks in the sequence
    (if there are at least 3).  It does this because it is possible
    that the latest chunk might be incomplete. If it cannot to determine
    a consistent size, then no resumable is reported for the file.

    Note: this match is probabilistic, but likely to be correct.
    The likelihood depends on the behaviour of project members.
    The only scenario under which the wrong match will be generated is
    as follows.

    A resumable upload is started, by person A containing with filename
    data.txt. The upload is stopped for some reason, and the client/person
    forgets the upload_id. In the meantime person B (belonging to the same
    TSD project) starts another resumable upload, with different data,
    but the file is also named data.txt. This upload is also stopped,
    and the client/person loses the upload_id.

    Now before person B can resume their upload, person A comes along
    and tries to resume the upload of their own data.txt. The server
    will not be able to find the correct match without the upload_id,
    so the wrong information will be returned. This likelihood is
    estimated to be very low.

    Mitigation of possible errors
    -----------------------------
    To mitigate the likelihood of the client mistakenly acting on the wrong
    resumable information, the server generates the md5 digest of the last
    chunk in the sequence, and returns this to the client. The client can
    then regenerate the chunk locally, compute its own digest, and compare
    it with the one sent by the server.

    There is yet another possibility of mistake here: if two different files
    with the same name generate the same md5 digest in their last chunk on
    the server. But that would also require that person 's and person B's
    uploads stopped at the point where the two files happen to be the same
    and that their chunk sizes would at that point lead to the same md5. This
    seems extremely unlikely.

    In conclusion, the extremely paranoid client implementor can simply require
    the upload_id for resume, if they deem the md5 verification alone is not good
    enough.

    """

    def resumables_cmp(self, a, b):
        a_time = a[0]
        b_time = b[0]
        if a_time > b_time:
            return -1
        elif a_time < b_time:
            return 1
        else:
            return 1


    def find_nth_chunk(self, project_dir, upload_id, filename, n):
        n = n - 1 # chunk numbers start at 1, but keep 0-based for the signaure
        current_resumable = '%s/%s' % (project_dir, upload_id)
        files = os.listdir(current_resumable)
        files.sort()
        return files[n]


    def find_relevant_resumable_dir(self, project_dir, filename, upload_id):
        """
        If the client provides an upload_id, then the exact folder is returned.
        If no upload_id is provided, e.g. when the upload_id is lost, then
        the server will try to find a match, based on the filename, returning
        the most recent entry.

        Returns
        -------
        str, upload_id (name of the directory)

        """
        potential_resumables = os.listdir(project_dir)
        if not upload_id:
            logging.info('Trying to find a matching resumable for %s', filename)
            candidates = []
            for pr in potential_resumables:
                current_pr = '%s/%s' % (project_dir, pr)
                if _IS_VALID_UUID.match(pr):
                    candidates.append((os.stat(current_pr).st_mtime, pr))
            candidates.sort(self.resumables_cmp)
            relevant = None
            for cand in candidates:
                upload_id = cand[1]
                first_chunk = self.find_nth_chunk(project_dir, upload_id, filename, 1)
                if filename in first_chunk:
                    relevant = cand[1]
                    break
        else:
            for pr in potential_resumables:
                current_pr = '%s/%s' % (project_dir, pr)
                if _IS_VALID_UUID.match(pr) and str(upload_id) == str(pr):
                    relevant = pr
        return relevant


    def get_resumable_chunk_info(self, resumable_dir):
        """
        Try to inspect at least 3 of the last chunks in the sequence.

        Returns
        -------
        tuple, (size, chunknum, md5sum, previous_offset, next_offset)

        """
        def info(chunk, size, n):
            previous_offset = n * size - size
            next_offset = n * size
            try:
                chunk_num_in_filename = int(chunk.split('.')[-1])
                assert chunk_num_in_filename == n
                assert '.part' not in chunk
            except AssertionError:
                raise Exception('Inconsistency between chunk filename, and computed relevant chunk')
            return size, n, md5sum(chunk), previous_offset, next_offset
        def bytes(chunk):
            size = os.stat(chunk).st_size
            return size
        def check_n(chunks, n):
            size1 = bytes(chunks[0])
            size2 = bytes(chunks[1])
            size3 = bytes(chunks[2])
            if size1 == size2 == size3:
                return info(chunks[2], size3, n)
            elif size2 == size1:
                return info(chunks[1], size2, n - 1)
            else:
                return info(chunks[0], size1, n - 2)
        chunks = [ '%s/%s' % (resumable_dir, i) for i in os.listdir(resumable_dir) ]
        chunks.sort()
        if len(chunks) == 1:
            size1 = bytes(chunks[0])
            return info(chunks[0], size1, 1)
        elif len(chunks) == 2:
            size1 = bytes(chunks[0])
            size2 = bytes(chunks[1])
            if size2 == size1:
                return info(chunks[1], size2, 2)
            else:
                return info(chunks[0], size1, 1)
        elif len(chunks) == 3:
            return check_n(chunks, 3)
        elif len(chunks) > 3:
            sample = chunks[-3:]
            return check_n(sample, len(chunks))


    def get_resumable_info(self, project_dir, filename, upload_id):
        relevant_dir = self.find_relevant_resumable_dir(project_dir, filename, upload_id)
        if not relevant_dir:
            raise Exception('No resumable found for: %s', filename)
        resumable_dir = '%s/%s' % (project_dir, relevant_dir)
        chunk_size, max_chunk, md5sum, previous_offset, next_offset = self.get_resumable_chunk_info(resumable_dir)
        info = {'filename': filename, 'id': relevant_dir,
                'chunk_size': chunk_size, 'max_chunk': max_chunk,
                'md5sum': md5sum, 'previous_offset': previous_offset,
                'next_offset': next_offset}
        return info


    def get(self, pnum, filename):
        self.message = {'filename': filename, 'id': None, 'chunk_size': None, 'max_chunk': None}
        upload_id = None
        try:
            try:
                self.authnz = self.validate_token(roles_allowed=['import_user', 'export_user', 'admin_user'])
            except Exception as e:
                logging.error('Not authorized to list resumable')
                self.message = {'message': 'Not authorized'}
                raise Exception('Not authorized')
            try:
                assert _VALID_PNUM.match(pnum)
                project_dir = project_import_dir(options.uploads_folder, pnum, None, None)
                secured_filename = check_filename(url_unescape(filename))
            except Exception:
                logging.error('not able to check for resumable due to bad input')
                raise Exception
            try:
                upload_id = url_unescape(self.get_query_argument('id'))
            except Exception:
                pass
            info = self.get_resumable_info(project_dir, secured_filename, upload_id)
            self.set_status(200)
            self.write(info)
        except Exception as e:
            logging.error(e)
            self.set_status(400)
            self.write(self.message)


@stream_request_body
class StreamHandler(AuthRequestHandler):

    #pylint: disable=line-too-long

    """
    Handles internal requests made from ProxyHandler.
    Does request data processing, file management, and writes data to disk.
    Calls the chowner to set ownership and rights.

    """

    def decrypt_aes_key(self, b64encoded_pgpencrypted_key):
        gpg = _import_keys(CONFIG)
        key = base64.b64decode(b64encoded_pgpencrypted_key)
        decr_aes_key = str(gpg.decrypt(key)).strip()
        return decr_aes_key


    def start_openssl_proc(self, output_file=None, base64=True):
        cmd = ['openssl', 'enc', '-aes-256-cbc', '-d'] + self.aes_decryption_args_from_headers()
        if output_file is not None:
            cmd = cmd + ['-out', output_file]
        if base64:
            cmd = cmd + ['-a']
        return subprocess.Popen(cmd,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE if output_file is None else None)


    def aes_decryption_args_from_headers(self):
        decr_aes_key = self.decrypt_aes_key(self.request.headers['Aes-Key'])
        if "Aes-Iv" in self.request.headers:
            return ['-iv', self.request.headers["Aes-Iv"], '-K', decr_aes_key]
        else:
            return ['-pass', 'pass:%s' % decr_aes_key]


    def handle_aes(self, content_type):
        self.custom_content_type = content_type
        self.proc = self.start_openssl_proc(output_file=self.path)


    def handle_aes_octet_stream(self, content_type):
        self.custom_content_type = 'application/aes'
        self.proc = self.start_openssl_proc(output_file=self.path, base64=False)


    def handle_tar(self, content_type, project_dir):
        if 'gz' in content_type:
            tarflags = '-xzf'
        else:
            tarflags = '-xf'
        self.custom_content_type = content_type
        self.proc = subprocess.Popen(['tar', '-C', project_dir, tarflags, '-'],
                                      stdin=subprocess.PIPE)


    def handle_tar_aes(self, content_type, project_dir):
        if 'gz' in content_type:
            tarflags = '-xzf'
        else:
            tarflags = '-xf'
        self.custom_content_type = content_type
        self.openssl_proc = self.start_openssl_proc()
        logging.info('started openssl process')
        self.tar_proc = subprocess.Popen(['tar', '-C', project_dir, tarflags, '-'],
                                 stdin=self.openssl_proc.stdout)


    def handle_gz(self, content_type, filemode):
        self.custom_content_type = content_type
        self.target_file = open(self.path, filemode)
        self.gunzip_proc = subprocess.Popen(['gunzip', '-c', '-'],
                                             stdin=subprocess.PIPE,
                                             stdout=self.target_file)


    def handle_gz_aes(self, content_type, filemode):
        self.custom_content_type = content_type
        self.target_file = open(self.path, filemode)
        self.openssl_proc = self.start_openssl_proc()
        self.gunzip_proc = subprocess.Popen(['gunzip', '-c', '-'],
                                             stdin=self.openssl_proc.stdout,
                                             stdout=self.target_file)


    def merge_resumables(self, project_dir, last_chunk_filename, upload_id):
        """
        Merge chunks into one file.

        There is a subtle trade-off between disk-usage efficiency
        and resumable upload reliability. If we do not perform incremental
        merging, then there will be a moment where the uploaded file
        occupies twice its final size on disk. For large files this
        may have a significant impact on disk quotas. The advantage of
        this is, however, that if the last request in the sequence fails
        while the merge is taking place, we still have all the chunked
        data. If the client needed to restart the final merge instruction
        then we would simply restart the merge from chunk1, and over-write
        whatever had been accumulated before. The over-write semantics
        guarantees that the merged file will be correct, and it is simple
        to implement.

        On the other hand it is possible to perform an incremental merge, in
        which chunks are removed from disk, as they are being merged into
        the final file. In the scenario where the request drops while the
        merge is taking place, preserving the ability to restart the merge
        and end up with correct data is more difficult. The reason it is
        more difficult is that the request might fail in the middle of reading
        and writing a chunk to the merged file. So that partially merged
        chunk would remain on disk, in its entirety when the request fails.
        One could then try to accumulate the merged file in append-mode,
        to be able to restart the merge, as it were, but to do that
        correctly in this regard, we should not start reading the last chunk
        from line 1, but from the exact point where the cursor was in the file
        when the merge request failed. To do this correctly we need a rollback
        function if an incremental merge fails, which tells the client to try
        again, and keep server-side data consistent.

        Either way, both non-inplace, and inplace methods have the same memory
        footprint, so the tradeoff here is to use more disk to get better reliability.

        """
        merged_filename = last_chunk_filename.replace(upload_id + '/', '').replace('.chunk.end', '')
        out = os.path.normpath(project_dir + '/' + merged_filename)
        chunks_dir = project_dir + '/' + upload_id
        chunked_files = os.listdir(chunks_dir)
        chunks = map(lambda x: '%s/%s/%s' % (project_dir, upload_id, x), chunked_files)
        chunks.sort()
        with open(out, 'wb') as fout:
            for chunk in chunks:
                with open(chunk, 'rb') as fin:
                    shutil.copyfileobj(fin, fout)
        shutil.rmtree(chunks_dir)
        return out


    @gen.coroutine
    def prepare(self):
        try:
            self.call_chowner = True
            self.merged_file = False
            try:
                self.authnz = self.validate_token(roles_allowed=['import_user', 'export_user', 'admin_user'])
            except Exception as e:
                logging.error(e)
                raise Exception
            try:
                pnum = self.request.uri.split('/')[1]
                try:
                    assert _VALID_PNUM.match(pnum)
                except AssertionError as e:
                    logging.error('URI does not contain a valid pnum')
                    raise e
                try:
                    self.group_name = url_unescape(self.get_query_argument('group'))
                except Exception:
                    self.group_name = pnum + '-member-group'
                if self.request.method == 'POST':
                    filemode = 'ab+'
                elif self.request.method == 'PUT' or self.request.method == 'PATCH':
                    # even for PATCH, files writes are idempotent
                    # because we use that for resumable uploads
                    filemode = 'wb+'
                try:
                    content_type = self.request.headers['Content-Type']
                    project_dir = project_import_dir(options.uploads_folder, pnum, None, None)
                    # TODO: get this from URL instead
                    # build it ourselves in /stream handler
                    filename = secure_filename(self.request.headers['Filename'])
                    if self.request.method == 'PATCH':
                        chunk_num = url_unescape(self.get_query_argument('chunk'))
                        upload_id = url_unescape(self.get_query_argument('id'))
                        filename = filename + '.chunk.' + chunk_num
                        if chunk_num != 'end':
                            chunk_num = int(chunk_num)
                        if chunk_num == 'end':
                            self.chunk_num = 'end'
                            self.upload_id = upload_id
                            self.call_chowner = True
                            filename = self.upload_id + '/' + filename
                            self.merged_file = self.merge_resumables(project_dir, filename, self.upload_id)
                            self.target_file = None
                        elif chunk_num == 1:
                            self.chunk_num = 1
                            self.upload_id = str(uuid4())
                            self.call_chowner = False
                            filename = self.upload_id + '/' + filename
                            os.makedirs(project_dir + '/' + self.upload_id)
                        elif chunk_num > 1:
                            self.chunk_num = chunk_num
                            self.upload_id = upload_id
                            self.call_chowner = False
                            filename = self.upload_id + '/' + filename
                    self.path = os.path.normpath(project_dir + '/' + filename)
                    self.path_part = self.path + '.' + str(uuid4()) + '.part'
                    if os.path.lexists(self.path_part):
                        logging.error('trying to write to partial file - killing request')
                        raise Exception
                    if os.path.lexists(self.path):
                        if os.path.isdir(self.path):
                            logging.info('directory: %s already exists due to prior upload, removing', self.path)
                            shutil.rmtree(self.path)
                        else:
                            logging.info('%s already exists, renaming to %s', self.path, self.path_part)
                            os.rename(self.path, self.path_part)
                            assert os.path.lexists(self.path_part)
                            assert not os.path.lexists(self.path)
                    self.path, self.path_part = self.path_part, self.path
                    if content_type == 'application/aes':
                        self.handle_aes(content_type)
                    elif content_type == 'application/aes-octet-stream':
                        self.handle_aes_octet_stream(content_type)
                    elif content_type in ['application/tar', 'application/tar.gz']:
                        self.handle_tar(content_type, project_dir)
                    elif content_type in ['application/tar.aes', 'application/tar.gz.aes']:
                        self.handle_tar_aes(content_type, project_dir)
                    elif content_type == 'application/gz':
                        self.handle_gz(content_type, filemode)
                    elif content_type == 'application/gz.aes':
                        # seeing a non-determnistic failure here sometimes...
                        self.handle_gz_aes(content_type, filemode)
                    else:
                        self.custom_content_type = None
                        if not self.merged_file:
                            self.target_file = open(self.path, filemode)
                except KeyError:
                    logging.info('No content-type - do not know what to do with data')
            except Exception as e:
                logging.error(e)
                logging.error("filename not found")
                try:
                    self.target_file.close()
                    os.rename(self.path, self.path_part)
                except AttributeError as e:
                    logging.error(e)
                    logging.error('No file to close after all - so nothing to worry about')
        except Exception as e:
            logging.error('stream handler failed')
            self.finish({'message': 'no stream processing will happen'})


    @gen.coroutine
    def data_received(self, chunk):
        # could use this to rate limit the client if needed
        # yield gen.Task(IOLoop.current().call_later, options.server_delay)
        try:
            if not self.custom_content_type:
                self.target_file.write(chunk)
            elif self.custom_content_type in ['application/tar', 'application/tar.gz',
                                              'application/aes']:
                self.proc.stdin.write(chunk)
                if not chunk:
                    self.proc.stdin.flush()
            elif self.custom_content_type in ['application/tar.aes', 'application/tar.gz.aes']:
                self.openssl_proc.stdin.write(chunk)
                if not chunk:
                    self.openssl_proc.stdin.flush()
                    self.tar_proc.stdin.flush()
            elif self.custom_content_type == 'application/gz':
                self.gunzip_proc.stdin.write(chunk)
                if not chunk:
                    self.gunzip_proc.stdin.flush()
            elif self.custom_content_type == 'application/gz.aes':
                self.openssl_proc.stdin.write(chunk)
                if not chunk:
                    self.openssl_proc.stdin.flush()
                    self.gunzip_proc.stdin.flush()
        except Exception as e:
            logging.error(e)
            logging.error("something went wrong with stream processing have to close file")
            self.target_file.close()
            os.rename(self.path, self.path_part)
            self.send_error("something went wrong")


    # TODO: check for errors
    def post(self, pnum):
        if not self.custom_content_type:
            self.target_file.close()
            os.rename(self.path, self.path_part)
        elif self.custom_content_type in ['application/tar', 'application/tar.gz',
                                          'application/aes']:
            out, err = self.proc.communicate()
            if self.custom_content_type == 'application/aes':
                os.rename(self.path, self.path_part)
        elif self.custom_content_type in ['application/tar.aes', 'application/tar.gz.aes']:
            out, err = self.openssl_proc.communicate()
            out, err = self.tar_proc.communicate()
        elif self.custom_content_type == 'application/gz':
            out, err = self.gunzip_proc.communicate()
            self.target_file.close()
            os.rename(self.path, self.path_part)
        elif self.custom_content_type == 'application/gz.aes':
            out, err = self.openssl_proc.communicate()
            out, err = self.gunzip_proc.communicate()
            self.target_file.close()
            os.rename(self.path, self.path_part)
        self.set_status(201)
        self.write({'message': 'data streamed'})


    # TODO: check for errors
    def put(self, pnum):
        if not self.custom_content_type:
            self.target_file.close()
            os.rename(self.path, self.path_part)
        elif self.custom_content_type in ['application/tar', 'application/tar.gz',
                                          'application/aes']:
            out, err = self.proc.communicate()
            if self.custom_content_type == 'application/aes':
                os.rename(self.path, self.path_part)
        elif self.custom_content_type in ['application/tar.aes', 'application/tar.gz.aes']:
            out, err = self.openssl_proc.communicate()
            out, err = self.tar_proc.communicate()
        elif self.custom_content_type == 'application/gz':
            out, err = self.gunzip_proc.communicate()
            self.target_file.close()
            os.rename(self.path, self.path_part)
        elif self.custom_content_type == 'application/gz.aes':
            out, err = self.openssl_proc.communicate()
            out, err = self.gunzip_proc.communicate()
            self.target_file.close()
            os.rename(self.path, self.path_part)
        self.set_status(201)
        self.write({'message': 'data streamed'})


    def patch(self, pnum):
        if not self.merged_file:
            self.target_file.close()
            os.rename(self.path, self.path_part)
            filename = os.path.basename(self.path_part).split('.chunk')[0]
        else:
            filename = os.path.basename(self.merged_file)
        self.set_status(201)
        self.write({'filename': filename, 'id': self.upload_id, 'max_chunk': self.chunk_num})


    def head(self, pnum):
        self.set_status(201)


    def on_finish(self):
        """Called after each request. Clean up any open files if an error occurred."""
        try:
            if not self.target_file.closed:
                self.target_file.close()
                os.rename(self.path, self.path_part)
        except AttributeError as e:
            pass
        if options.set_owner and self.call_chowner:
            try:
                # switch path and path_part variables back to their original values
                # keep local copies in this scope for safety
                if not self.merged_file:
                    path, path_part = self.path_part, self.path
                else:
                    path = self.merged_file
                os.chmod(path, _RW______)
                logging.info('Attempting to change ownership of %s to %s', path, self.user)
                subprocess.call(['sudo', options.chowner_path, path,
                                 self.user, options.api_user, self.group_name])
            except Exception as e:
                logging.info('could not change file mode or owner for some reason')
                logging.info(e)


    def on_connection_close(self):
        """Called when clients close the connection. Clean up any open files."""
        try:
            if not self.target_file.closed:
                self.target_file.close()
                os.rename(self.path, self.path_part)
                logging.info('StreamHandler: Closed file after client closed connection')
        except AttributeError as e:
            logging.info(e)
            logging.info('There was no open file to close')


@stream_request_body
class ProxyHandler(AuthRequestHandler):

    @gen.coroutine
    def prepare(self):
        """Called after headers have been read."""
        try:
            # 1. Set up internal variables
            try:
                self.chunks = tornado.queues.Queue(1)
                if self.request.method == 'HEAD':
                    body = None
                else:
                    body = self.body_producer
            except Exception as e:
                logging.error('Could not set up internal async variables')
                raise e
            # 2. Authentication and authorization
            try:
                authnz_status = self.validate_token(roles_allowed=['import_user', 'export_user', 'admin_user'])
            except Exception as e:
                logging.error('Access token invalid')
                raise e
            # 3. Validate project number in URI
            try:
                pnum = self.request.uri.split('/')[1]
                assert _VALID_PNUM.match(pnum)
            except AssertionError as e:
                logging.error('URI does not contain a valid pnum')
                raise e
            # 4. Set the filename
            try:
                uri = self.request.uri
                uri_parts = uri.split('/')
                if len(uri_parts) == 5:
                    basename = uri_parts[-1]
                    filename = basename.split('?')[0]
                    self.filename = secure_filename(url_unescape(filename))
                else:
                    # TODO: deprecate this once transitioned to URI scheme
                    self.filename = secure_filename(self.request.headers['Filename'])
            except KeyError:
                self.filename = datetime.datetime.now().isoformat() + '.txt'
                logging.info("filename not found - setting filename to: %s", self.filename)
            # 5. Validate group name
            try:
                group_memberships = authnz_status['claims']['groups']
                try:
                    group_name = url_unescape(self.get_query_argument('group'))
                except Exception as e:
                    logging.info('no group specified - choosing default: member-group')
                    group_name = pnum + '-member-group'
            except Exception as e:
                logging.info('Could not get group info from JWT - choosing default: member-group')
                # this happens with basic auth, anonymous end-users
                # then we only allow upload the member group
                group_name = pnum + '-member-group'
                group_memberships = [group_name]
            try:
                assert IS_VALID_GROUPNAME.match(group_name)
            except AssertionError as e:
                logging.error('invalid group name: %s', group_name)
                raise e
            try:
                assert pnum == group_name.split('-')[0]
            except AssertionError as e:
                logging.error('pnum in url: %s and group name: %s do not match', self.request.uri, group_name)
                raise e
            try:
                assert group_name in group_memberships
            except AssertionError as e:
               logging.error('user not member of group')
               raise e
            # 6. Set headers for internal request
            try:
                if 'Content-Type' not in self.request.headers.keys():
                    content_type = 'application/octet-stream'
                elif 'Content-Type' in self.request.headers.keys():
                    content_type = self.request.headers['Content-Type']
                headers = {'Authorization': 'Bearer ' + self.jwt,
                           'Filename': self.filename,
                           'Content-Type': content_type}
                if 'Aes-Key' in self.request.headers.keys():
                    headers['Aes-Key'] = self.request.headers['Aes-Key']
                if 'Aes-Iv' in self.request.headers.keys():
                    headers['Aes-Iv'] = self.request.headers['Aes-Iv']
                if 'Pragma' in self.request.headers.keys():
                    headers['Pragma'] = self.request.headers['Pragma']
            except Exception as e:
                logging.error('Could not prepare headers for async request handling')
                raise e
            # 7. Build URL
            try:
                upload_id, chunk_num = None, None
                chunk_num = url_unescape(self.get_query_argument('chunk'))
                upload_id = url_unescape(self.get_query_argument('id'))
            except Exception:
                pass
            params = '?group=%s&chunk=%s&id=%s' % (group_name, chunk_num, upload_id)
            internal_url = 'http://localhost:%d/%s/files/upload_stream%s' % (options.port, pnum, params)
            # 8. Do async request to handle incoming data
            try:
                self.fetch_future = AsyncHTTPClient().fetch(
                    internal_url,
                    method=self.request.method,
                    body_producer=body,
                    # for the _entire_ request
                    # will have to adjust this
                    # there is also connect_timeout
                    # for the initial connection
                    # in seconds, both
                    request_timeout=12000.0,
                    headers=headers)
            except Exception as e:
                logging.error('Problem in async client')
                logging.error(e)
                raise e
        except Exception as e:
            self.set_status(401)
            self.finish({'message': 'Request failed'})

    @gen.coroutine
    def body_producer(self, write):
        while True:
            chunk = yield self.chunks.get()
            if chunk is None:
                return
            yield write(chunk)

    @gen.coroutine
    def data_received(self, chunk):
        yield self.chunks.put(chunk)

    @gen.coroutine
    def post(self, pnum, filename=None):
        """Called after entire body has been read."""
        yield self.chunks.put(None)
        # wait for request to finish.
        response = yield self.fetch_future
        self.set_status(response.code)
        self.write(response.body)

    @gen.coroutine
    def put(self, pnum, filename=None):
        """Called after entire body has been read."""
        yield self.chunks.put(None)
        # wait for request to finish.
        response = yield self.fetch_future
        self.set_status(response.code)
        self.write(response.body)

    @gen.coroutine
    def patch(self, pnum, filename=None):
        """Called after entire body has been read."""
        yield self.chunks.put(None)
        # wait for request to finish.
        response = yield self.fetch_future
        self.set_status(response.code)
        self.write(response.body)

    def head(self, pnum, filename=None):
        self.set_status(201)


class TableCreatorHandler(AuthRequestHandler):

    """
    Creates tables in sqlite.
    Data inputs are checked to prevent SQL injection.
    See the db module for more details.
    """

    def prepare(self):
        try:
            self.authnz = self.validate_token(roles_allowed=['import_user', 'export_user', 'admin_user'])
        except Exception as e:
            self.finish({'message': 'Authorization failed'})

    def post(self, pnum):
        try:
            data = json_decode(self.request.body)
            assert _VALID_PNUM.match(pnum)
            project_dir = project_import_dir(options.uploads_folder, pnum, None, None)
            engine = sqlite_init(project_dir)
            try:
                _type = data['type']
            except KeyError as e:
                logging.error(e.message)
                logging.error('missing table definition type')
                raise e
            if _type == 'codebook':
                definition = data['definition']
                form_id = data['form_id']
                def_type = data['type']
                create_table_from_codebook(definition, form_id, engine)
                self.set_status(201)
                self.write({'message': 'table created'})
            elif _type == 'generic':
                definition = data['definition']
                create_table_from_generic(definition, engine)
                self.set_status(201)
                self.write({'message': 'table created'})
        except Exception as e:
            logging.error(e.message)
            if e is KeyError:
                m = 'Check your JSON'
            else:
                m = e.message
            self.set_status(400)
            self.finish({'message': m})



class JsonToSQLiteHandler(AuthRequestHandler):

    """
    Stores JSON data in sqlite.
    Data inputs are checked to prevent SQL injection.
    See the db module for more details.
    """

    def prepare(self):
        try:
            self.authnz = self.validate_token(roles_allowed=['import_user', 'export_user', 'admin_user'])
        except Exception as e:
            self.finish({'message': 'Authorization failed'})

    def post(self, pnum, resource_name):
        try:
            data = json_decode(self.request.body)
            assert _VALID_PNUM.match(pnum)
            project_dir = project_import_dir(options.uploads_folder, pnum, None, None)
            engine = sqlite_init(project_dir)
            try:
                valid_resource_name = _table_name_from_table_name(resource_name)
            except TableNameException as e:
                logging.error('invalid request resource')
                raise e
            insert_into(engine, valid_resource_name, data)
            self.set_status(201)
            self.write({'message': 'data stored'})
        except Exception as e:
            logging.error(e)
            self.set_status(400)
            self.write({'message': e.message})



class PGPJsonToSQLiteHandler(AuthRequestHandler):

    """
    Decrypts JSON data, stores it in sqlite.
    """

    def prepare(self):
        try:
            self.authnz = self.validate_token(roles_allowed=['import_user', 'export_user', 'admin_user'])
        except Exception as e:
            self.finish({'message': 'Authorization failed'})

    def post(self, pnum):
        try:
            all_data = json_decode(self.request.body)
            if 'form_id' in all_data.keys():
                table_name = _table_name_from_form_id(all_data['form_id'])
            else:
                table_name = _table_name_from_table_name(str(all_data['table_name']))
            decrypted_data = decrypt_pgp_json(CONFIG, all_data['data'])
            assert _VALID_PNUM.match(pnum)
            project_dir = project_import_dir(options.uploads_folder, pnum, None, None)
            engine = sqlite_init(project_dir)
            insert_into(engine, table_name, decrypted_data)
            self.set_status(201)
            self.write({'message': 'data stored'})
        except Exception as e:
            logging.error(e)
            self.set_status(400)
            self.write({'message': e.message})


class HealthCheckHandler(RequestHandler):

    def head(self, pnum):
        self.set_status(200)
        self.write({'message': 'healthy'})


def main():
    parse_command_line()
    app = Application([
        ('/(.*)/files/health', HealthCheckHandler),
        ('/(.*)/files/upload_stream', StreamHandler),
        ('/(.*)/files/stream', ProxyHandler),
        ('/(.*)/files/stream/(.*)', ProxyHandler),
        ('/(.*)/files/upload', FormDataHandler),
        # this has to present the same interface as
        # the postgrest API in terms of endpoints
        # storage backends should be transparent
        ('/(.*)/storage/rpc/create_table', TableCreatorHandler),
        ('/(.*)/storage/encrypted_data', PGPJsonToSQLiteHandler),
        # this route should be last - exact route matches first
        ('/(.*)/storage/(.*)', JsonToSQLiteHandler),
        # e.g. /p11/sns/94F0E05DB5093C71/54162
        ('/(.*)/sns/(.*)/(.*)', SnsFormDataHandler),
        ('/(.*)/files/export', FileStreamerHandler),
        ('/(.*)/files/export/(.*)', FileStreamerHandler),
        ('/(.*)/files/resumables/(.*)', ResumablesListHandler)
    ], debug=options.debug)
    app.listen(options.port, max_body_size=options.max_body_size)
    IOLoop.instance().start()


if __name__ == '__main__':
    main()
