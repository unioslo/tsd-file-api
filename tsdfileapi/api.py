
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

from uuid import uuid4
from sys import argv
from collections import OrderedDict

import yaml
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
                  IS_VALID_GROUPNAME
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
                logging.error(e)
                logging.error('Missing authorization header')
                self.set_status(400)
                raise Exception('Authorization not possible: missing header')
            try:
                self.jwt = auth_header.split(' ')[1]
            except IndexError as e:
                logging.error(e)
                logging.error('Malformed authorization header')
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
                # extract user info from token
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
                logging.error(e)
                self.set_status(401)
                raise Exception('Authorization failed')
        except Exception as e:
            if not self.status:
                self.set_status(401)
            raise Exception


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


@stream_request_body
class StreamHandler(AuthRequestHandler):

    #pylint: disable=line-too-long
    # Future: http://www.tornadoweb.org/en/stable/util.html?highlight=gzip#tornado.util.GzipDecompressor

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


    @gen.coroutine
    def prepare(self):
        try:
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
                elif self.request.method == 'PUT':
                    filemode = 'wb+'
                try:
                    content_type = self.request.headers['Content-Type']
                    project_dir = project_import_dir(options.uploads_folder, pnum, None, None)
                    filename = secure_filename(self.request.headers['Filename'])
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
                        # only decryption, write to file
                        self.custom_content_type = content_type
                        self.proc = self.start_openssl_proc(output_file=self.path)
                    elif content_type == 'application/aes-octet-stream':
                        # AES binary data, treat like application/aes but do not attempt base64 decoding
                        self.custom_content_type = 'application/aes'
                        self.proc = self.start_openssl_proc(output_file=self.path, base64=False)
                    elif content_type in ['application/tar', 'application/tar.gz']:
                        # tar command creates the dir, no filename to use, no file to open
                        if 'gz' in content_type:
                            tarflags = '-xzf'
                        else:
                            tarflags = '-xf'
                        self.custom_content_type = content_type
                        self.proc = subprocess.Popen(['tar', '-C', project_dir, tarflags, '-'],
                                                 stdin=subprocess.PIPE)
                        logging.info('unpacking tarball')
                    elif content_type in ['application/tar.aes', 'application/tar.gz.aes']:
                        # tar command creates the dir, no filename to use, no file to open
                        if 'gz' in content_type:
                            tarflags = '-xzf'
                        else:
                            tarflags = '-xf'
                        self.custom_content_type = content_type
                        self.openssl_proc = self.start_openssl_proc()
                        logging.info('started openssl process')
                        self.tar_proc = subprocess.Popen(['tar', '-C', project_dir, tarflags, '-'],
                                                 stdin=self.openssl_proc.stdout)
                        logging.info('started tar process')
                    elif content_type == 'application/gz':
                        self.custom_content_type = content_type
                        logging.info('opening file: %s', self.path)
                        self.target_file = open(self.path, filemode)
                        self.gunzip_proc = subprocess.Popen(['gunzip', '-c', '-'],
                                                             stdin=subprocess.PIPE,
                                                             stdout=self.target_file)
                        logging.info('started gunzip process')
                    elif content_type == 'application/gz.aes':
                        # seeing a non-determnistic failure here sometimes...
                        self.custom_content_type = content_type
                        logging.info('opening file: %s', self.path)
                        self.target_file = open(self.path, filemode)
                        self.openssl_proc = self.start_openssl_proc()
                        self.gunzip_proc = subprocess.Popen(['gunzip', '-c', '-'],
                                                             stdin=self.openssl_proc.stdout,
                                                             stdout=self.target_file)
                    else:
                        # write data to file, as-is
                        self.custom_content_type = None
                        logging.info('opening file: %s', self.path)
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
        #logging.info('StreamHandler.data_received(%d bytes: %r)', len(chunk), chunk[:9])
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
            logging.info('StreamHandler: closed file')
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
            logging.info('StreamHandler: closed file')
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

    def head(self, pnum):
        self.set_status(201)

    def on_finish(self):
        """Called after each request. Clean up any open files if an error occurred."""
        try:
            if not self.target_file.closed:
                self.target_file.close()
                os.rename(self.path, self.path_part)
                logging.info('StreamHandler: Closed file')
        except AttributeError as e:
            logging.info(e)
            logging.info('There was no open file to close')
        if options.set_owner:
            try:
                # switch path and path_part variables back to their original values
                # keep local copies in this scope for safety
                path, path_part = self.path_part, self.path
                os.chmod(path, _RW______)
                logging.info('Attempting to change ownership of %s to %s', path, self.user)
                subprocess.call(['sudo', options.chowner_path, path,
                                 self.user, options.api_user, self.group_name])
            except Exception as e:
                logging.info('could not change file mode or owner for some reason')
                logging.info(e)
        logging.info("Stream processing finished")

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
                logging.info('supplied filename: %s', self.filename)
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
                logging.error('Could not get group name')
                raise e
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
            # 7. Do async request to handle incoming data
            try:
                self.fetch_future = AsyncHTTPClient().fetch(
                    'http://localhost:%d/%s/files/upload_stream?group=%s' % (options.port, pnum, group_name),
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
        #logging.info('ProxyHandler.data_received(%d bytes: %r)', len(chunk), chunk[:9])
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

    def head(self, pnum, filename=None):
        self.set_status(201)


class MetaDataHandler(AuthRequestHandler):

    def prepare(self):
        try:
            self.authnz = self.validate_token(roles_allowed=['import_user', 'export_user', 'admin_user'])
        except Exception as e:
            self.finish({'message': 'Authorization failed'})

    def get(self, pnum):
        # calls to None are for compatibility with the signature of project_sns_dir
        _dir = project_import_dir(options.uploads_folder, pnum, None, None)
        files = os.listdir(_dir)
        times = map(lambda x:
                    datetime.datetime.fromtimestamp(
                        os.stat(os.path.normpath(_dir + '/' + x)).st_mtime).isoformat(), files)
        file_info = OrderedDict()
        for i in zip(files, times):
            file_info[i[0]] = i[1]
        self.write(file_info)


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
        ('/(.*)/files/list', MetaDataHandler),
        # this has to present the same interface as
        # the postgrest API in terms of endpoints
        # storage backends should be transparent
        ('/(.*)/storage/rpc/create_table', TableCreatorHandler),
        ('/(.*)/storage/encrypted_data', PGPJsonToSQLiteHandler),
        # this route should be last - exact route matches first
        ('/(.*)/storage/(.*)', JsonToSQLiteHandler),
        # e.g. /p11/sns/94F0E05DB5093C71/54162
        ('/(.*)/sns/(.*)/(.*)', SnsFormDataHandler),
    ], debug=options.debug)
    app.listen(options.port, max_body_size=options.max_body_size)
    IOLoop.instance().start()


if __name__ == '__main__':
    main()
