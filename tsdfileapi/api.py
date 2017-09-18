
"""API for uploading files and data streams to TSD."""

import os
import logging
import json
import yaml
import datetime
import hashlib
from sys import argv
from collections import OrderedDict

import tornado.queues
from tornado.concurrent import Future
from tornado.escape import utf8, json_decode
from tornado import gen
from tornado.httpclient import AsyncHTTPClient
from tornado.ioloop import IOLoop
from tornado.options import parse_command_line, define, options
from tornado.web import Application, RequestHandler, stream_request_body, \
                        HTTPError, MissingArgumentError

from auth import verify_json_web_token
from utils import secure_filename
from db import insert_into, create_table_from_codebook, sqlite_init, \
               create_table_from_generic, _table_name_from_form_id, \
               _valid_pnum
from pgp import decrypt_pgp_json


def read_config(file):
    with open(file) as f:
        conf = yaml.load(f)
    return conf

try:
    file = argv[1]
    config = read_config(file)
except Exception as e:
    logging.error(e)
    raise e


define('port', default=config['port'])
define('debug', default=config['debug'])
define('server_delay', default=config['server_delay'])
define('num_chunks', default=config['num_chunks'])
define('max_body_size', config['max_body_size'])
define('uploads_folder', config['uploads_folder'])
define('nsdb_path', config['sqlite_folder'])
if not config['use_secret_store']:
    define('secret', config['secret'])
else:
    from db import load_jwk_store
    define('secret_store', load_jwk_store(config))


class AuthRequestHandler(RequestHandler):

    def validate_token(self, roles_allowed=None):
        """
        Token validation is about authorization. Clients and/or users authenticate
        themselves with the auth-api to obtain tokens. When performing requests
        against the file-api these tokens are presented in the Authorization header
        of the HTTP request as a Bearer token.

        Before the body of each request is process this method is called in 'prepare'.
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
        logging.info("checking JWT")
        self.status = None
        try:
            assert roles_allowed
            auth_header = self.request.headers['Authorization']
            self.jwt = auth_header.split(' ')[1]
            if not config['use_secret_store']:
                project_specific_secret = options.secret
            else:
                try:
                    pnum = self.request.uri.split('/')[1]
                    assert _valid_pnum.match(pnum)
                except AssertionError as e:
                    logging.error(e.message)
                    logging.error('pnum invalid')
                    raise e
                project_specific_secret = options.secret_store[pnum]
            token_verified_status = verify_json_web_token(auth_header, project_specific_secret, roles_allowed, pnum)
        except (KeyError, UnboundLocalError, AssertionError) as e:
            logging.error(e.message)
            token_verified_status = {}
            token_verified_status['message'] = 'Missing Authorization header.'
            token_verified_status['status'] = False
            self.status = 400
        if token_verified_status['status'] is True:
            return
        else:
            if self.status == 400:
                self.set_status(400)
            else:
                self.set_status(401)
            self.finish({ 'message': token_verified_status['message'] })


class FormDataHandler(AuthRequestHandler):

    def write_file(self, filemode):
        filename = secure_filename(self.request.files['file'][0]['filename'])
        target = os.path.normpath(options.uploads_folder + '/' + filename)
        filebody = self.request.files['file'][0]['body']
        with open(target, filemode) as f:
            f.write(filebody)

    def prepare(self):
        self.validate_token(roles_allowed=['app_user', 'import_user', 'export_user', 'admin_user'])
        try:
            if len(self.request.files['file']) > 1:
                self.set_status(405)
                self.message = 'Only one file per request is allowed.'
                raise KeyError
        except KeyError:
            issue = 'No file supplied with upload request'
            logging.error(issue)
            self.message = issue
            self.set_status(400)
            raise MissingArgumentError('file')

    def post(self, pnum):
        self.write_file('ab+')
        self.set_status(201)
        self.write({'message': 'file uploaded'})

    def patch(self, pnum):
        self.write_file('ab+')
        self.set_status(201)
        self.write({'message': 'file uploaded'})

    def put(self, pnum):
        self.write_file('wb+')
        self.set_status(201)
        self.write({'message': 'file uploaded'})

    def head(self, pnum):
        self.set_status(201)


@stream_request_body
class StreamHandler(AuthRequestHandler):

    # Future: http://www.tornadoweb.org/en/stable/util.html?highlight=gzip#tornado.util.GzipDecompressor

    @gen.coroutine
    def prepare(self):
        logging.info('StreamHandler')
        self.validate_token(roles_allowed=['app_user', 'import_user', 'export_user', 'admin_user'])
        try:
            filename = secure_filename(self.request.headers['Filename'])
            path = os.path.normpath(options.uploads_folder + '/' + filename)
            logging.info('opening file')
            logging.info('path: %s', path)
            if self.request.method == 'POST':
                self.target_file = open(path, 'ab+')
            elif self.request.method == 'PUT':
                self.target_file = open(path, 'wb+')
        except Exception as e:
            logging.error(e)
            logging.error("filename not found")
            try:
                self.target_file.close()
            except AttributeError as e:
                logging.error(e)
                logging.error('No file to close after all - so nothing to worry about')


    @gen.coroutine
    def data_received(self, chunk):
        # could use this to rate limit the client if needed
        # yield gen.Task(IOLoop.current().call_later, options.server_delay)
        #logging.info('StreamHandler.data_received(%d bytes: %r)', len(chunk), chunk[:9])
        try:
            self.target_file.write(chunk)
        except Exception:
            logging.error("something went wrong with stream processing have to close file")
            self.target_file.close()
            self.send_error("something went wrong")

    def post(self, pnum):
        logging.info('StreamHandler.post')
        self.target_file.close()
        logging.info('StreamHandler: closed file')
        self.set_status(201)
        self.write({ 'message': 'data streamed to file' })

    def put(self, pnum):
        logging.info('StreamHandler.put')
        self.target_file.close()
        logging.info('StreamHandler: closed file')
        self.set_status(201)
        self.write({ 'message': 'data streamed to file' })

    def head(self, pnum):
        self.set_status(201)

    def on_finish(self):
        """Called after each request. Clean up any open files if an error occurred."""
        try:
            if not self.target_file.closed:
                self.target_file.close()
                logging.info('StreamHandler: Closed file')
        except AttributeError as e:
            logging.info(e)
            logging.info('There was no open file to close')
        logging.info("Stream processing finished")

    def on_connection_close(self):
        """Called when clients close the connection. Clean up any open files."""
        try:
            if not self.target_file.closed:
                self.target_file.close()
                logging.info('StreamHandler: Closed file after client closed connection')
        except AttributeError as e:
            logging.info(e)
            logging.info('There was no open file to close')


@stream_request_body
class ProxyHandler(AuthRequestHandler):

    @gen.coroutine
    def prepare(self):
        """Called after headers have been read."""
        logging.info('ProxyHandler.prepare')
        self.validate_token(roles_allowed=['app_user', 'import_user', 'export_user', 'admin_user'])
        try:
            self.filename = secure_filename(self.request.headers['Filename'])
            logging.info('supplied filename: %s', self.filename)
        except KeyError:
            self.filename = datetime.datetime.now().isoformat() + '.txt'
            logging.info("filename not found - going to use this filename: %s" % self.filename)
        self.chunks = tornado.queues.Queue(1) # TODO: performace tuning here
        try:
            if self.request.method == 'HEAD':
                body = None
            else:
                body = self.body_producer
            pnum = self.request.uri.split('/')[1]
            try:
                assert _valid_pnum.match(pnum)
            except AssertionError as e:
                logging.error('URI does not contain a valid pnum')
                raise e
            self.fetch_future = AsyncHTTPClient().fetch(
                'http://localhost:%d/%s/upload_stream' % (options.port, pnum),
                method=self.request.method,
                body_producer=body,
                # for the _entire_ request
                # will have to adjust this
                # there is also connect_timeout
                # for the initial connection
                # in seconds, both
                request_timeout=12000.0,
                headers={ 'Authorization': 'Bearer ' + self.jwt, 'Filename': self.filename })
        except (AttributeError, HTTPError, AssertionError) as e:
            logging.error('Problem in async client')
            logging.error(e)

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
    def post(self, pnum):
        """Called after entire body has been read."""
        logging.info('ProxyHandler.post')
        yield self.chunks.put(None)
        # wait for request to finish.
        response = yield self.fetch_future
        self.set_status(response.code)
        self.write(response.body)

    @gen.coroutine
    def put(self, pnum):
        """Called after entire body has been read."""
        logging.info('ProxyHandler.put')
        yield self.chunks.put(None)
        # wait for request to finish.
        response = yield self.fetch_future
        self.set_status(response.code)
        self.write(response.body)

    def head(self, pnum):
        self.set_status(201)


class MetaDataHandler(AuthRequestHandler):

    def prepare(self):
        self.validate_token(roles_allowed=['app_user', 'import_user', 'export_user', 'admin_user'])

    def get(self, pnum):
        _dir = options.uploads_folder
        files = os.listdir(_dir)
        times = map(lambda x:
            datetime.datetime.fromtimestamp(os.stat(os.path.normpath(_dir + '/' + x)).st_mtime).isoformat(), files)
        file_info = OrderedDict()
        for i in zip(files, times):
            file_info[i[0]] = i[1]
        self.write(file_info)


class ChecksumHandler(AuthRequestHandler):

    # TODO: consider removing

    def md5sum(self, filename, blocksize=65536):
        hash = hashlib.md5()
        with open(filename, "rb") as f:
            for block in iter(lambda: f.read(blocksize), b""):
                hash.update(block)
        return hash.hexdigest()

    def prepare(self):
        self.validate_token(roles_allowed=['app_user', 'import_user', 'export_user', 'admin_user'])

    def get(self, pnum):
        # Consider: http://www.tornadoweb.org/en/stable/escape.html#tornado.escape.url_unescape
        filename = secure_filename(self.get_query_argument('filename'))
        path = os.path.normpath(options.uploads_folder + '/' + filename)
        checksum = self.md5sum(path)
        self.write({ 'checksum': checksum, 'algorithm': 'md5' })


class TableCreatorHandler(AuthRequestHandler):

    """
    Creates tables in sqlite.
    Data inputs are checked to prevent SQL injection.
    See the db module for more details.
    """

    def prepare(self):
        self.validate_token(roles_allowed=['app_user', 'import_user', 'export_user', 'admin_user'])


    def post(self, pnum):
        try:
            data = json_decode(self.request.body)
            engine = sqlite_init(options.nsdb_path, pnum)
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
        self.validate_token(roles_allowed=['app_user', 'import_user', 'export_user', 'admin_user'])

    def post(self, pnum, resource_name):
        try:
            data = json_decode(self.request.body)
            engine = sqlite_init(options.nsdb_path, pnum)
            insert_into(engine, resource_name, data)
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
        self.validate_token(roles_allowed=['app_user', 'import_user', 'export_user', 'admin_user'])
        pass

    def post(self, pnum):
        try:
            all_data = json_decode(self.request.body)
            table_name = _table_name_from_form_id(all_data['form_id'])
            decrypted_data = decrypt_pgp_json(config, all_data['data'])
            engine = sqlite_init(options.nsdb_path, pnum)
            insert_into(engine, table_name, decrypted_data)
            self.set_status(201)
            self.write({'message': 'data stored'})
        except Exception as e:
            logging.error(e)
            self.set_status(400)
            self.write({'message': e.message})


def main():
    parse_command_line()
    app = Application([
        ('/(.*)/upload_stream', StreamHandler),
        ('/(.*)/stream', ProxyHandler),
        ('/(.*)/upload', FormDataHandler),
        ('/(.*)/checksum', ChecksumHandler),
        ('/(.*)/list', MetaDataHandler),
        # this has to present the same interface as
        # the postgrest API in terms of endpoints
        # storage backends should be transparent
        ('/(.*)/storage/(.*)', JsonToSQLiteHandler),
        ('/(.*)/rpc/create_table', TableCreatorHandler),
        ('/(.*)/encrypted_data', PGPJsonToSQLiteHandler),
    ], debug=options.debug)
    app.listen(options.port, max_body_size=options.max_body_size)
    IOLoop.instance().start()


if __name__ == '__main__':
    main()
