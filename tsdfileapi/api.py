
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
from tornado.web import Application, RequestHandler, stream_request_body, HTTPError, MissingArgumentError

from auth import verify_json_web_token
from utils import secure_filename
from db import insert_into, create_table_from_codebook, sqlite_init


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
define('import_secret', config['import_secret'])
define('export_secret', config['export_secret'])
define('nsdb_path', config['sqlite_folder'])


class AuthRequestHandler(RequestHandler):

    def validate_token(self):
        # this only supports uploads, not downloads (yet)
        logging.info("checking JWT")
        self.status = None
        try:
            auth_header = self.request.headers['Authorization']
            self.jwt = auth_header.split(' ')[1]
            token_verified_status = verify_json_web_token(auth_header, options.import_secret, 'app_user')
        except (KeyError, UnboundLocalError) as e:
            logging.error(e)
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
        self.validate_token()
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

    def post(self):
        self.write_file('ab+')
        self.set_status(201)
        self.write({'message': 'file uploaded'})

    def patch(self):
        self.write_file('ab+')
        self.set_status(201)
        self.write({'message': 'file uploaded'})

    def put(self):
        self.write_file('wb+')
        self.set_status(201)
        self.write({'message': 'file uploaded'})

    def head(self):
        self.set_status(201)


@stream_request_body
class StreamHandler(AuthRequestHandler):

    # Future: http://www.tornadoweb.org/en/stable/util.html?highlight=gzip#tornado.util.GzipDecompressor

    @gen.coroutine
    def prepare(self):
        logging.info('StreamHandler')
        self.validate_token()
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

    def post(self):
        logging.info('StreamHandler.post')
        self.target_file.close()
        logging.info('StreamHandler: closed file')
        self.set_status(201)
        self.write({ 'message': 'data streamed to file' })

    def put(self):
        logging.info('StreamHandler.put')
        self.target_file.close()
        logging.info('StreamHandler: closed file')
        self.set_status(201)
        self.write({ 'message': 'data streamed to file' })

    def head(self):
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
        self.validate_token()
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
            self.fetch_future = AsyncHTTPClient().fetch(
                'http://localhost:%d/upload_stream' % options.port,
                method=self.request.method,
                body_producer=body,
                # for the _entire_ request
                # will have to adjust this
                # there is also connect_timeout
                # for the initial connection
                # in seconds, both
                request_timeout=12000.0,
                headers={ 'Authorization': 'Bearer ' + self.jwt, 'Filename': self.filename })
        except (AttributeError, HTTPError) as e:
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
    def post(self):
        """Called after entire body has been read."""
        logging.info('ProxyHandler.post')
        yield self.chunks.put(None)
        # wait for request to finish.
        response = yield self.fetch_future
        self.set_status(response.code)
        self.write(response.body)

    @gen.coroutine
    def put(self):
        """Called after entire body has been read."""
        logging.info('ProxyHandler.put')
        yield self.chunks.put(None)
        # wait for request to finish.
        response = yield self.fetch_future
        self.set_status(response.code)
        self.write(response.body)

    def head(self):
        self.set_status(201)


class MetaDataHandler(AuthRequestHandler):

    def prepare(self):
        self.validate_token()

    def get(self):
        _dir = options.uploads_folder
        files = os.listdir(_dir)
        times = map(lambda x:
            datetime.datetime.fromtimestamp(os.stat(os.path.normpath(_dir + '/' + x)).st_mtime).isoformat(), files)
        file_info = OrderedDict()
        for i in zip(files, times):
            file_info[i[0]] = i[1]
        self.write(file_info)


class ChecksumHandler(AuthRequestHandler):

    def md5sum(self, filename, blocksize=65536):
        hash = hashlib.md5()
        with open(filename, "rb") as f:
            for block in iter(lambda: f.read(blocksize), b""):
                hash.update(block)
        return hash.hexdigest()

    def prepare(self):
        self.validate_token()

    def get(self):
        # Consider: http://www.tornadoweb.org/en/stable/escape.html#tornado.escape.url_unescape
        filename = secure_filename(self.get_query_argument('filename'))
        path = os.path.normpath(options.uploads_folder + '/' + filename)
        checksum = self.md5sum(path)
        self.write({ 'checksum': checksum, 'algorithm': 'md5' })


class TableCreatorHandler(AuthRequestHandler):

    def prepare(self):
        self.validate_token()
        pass

    def post(self, pnum):
        try:
            data = json_decode(self.request.body)
            definition = data['definition']
            form_id = data['form_id']
            def_type = data['type']
            engine = sqlite_init(options.nsdb_path, pnum)
            create_table_from_codebook(definition, form_id, engine)
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

    def prepare(self):
        self.validate_token()
        pass

    def post(self, pnum, resource_name):
        # data inputs are checked to prevent SQL injection
        # see the db module for more details
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


def main():
    parse_command_line()
    app = Application([
        # todo add project numbers in url
        ('/upload_stream', StreamHandler),
        ('/stream', ProxyHandler),
        ('/upload', FormDataHandler),
        ('/checksum', ChecksumHandler),
        ('/list', MetaDataHandler),
        ('/(.*)/storage/(.*)', JsonToSQLiteHandler),
        ('/(.*)/rpc/create_table', TableCreatorHandler)
    ], debug=options.debug)
    app.listen(options.port, max_body_size=options.max_body_size)
    IOLoop.instance().start()


if __name__ == '__main__':
    main()
