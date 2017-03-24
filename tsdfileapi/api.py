
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
from tornado.web import Application, RequestHandler, stream_request_body


from auth import verify_json_web_token


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
define('jwt_secret', config['jwt_secret'])


def check_filename(filename):
    pass


class AuthRequestHandler(RequestHandler):

    def validate_token(self):
        # this only supports uploads, not downloads (yet)
        logging.info("checking JWT")
        self.status = None
        try:
            auth_header = self.request.headers['Authorization']
            self.jwt = auth_header.split(' ')[1]
            token_verified_status = verify_json_web_token(auth_header, options.jwt_secret, 'app_user')
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
        # TODO: check filename
        filename = self.request.files['file'][0]['filename']
        target = os.path.normpath(options.uploads_folder + '/' + filename)
        filebody = self.request.files['file'][0]['body']
        with open(target, filemode) as f:
            f.write(filebody)

    def prepare(self):
        self.validate_token()
        if len(self.request.files['file']) > 1:
            self.set_status(405)
            self.finsh({ 'message': 'Only one file per request is allowed.' })

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


@stream_request_body
class StreamHandler(AuthRequestHandler):

    def prepare(self):
        logging.info('StreamHandler')
        self.validate_token()
        try:
            filename = self.request.headers['X-Filename']
            path = os.path.normpath(options.uploads_folder + '/' + filename)
            logging.info('opening file')
            logging.info('path: %s', path)
            self.target_file = open(path, 'ab+')
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
        logging.info('closing file')
        self.target_file.close()
        self.write({ 'message': 'data streamed to file' })

    def on_finish(self):
        logging.info("FINISHED")


@stream_request_body
class ProxyHandler(AuthRequestHandler):

    def prepare(self):
        logging.info('ProxyHandler.prepare')
        self.validate_token()
        try:
            self.filename = self.request.headers['X-Filename']
            logging.info('supplied filename: %s', self.filename)
        except KeyError:
            self.filename = datetime.datetime.now().isoformat() + '.txt'
            logging.error("filename not found - creating own: %s" % self.filename)
        self.chunks = tornado.queues.Queue(1) # TODO: performace tuning here
        try:
            self.fetch_future = AsyncHTTPClient().fetch(
                'http://localhost:%d/upload_stream' % options.port,
                method='POST',
                body_producer=self.body_producer,
                request_timeout=12000.0,
                headers={ 'Authorization': 'Bearer ' + self.jwt, 'X-Filename': self.filename })
        except AttributeError as e:
            logging.error(e)
            logging.error('No JWT found.')

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
        logging.info('ProxyHandler.post')
        yield self.chunks.put(None)
        # wait for request to finish.
        response = yield self.fetch_future
        self.set_status(response.code)
        self.write(response.body)


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
        filename = self.get_query_argument('filename')
        algorithm = self.get_query_argument('algorithm')
        if algorithm != 'md5':
            self.finish({ 'message': 'algorithm not supported' })
        else:
            path = os.path.normpath(options.uploads_folder + '/' + filename)
            checksum = self.md5sum(path)
            self.write({ 'checksum': checksum, 'algorithm': 'md5' })


def main():
    parse_command_line()
    app = Application([
        ('/upload_stream', StreamHandler),
        ('/stream', ProxyHandler),
        ('/upload', FormDataHandler),
        ('/checksum', ChecksumHandler),
        ('/list', MetaDataHandler)
    ], debug=options.debug)
    app.listen(options.port, max_body_size=options.max_body_size)
    IOLoop.instance().start()


if __name__ == '__main__':
    main()
