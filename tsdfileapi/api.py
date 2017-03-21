
"""API for uploading files and data streams to TSD."""

import os
import logging
import json
import yaml
import datetime
import tornado.queues
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool
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
        try:
            auth_header = self.request.headers['Authorization']
            self.jwt = auth_header.split(' ')[1]
            token_verified_status = verify_json_web_token(auth_header, options.jwt_secret, 'app_user')
            self.authnz = token_verified_status
        except (KeyError, UnboundLocalError) as e:
            self.st = 400
            self.message = 'Missing Authorization header.'
        if token_verified_status is True:
            return
        else:
            self.st = 403
            self.message = token_verified_status
            self.set_status(self.st)
            self.finish({ 'message': self.message })


class FormDataHandler(AuthRequestHandler):

    def prepare(self):
        self.validate_token()
        # TODO: disallow streaming here

    def post(self):
        if len(self.request.files['file']) > 1:
            self.set_status(405)
            self.finsh({ 'message': 'Only one file per request is allowed.' })
        # TODO: check filename
        filename = self.request.files['file'][0]['filename']
        target = os.path.normpath(options.uploads_folder + '/' + filename)
        filebody = self.request.files['file'][0]['body']
        with open(target, 'ab+') as f:
            f.write(filebody)
        self.write({'message': 'file uploaded'})


@stream_request_body
class StreamHandler(AuthRequestHandler):

    def prepare(self):
        logging.info('StreamHandler')
        self.validate_token()
        try:
            filename = self.request.headers['X-Filename']
            path = os.path.normpath(options.uploads_folder + '/' + filename)
        except KeyError:
            logging.error("filename not found")
            self.send_error("ERROR")
        logging.info('opening file')
        self.target_file = open(filename, 'ab+')

    @gen.coroutine
    def data_received(self, chunk):
        # could use this to rate limit the client if needed
        # yield gen.Task(IOLoop.current().call_later, options.server_delay)
        logging.info('StreamHandler.data_received(%d bytes: %r)', len(chunk), chunk[:9])
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
            logging.error("filename not found - creating own")
        self.chunks = tornado.queues.Queue(1) # TODO: performace tuning here
        self.fetch_future = AsyncHTTPClient().fetch(
            'http://localhost:%d/upload_stream' % options.port,
            method='POST',
            body_producer=self.body_producer,
            request_timeout=12000.0,
            headers={
                'Authorization': 'Bearer ' + self.jwt,
                'X-Filename': self.filename
                })

    @gen.coroutine
    def body_producer(self, write):
        while True:
            chunk = yield self.chunks.get()
            if chunk is None:
                return
            yield write(chunk)

    @gen.coroutine
    def data_received(self, chunk):
        logging.info('ProxyHandler.data_received(%d bytes: %r)', len(chunk), chunk[:9])
        yield self.chunks.put(chunk)

    @gen.coroutine
    def post(self):
        logging.info('ProxyHandler.post')
        yield self.chunks.put(None)
        # wait for request to finish.
        response = yield self.fetch_future
        self.set_status(response.code)
        self.write(response.body)


def main():
    parse_command_line()
    app = Application([
        ('/upload_stream', StreamHandler),
        ('/stream', ProxyHandler),
        ('/upload', FormDataHandler),
    ], debug=options.debug)
    app.listen(options.port, max_body_size=options.max_body_size)
    IOLoop.instance().start()


if __name__ == '__main__':
    main()
