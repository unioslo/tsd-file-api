
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

from auth import store_email_and_password, generate_token, verify_json_web_token, \
    check_client_credentials_in_order


def read_config(file):
    with open(file) as f:
        conf = yaml.load(f)
    return conf


define('port', default=8888)
define('debug', default=True)
define('server_delay', default=0)
define('num_chunks', default=50)
define('max_body_size', 1024*1024*1024*5)

# get all this from config
# consider making a class
# investigate define functionality for storage
UPLOADS_FOLDER = '/Users/leondutoit/uploaded-files'
JWT_SECRET = 'testsecret'
DBURL = 'sqlite:////Users/leondutoit/tsd-file-api/api-users.db'

def db_init(engine_type):
    # Ref: http://docs.sqlalchemy.org/en/rel_1_1/core/pooling.html
    if engine_type == 'sqlite':
        engine = create_engine(DBURL, poolclass=QueuePool)
        try:
            conn = engine.connect()
            conn.execute('create table if not exists users(email TEXT, pw TEXT, verified INT);')
            conn.close()
        except Exception:
            raise Exception("Could not initialise sqlite - user table not created.")
        return engine
    elif engine_type == 'postgresql':
        raise Exception("postgresql engine not implemented yet")
    else:
        raise Exception("Did you perhaps make a typo in your engine spec? \
             Legal values are: 'sqlite' and 'postgresql'.")


ENGINE = db_init('sqlite')


def check_filename(filename):
    pass


class UserRegistrationHandler(RequestHandler):

    def prepare(self):
        data = json_decode(self.request.body)
        email = str(data['email'])
        pw = str(data['pw'])
        conn = ENGINE.connect()
        store_email_and_password(conn, email, pw)

    def post(self):
        self.write({ 'message': 'user registered' })


class JWTIssuerHandler(RequestHandler):

    def prepare(self):
        data = json_decode(self.request.body)
        self.email = str(data['email'])
        self.pw = str(data['pw'])
        conn = ENGINE.connect()
        self.answer = check_client_credentials_in_order(conn, self.email, self.pw)
        if not self.answer['credentials_in_order']:
            self.set_status(403)
            self.finish({ 'message': self.answer['message'] })
    def post(self):
        token = generate_token(self.email, JWT_SECRET)
        self.write({ 'token': token })


class AuthRequestHandler(RequestHandler):

    def validate_token(self):
        logging.info("checking JWT")
        try:
            auth_header = self.request.headers['Authorization']
            self.jwt = auth_header.split(' ')[1]
            token_verified_status = verify_json_web_token(auth_header, JWT_SECRET, 'app_user')
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
        target = os.path.normpath(UPLOADS_FOLDER + '/' + filename)
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
        ('/upload_signup', UserRegistrationHandler),
        ('/upload_token', JWTIssuerHandler),
        ('/upload_stream', StreamHandler),
        ('/stream', ProxyHandler),
        ('/upload', FormDataHandler),
    ], debug=options.debug)
    app.listen(options.port, max_body_size=options.max_body_size)
    IOLoop.instance().start()


if __name__ == '__main__':
    main()
