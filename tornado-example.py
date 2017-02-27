# https://gist.github.com/bdarnell/5bb1bd04a443c4e06ccd

import logging
import tornado.queues

from tornado.concurrent import Future
from tornado.escape import utf8
from tornado import gen
from tornado.httpclient import AsyncHTTPClient
from tornado.ioloop import IOLoop
from tornado.options import parse_command_line, define, options
from tornado.web import Application, RequestHandler, stream_request_body

define('port', default=8888)
define('debug', default=True)
define('server_delay', default=0)
define('num_chunks', default=50)
define('max_body_size', 1024*1024*1024)

@stream_request_body
class UploadHandler(RequestHandler):
    def prepare(self):
        logging.info('UploadHandler.prepare')

    @gen.coroutine
    def data_received(self, chunk):
        logging.info('UploadHandler.data_received(%d bytes: %r)',
                     len(chunk), chunk[:9])
        with open('out', 'ab+') as f:
            f.write(chunk)
        yield gen.Task(IOLoop.current().call_later, options.server_delay)

    def put(self):
        logging.info('UploadHandler.put')
        self.write('ok')

@stream_request_body
class ProxyHandler(RequestHandler):
    def prepare(self):
        logging.info('ProxyHandler.prepare')
        self.chunks = tornado.queues.Queue(1)
        self.fetch_future = AsyncHTTPClient().fetch(
            'http://localhost:%d/upload' % options.port,
            method='PUT',
            body_producer=self.body_producer,
            request_timeout=12000.0)

    @gen.coroutine
    def body_producer(self, write):
        while True:
            chunk = yield self.chunks.get()
            if chunk is None:
                return
            yield write(chunk)

    @gen.coroutine
    def data_received(self, chunk):
        logging.info('ProxyHandler.data_received(%d bytes: %r)',
                     len(chunk), chunk[:9])
        yield self.chunks.put(chunk)

    @gen.coroutine
    def put(self):
        logging.info('ProxyHandler.put')
        # Write None to the chunk queue to signal body_producer to exit,
        # then wait for the request to finish.
        yield self.chunks.put(None)
        response = yield self.fetch_future
        self.set_status(response.code)
        self.write(response.body)

@stream_request_body
class Mine(tornado.web.RequestHandler):
    def data_received(self, chunk):
        with open('boom', 'wb+') as f:
            f.write(chunk)
    def post(self):
        self.write({'m': 'yep'})

def main():
    parse_command_line()
    app = Application([
        ('/upload', UploadHandler),
        ('/proxy', ProxyHandler),
        ('/proxy', Mine),
    ], debug=options.debug)
    app.listen(options.port, max_body_size=options.max_body_size)
    IOLoop.instance().start()

if __name__ == '__main__':
    main()