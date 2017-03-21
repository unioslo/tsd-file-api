
"""
Exploring Transfer-Encoding: chunked with a minimal python client.

From: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding

Data is sent in a series of chunks. The Content-Length header is omitted in this
case and at the beginning of each chunk you need to add the length of the current
chunk in hexadecimal format, followed by '\r\n' and then the chunk itself, followed
by another '\r\n'.

The terminating chunk is a regular chunk, with the exception that its length is zero.
It is followed by the trailer, which consists of a (possibly empty) sequence of
entity header fields.

E.g.

HTTP/1.1 200 OK
Content-Type: text/plain
Transfer-Encoding: chunked

7\r\n
Mozilla\r\n
9\r\n
Developer\r\n
7\r\n
Network\r\n
0\r\n
\r\n

tornado
so with tornado it _just works_ - but not the naive impl
the async method write data to the file, while waiting for the rest
this is _exactly what the video streaming needs.
behind nginx you need to set the following:
proxy_http_version 1.1;
proxy_request_buffering off;

From bdarnell:
sending an error requires a little-used feature of HTTP called "100-continue".
If the client supports 100-continue (curl-based clients do by default for large POSTS;
most others don't. I don't know if curl uses 100-continue with chunked requests)
and the tornado service uses @stream_request_body, then sending an error response
from prepare() will be received by the client before the body is uploaded

So the HTTP Client should implement this...
Some background on python2.7 and requests
https://github.com/kennethreitz/requests/issues/713

"""

import click
import logging
import httplib
import requests
import string
import time
import sys
import json
import os
import unittest
import yaml


httplib.HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True


def lazy_file_reader(filename):
    with open(filename, 'r+') as f:
        while True:
            line = f.readline()
            if line == '':
                break
            else:
                yield line


def get_token(url):
    resp = requests.post(url + '/import_token',
        data=json.dumps({'email':'health@check.local', 'pass': 'something_healthy'}),
        headers={'Content-Type': 'application/json'})
    return json.loads(resp.text)['token']

TOKEN = get_token('http://localhost:3002')

class TestFileApi(unittest.TestCase):


    @classmethod
    def setUpClass(cls):
        try:
            with open(sys.argv[1]) as f:
                cls.config = yaml.load(f)
                print cls.config
        except Exception as e:
            print e
            print "Missing config file?"
            sys.exit(1)
        cls.base_url = 'http://localhost' + ':' + str(cls.config['port'])
        cls.data_folder = cls.config['data_folder']
        cls.file_to_stream = os.path.normpath(cls.data_folder + '/example.csv')
        cls.uploads_folder = cls.config['uploads_folder']


    @classmethod
    def tearDownClass(cls):
        uploaded_files = os.listdir(cls.config['uploads_folder'])
        test_files = os.listdir(cls.config['data_folder'])
        for file in uploaded_files:
            if file in test_files:
                try:
                    os.remove(os.path.abspath(file))
                except OSError:
                    return

    def test_reject_invalid_token(self):
        pass


    def test_streaming(self):
        headers = { 'X-Filename': 'streamed-example.csv', 'Authorization': 'Bearer ' + TOKEN }
        resp = requests.post(self.base_url + '/stream', data=lazy_file_reader(self.file_to_stream), headers=headers)
        # assert all the things!

def main():
    runner = unittest.TextTestRunner()
    suite = []
    suite.append(unittest.TestSuite(map(TestFileApi, ['test_reject_invalid_token', 'test_streaming'])))
    map(runner.run, suite)

if __name__ == '__main__':
    main()

