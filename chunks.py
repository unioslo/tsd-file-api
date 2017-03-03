
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

"""
import logging
import httplib
import requests
import string
import time
import sys

httplib.HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

def lazy_file_reader():
    # TODO: create a test file in repo
    # create a test upload location
    with open('blamo.csv', 'r+') as f:
        while True:
            line = f.readline()
            if line == '':
                break
            else:
                yield line

# TODO choose either directly against tornado or via nginx
# depending on what you want to test
url1 = 'http://localhost:8888/stream'
url2 = 'http://localhost:8888/upload'
url3 = 'http://localhost:8080/stream'

# get a token
filename = '' # TODO
token = 'Bearer TOKEN' # TODO
headers = {}

headers = { 'X-Filename': filename, 'Authorization': token }

resp = requests.post(url1, data=lazy_file_reader(), headers=headers)
print resp.text
