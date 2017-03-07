
## Handling large files

There are roughly 5 methods, with varying applicability according to client capabilities and file size:

1. Transfer-Encoding: chunked, [ref](https://en.wikipedia.org/wiki/Chunked_transfer_encoding) and [rfc ref](https://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html)
2. PATCH resources using --data-binary along with `Content-Type: application/octet-stream`
3. Ignore `Content-Length` in nginx, use WSGI-Flask stream as above
4. _exploratory_: uwsgi option `--http-chunked-input`
5. _exploratory_: HTTP2?

Considerations:

* Option #1: requires some work on the client and server side; suitable for browser-based uploads since JS libraries offer chunking support, [Flask ref](https://stackoverflow.com/questions/15040706/streaming-file-upload-using-bottle-or-flask-or-similar) - note this does multiple requests including a different `Content-Range` in each request

* Option #2: this works well programmatically (with curl e.g.), data is read and written byte-for-byte unaltered, if nginx sets a limit to Content-Length then the client would have to repeatedly PATCH the same resource (i.e. append to a file), this would be, in effect, client-side chunking of binary data, a sort of buffering [Flask ref](https://blog.pelicandd.com/article/80/streaming-input-and-output-in-flask)

* Option #3: this is much like #2 but would allow clients to upload files up to e.g. 10GB within 3 minutes without having to chunk or PATCH anything, the larger the data, the more critical it is to keep the HTTP connection alive though, so there will be some point at which this becomes impractical; and you still need to know the content length before making the request, otherwise the stream will not be processed correctly; this adds a bit of work for the client, or requires access to enough memory

* Option #4: [ref1](https://uwsgi-docs.readthedocs.io/en/latest/Chunked.html), [ref2](https://github.com/unbit/uwsgi/issues/798)

* Option #5: To be explored

## File uploads using WSGI-Flask stream

## Current timing using the Flask wsgi stream

```
basic local timings
-------------------
gb  sec     diff
--  ---     ----
2   10      -
3   40      30
4   55      25
5   75      20
6   85      10
7   98      13
8   114     16
9   132     18
10  180     48

so ~15s per GB, roughly linear perf, I think curl reads it all into memory before posting
This still requires knowing the Content-Length before the request though
This also requires setting client_max_body_size to 0 which means ignoring Content-Length in nginx
Don't think we can allow all clients to do this by default
Additionally you could patch theses resources
```

## Content-Length and chunked transfer encoding

* https://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.4
    * If Transfer-Encoding is present Content-Length must be ignored
    * "If a Transfer-Encoding header field (section 14.41) is present and has any value other than "identity", then the transfer-length is defined by use of the "chunked" transfer-coding (section 3.6), unless the message is terminated by closing the connection."
        * So it is valid to keep writing a stream until the connection is closed?
    * "If multiple encodings have been applied to an entity, the transfer- codings MUST be listed in the order in which they were applied."
    * [multipart/byteranges](https://www.w3.org/Protocols/rfc2616/rfc2616-sec19.html#sec19.2) - a self-delimiting media type
* [transfer codings](https://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.6)
    * chunks have their own size indicators
* from the client side with python
    * http://docs.python-requests.org/en/master/user/advanced/#chunk-encoded-requests
    * https://stackoverflow.com/questions/17661962/how-to-post-chunked-encoded-data-in-python

## Performance tuning

* nginx
    * https://www.nginx.com/blog/tuning-nginx/
    * client_body_buffer_size, client_max_body_size, client_body_timeout
    * https://github.com/pgaertig/nginx-big-upload
* uwsgi
    * num workers, num threads
    * depends on num CPUs
    * https://blog.codeship.com/getting-every-microsecond-out-of-uwsgi/

## Future/ideas

* in general, use [Entity Header Fields](https://www.w3.org/Protocols/rfc2616/rfc2616-sec7.html#sec7.2.2) to describe characteristics about the file before sending it
* use transfer codings to build complex pipelines
    * e.g. encrypt, compress, chunk --> transport --> assemble, decompress, decrypt
* https://mrjoes.github.io/2013/06/21/python-realtime.html
* support posting multiple files in same request
* gzip compression
    * https://stackoverflow.com/questions/28304515/receiving-gzip-with-flask
    * https://github.com/cralston0/gzip-encoding
    * https://github.com/cralston0/gzip-encoding/blob/master/flask/middleware.py
    * looks like gzip.io provides streaming tools
* HTTP2
    * SPDY as point of departure
    * https://bagder.gitbooks.io/http2-explained/content/en/
    * https://hyper.readthedocs.io/en/latest/
    * https://nghttp2.org/
    * https://github.com/http2/http2-spec/wiki/Implementations
* Websockets (doesnt seem appropriate)
    * https://www.fullstackpython.com/websockets.html
        * full duplex, server push
        * Tornado, Autobahn
    * http://lucumr.pocoo.org/2012/9/24/websockets-101/
        * suitable only for browsers, otherwise just use raw TCP
* RTMP
    * video streaming: https://github.com/arut/nginx-rtmp-module
* Coordinate with Marcin (PRACE (HTTP2, pipelines)/CEES)
* asynchronous workers, notifications
* establish long-lived http connections (e.g. long polling), don't respond until EOF is received

## Other references

* [overview of HTTP streaming](https://gist.github.com/CMCDragonkai/6bfade6431e9ffb7fe88)
* https://github.com/blueimp/jQuery-File-Upload
* https://stackoverflow.com/questions/16268491/python-web-framework-capable-of-chunked-transfer-encoding
* http://kristi.nikolla.me/2016/08/21/wsgi-chunked-transfer-requests/
* on realtime
    * http://lucumr.pocoo.org/2012/8/5/stateless-and-proud/
    * process request data onto queues, keep TCP connections alive
* [rfc for form-based file uploads](https://tools.ietf.org/html/rfc1867)
    * metions deferred file transmission - hints that content-length may not be required


## Auth

* separate auth server? impl?
    * https://www.nginx.com/resources/admin-guide/restricting-access-auth-request/

## Tornado

* http://www.tornadoweb.org/en/stable/guide/running.html?highlight=nginx
* [stream processing with tornado](https://gist.github.com/bdarnell/5bb1bd04a443c4e06ccd)

## Use cases

1. Nettskjema attachments
2. Medical instrument data (Alex Rowe)
3. Streaming video
4. Video file posing
5. CEES (Marcin)
