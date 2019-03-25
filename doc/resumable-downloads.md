
## Resumable downloads

Or, how to perform conditional range requests, per file.

## Starting a resumable download

Clients can get resource information before starting a download as follows:

```txt
HEAD /files/export/filename
```

The server will return an `Etag` header, containing an ID which uniquely identifies the resource content. Addtionally, the server will return the `Content-Length` in bytes. Clients can store the `Etag` to make sure that if they resume a download, they can check with the server that the resource has not changed in the meantime.

Downloads are started as usual:

```txt
GET /files/export/filename
```

## Resuming a partially complete download

If a download is paused or fails before completing, the client can count the number of bytes in the local partial download, and request the rest from the server, using the `Range` header. _Importantly, range requests specify ranges with a 0-based index. So if the client already has 103 bytes of a file (bytes 0-102, with an 0-based index), and it wants the rest, then it should ask for_:

```txt
GET /files/export/filename
Range: bytes=103-
```

A specific index range can also be requested, if relevant:

```txt
GET /files/export/filename
Range: bytes=104-200
```

And to ensure resource integrity it is recommended that the value of the `Etag` ias included, thereby performing a conditional range request:

```txt
GET /files/export/filename
If-Ranfge: 0g04d6de2ecd9d1d1895e2086c8785f1
Range: bytes=104-
```

The server will then only send the requested range if the resource has not been modified.

## Not supported

* multipart range requests
