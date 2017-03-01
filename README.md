
# tsd-file-api

A REST API for upload and streaming of files to TSD, authenticated by JWT.

## Background

The API conventions are established with reference to the [HTTP 1.1](https://tools.ietf.org/html/rfc7230) and [MIME Conformance Critera](https://tools.ietf.org/html/rfc2045) RFCs. A good starting point for developers who want background on HTTP and who are integrating with the API is [Mozilla's Developer Network guide](https://developer.mozilla.org/en-US/docs/Web/HTTP).

## Authentication and authorization

Authentication and authorization is based on [JSON Web Tokens](https://jwt.io/). An API client must sign up with a username and password. This will be approved by a TSD administrator. After approval, a token can be requested. The token, which is cryptographically signed and encrypted, contains information about the role and privileges assigned to the client. These are evaluated by the API on each request to determine if the authenticated client is allowed to perform the action. Upload tokens lasts 24 hours.

```bash
curl http://url/upload_signup --request POST -H "Content-Type: application/json" --data '{ "email": "your.email@whatever.com", "pass": "your-password"  }'
curl http://url/upload_token --request POST -H "Content-Type: application/json" --data '{ "email": "your.email@whatever.com", "pass": "your-password"  }'
```

## Choosing the appropriate HTTP verb

Concerning file uploads, there are two general types of operations a client can perform via the API:

1. Create a new file (or replace an existing file)
2. Append to an existing file
3. Stream content

Creating and replacing files are the same operation for the API: to initiate this the client performs a HTTP `PUT` operation on the appropriate endpoint, naming the resource (filename) in question. This operation is idempotent - that is, if you `PUT` the same data multiple times to the same filename, the contents will not change.

Appending to a file is accomplished by performing either HTTP `POST` (which is _not_ idempotent) or `PATCH`. This is useful when uploading different parts of the same file in different HTTP requests. By doing a `POST` or a `PATCH`, the client is deliberately _modifying_ a resource. The API provides no idempotency guarantees when clients perform `POST` or `PATCH`.

Streaming content is accomplished by initiation a `POST` or `PATCH` with `Transfer-Encoding: chunked`. Incoming data is written to a filename specified by the client.

## Two endpoints for uploading files

Each tsd project will have a limitation on the size of the data that can be included in a single HTTP request. These limits will be influenced by how the API is used, how many requests are made and so on. They will also be different depending on whether the API is used to upload files as form data (typically from browsers) or simply as binary data (typically from programs). Two endpoints are aviablable, each designed to handle a different primary `Content-Type`.

### /upload

Web apps running in the browser will typically use this endpoint. This endpoint accepts:

* files uploaded in a single request using `Content-Type: multipart/form-data` and
* chunked files uploaded in multiple requests `Content-Type: multipart/form-data, Content-Range: bytes start-end/total`.

Many javascript libraries, such as [jQuery-File-Upload](https://github.com/blueimp/jQuery-File-Upload/wiki/Options) will create file chunks and set the `Content-Range` on your behalf. Note that this generates a separate HTTP request for each chunk.

Files that are not chunked can be uploaded using `PUT` since no modification is necessary (at least initially). Files that are uploaded in chunks must be uploaded using either `POST` or `PATCH` since the incoming chunks will be appended to already uploaded ones. A natural choice for chunking would be to stay below the allowed maximum data size allowed in a single request.

### /stream

This endpoint is designed for programmatic use, but can also be use from the browser. It accepts:

* File data with `Content-Type: application/octet-stream`

Clients that upload file data to this endpoint should do no pre-processing whatsoever, since the server will write incoming data to a file, as is, byte-for-byte. Since no parsing is done it is more efficient than `/upload`. The maximum amount of data that is allowed in a single request to this endpoint will typically be higher. Files in excess of 10GB, for example, can be uploaded via this endpoint by chunking the file and doing a series of `PATCH` requests to the same resource.

## Examples

### Example: uploading files

Current allowed file types are: `'txt', 'pdf', 'png', 'jpg', 'jpeg', 'csv', 'tsv', 'asc'`.

Suppose we are working with a file named `file.ext` and that the API is available at URL `url`.



The API caters for both plain-text and PGP encrypted files. Clients can upload plain-text file as follows, using the `multipart/form-data` [MIME type](https://tools.ietf.org/html/rfc1341):

```bash
curl -i --form 'file=@file.ext;filename="file.ext"' -H "Authorization: Bearer $token" -H "Content-Type: multipart/form-data" http://url/upload
```

This curl-based example emulates uploading a file from a web form.

PGP encrypted files are also supported. Clients are recommended to use the `multipart/encrypted` Content-Type header described in [rfc1847](https://tools.ietf.org/html/rfc1847) and elaborated for PGP in [rfc3156](https://tools.ietf.org/html/rfc3156). Doing so will allow the API to initiate processing, such as decryption, on behalf of the client.

```bash
curl -i --form 'file=@file.ext.asc;filename=file.ext.asc' -H "Authorization: Bearer $token" -H 'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"' http://url/upload
```

### Example: large files and streaming

Large files can be uploaded as binary data. Incoming request data are written to a file byte-for-byte, in order. No data processing is done. All incoming bytes are preserved and written to a file as is. If a file is being streamed, for example, it is the client's responsibilty to construct the binary stream correctly, so that when the bytes are written to the file, data integrity will be preserved.

Cliets should provide a file name in a custom header: `X-Filename: <filename>`. If no filename is provided the current ISO 8601 timestamp will be chosen.

Nginx sets the maximum Content-Length allowed for the stream on a per request basis. If the data stream is smaller than the maximum Content-Length then a file can be streamed using POST:

``` bash
curl -X POST --data-binary @file -H "Authorization: Bearer $token" -H 'Content-Type: application/octet-stream' \
    -H 'X-Filename: filename' http://url/stream
```

If the data stream exceeds maximum Content-Length then data can be sent in consecutive streams, in separate requests. Incoming streams are appended to each other, byte-for-byte. Suppose a large file is split into two files (file1 and file2), clients can send streams to the same file using PATCH:

```bash
curl -X PATCH --data-binary @file1 -H "Authorization: Bearer $token" -H 'Content-Type: application/octet-stream' \
    -H 'X-Filename: filename' http://url/stream

curl -X PATCH --data-binary @file2 -H "Authorization: Bearer $token" -H 'Content-Type: application/octet-stream' \
    -H 'X-Filename: filename' http://url/stream
```

In this case the filename _must_ be provided, otherwise the streams will end up in separate files.

### To upload arbitrarily large files

In nginx.conf, set `client_max_body_size 0;` - this will make nginx ignore `Content-Length`. The input will be buffered and sent to the file-api which will handle the incoming stream in chunks and write it to a file.

### Checking data integrity

There are two ways to get checksum information about data stored in files: firstly, the client can request it for a file that has already been uploaded:

```bash
curl http://url/integrity/<filename> -H "Authorization: Bearer $token"
```

Secondly, when streaming binary data, if the client sends the `X-Checksum: md5sum` custom header in the request, a rolling checksum will be calculated and the hexdigest will be return upon completing the request. This is a bit slower but could be useful when pipelining many requests to the same file destination.

```bash
curl -X POST --data-binary "@1gb.txt" -H "Authorization: Bearer $token"  -H "Content-Type: application/octet-stream" \
    -H "X-Filename: 1gb.txt" -H "X-Checksum: md5sum" http://url/stream
# response
{
  "md5sum": "acd2770ddba692c3b1590c7a2c97f487",
  "message": "file uploaded"
}
```

### Getting file metadata

Clients typically want to know which files have been stored and when. This information is available to users who authenticate with upload and/or download tokens.

```bash
curl http://url/list -H "Authorization: Bearer $token"
```

The result will show an alphabetical order of files along with the latest time of content modification.

