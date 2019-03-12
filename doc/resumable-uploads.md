
# Design for resumable uploads

Note: resume is implemented _per file_.

## HTTP Methods

```txt
GET /files/resumable
PATCH /files/resumable/file?chunk=<chunknum,end>&id=<UUID>&group=<group-name>
```

## 1. Starting a new resumable upload

The client, having chunked the file, starts by initiating a PATCH, uploading the first chunk:

```txt
PATCH /files/resumable/filename?chunk=<num>

{filename: str, max_chunk: int, chunk_size: int, id: uuid}
```

Using the UUID returned by the server in the response, the client can continue sending succesive chunks, in sequence:

```txt
PATCH /files/resumable/filename?chunk=<num>&id=<UUID>

{filename: str, max_chunk: int, chunk_size: int, id: uuid}
```


## 2. Resuming prior uploads

The client can optionally make a GET request to get a list of uploads which are available to resume:

```txt
GET /files/resumable

{
    resumables: [
        {filename: str, max_chunk: int, chunk_size: int, id: uuid}
    ]
}
```

Each resumable upload has:
- a filename
- a chunk number
- a chunk size
- a UUID

The combination of the filename and UUID allow the client to resume an upload of a specific file for a specific prior request. The chunk size and number allow the client to seek locally in the file before sending more chunks to the server, avoiding sending the same data more than once.

The client then proceeds as follows:

```txt
PATCH /files/resumable/filename?chunk=<num>?id=<UUID>

{filename: str, max_chunk: int, chunk_size: int, id: uuid}
```

## 3. Completing an upload

To finish the upload the client must explicitly indicate that the current chunk marks the `end` of the sequence:

```txt
PATCH /files/resumable/filename?chunk=end?id=<UUID>?group=<group-name>
```

This will tell the server to assemble the final file. Setting the group is optional as normal.

## Implementation

### Server

When a new resumable request is made, the server generates a new UUID, and creates a directory with the name of that UUID which will contain the successive chunks, and writes each chunk to its own file in that directory, e.g.:

```txt
/cb65e4f4-f2f9-4f38-aab6-78c74a8963eb
    /filename.txt.cb65e4f4-f2f9-4f38-aab6-78c74a8963eb.chunk.1
    /filename.txt.cb65e4f4-f2f9-4f38-aab6-78c74a8963eb.chunk.2
    /filename.txt.cb65e4f4-f2f9-4f38-aab6-78c74a8963eb.chunk.3
```

Once the client has sent the final chunk in the sequence, the server will merge the chunks, move the merged file to its final destination, remove the chunks, their accumulating directory, and respond to the client that the upload is complete.

### Clients

Client are expected to split files into chunks, and upload each one as a separate request, _in order_. Since the server will return information about chunk size, and the last chunk sequence number, the client does not have to keep state if and when a resumable file upload fails.

If a resumable upload fails, the client can, before initiating a new resumable request for a file, ask the server whether there is a resumable for the given file. If so, it will recieve the chunk size and sequence numner, and the UUID which identifies the upload. Using this, the given file upload can be resumed. The client chunks the file, seeks to the relevant part, and continues the upload.

When uploading the last chunk, the client must explicitly indicate that it is the last part of the sequence.
