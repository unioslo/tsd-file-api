
# Design for resumable uploads

Note: resume is implemented _per file_.

## HTTP Methods

```txt
GET /files/resumables
GET /files/resumables/filename?id=<UUID>
PATCH /files/stream/file?chunk=<chunknum,end>&id=<UUID>&group=<group-name>
DELETE /files/resumables/filename?id=<UUID>
```

## 1. Starting a new resumable upload

The client, having chunked the file, starts by initiating a PATCH, uploading the first chunk:

```txt
PATCH /files/stream/filename?chunk=<num>&group=<group-name>

{filename: str, max_chunk: int, id: uuid}
```

Using the UUID returned by the server in the response, the client can continue sending succesive chunks, in sequence:

```txt
PATCH /files/stream/filename?chunk=<num>&id=<UUID>&group=<group-name>

{filename: str, max_chunk: int, id: uuid, key: str}
```


## 2. Resuming prior uploads

GET requests provide information necessary to resume a file upload.

Firstly, to list all resumables for the authenticated user:

```txt
GET /files/resumables

{
    resumables: [
        {
            filename: str,
            max_chunk: int,
            chunk_size: int,
            id: uuid,
            pevious_offset: int,
            next_offset: <int,'end'>,
            md5sum: str,
            warning: str,
            group: str,
            key: str
        },
        {...}
    ]
}
```

Secondly, the client can optionally specify a given filename without an upload id, and the server will return the resumable with the most data on the server (if there is more than one):

```txt
GET /files/resumables/myfile

[resumables: [{...}, {...}]}
```

And lastly, the information for a speific upload can be requested by including the uplooad id in addition to the filename:

```txt
GET /files/resumables/myfile?id=<UUID>

{
    filename: str,
    max_chunk: int,
    chunk_size: int,
    id: uuid,
    pevious_offset: int,
    next_offset: <int,'end'>,
    md5sum: str
    warning: str,
    group: str,
    key: str
}
```

In this way, the GET endpoints provide the client a way to either discover previous uploads which can be resumed, or to get direct information.

Each resumable upload has:
- a filename
- a chunk number
- a chunk size
- a UUID
- previous offset (number of bytes sent so far minus the last chunk size)
- next offset (number of bytes sent so far, or an instruction to 'end' the sequence)
- chunk md5
- a warning message, for if data is inconsistent
- the group which will own the upload (can be used for granular access)

The combination of the filename and UUID allow the client to resume an upload of a specific file for a specific prior request. The chunk size and number allow the client to seek locally in the file before sending more chunks to the server, avoiding sending the same data more than once. The md5 digest of the latest chunk, combined with the offset information allow clients to verify chunk integrity.

The server will attempt to repair any data inconsistencies which may have arised due to server crashes or filesystem issues. If it cannot get the resumable data back into a consistent state, the `next_offset` field will be set to `end`. Client are recommended to either end the upload, or delete it.

Assuming data is consistent, the client then proceeds as follows:

```txt
PATCH /files/stream/filename?chunk=<num>?id=<UUID>&group=<group-name>

{filename: str, max_chunk: int, id: uuid, key: str}
```

## 3. Completing an upload

To finish the upload the client must explicitly indicate that the upload is finished by sending an empty request as such:

```txt
PATCH /files/stream/filename?chunk=end&id=<UUID>&group=<group-name>
```

This will tell the server to assemble the final file. Setting the group is optional as normal.

## 4. Cancelling an upload

To avoid wasting disk space, partially completed uploads which were not resumed to completion, and abandoned, can be removed as such:

```txt
DELETE /files/resumables/filename?id=<UUID>
```

## Implementation

### Server

When a new resumable request is made, the server generates a new UUID, and creates a directory with the name of that UUID which will contain the successive chunks, and writes each chunk to its own file in that directory, e.g.:

```txt
/cb65e4f4-f2f9-4f38-aab6-78c74a8963eb
    /filename.txt.chunk.1
    /filename.txt.chunk.2
    /filename.txt.chunk.3
```

Once the client has sent the final chunk in the sequence, the server will merge the chunks, move the merged file to its final destination, remove the chunks, their accumulating directory, and respond to the client that the upload is complete.

### Clients

Client are expected to split files into chunks, and upload each one as a separate request, _in order_. Since the server will return information about chunks, the client does not have to keep state if and when a resumable file upload fails, but it can if it wants to, since each request return enough information to resume the upload in the event of failure.

If a resumable upload fails and the client has lost track of the upload id, the client can, before initiating a new resumable request for a file, ask the server whether there is a resumable for the given file. If so, it will recieve the chunk size and sequence numner, and the UUID which identifies the upload. Using this, the given file upload can be resumed. The client chunks the file, seeks to the relevant part, and continues the upload.

When uploading the last chunk, the client must explicitly indicate that it is the last part of the sequence.
