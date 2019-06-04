
## Background

- https://github.com/minio/mc/blob/83a9d8b91d0b4c61883442a50c2e990cb0bdc3be/cmd/mirror-main.go
- https://stackoverflow.com/questions/43529926/how-does-aws-s3-sync-determine-if-a-file-has-been-updated
- https://docs.aws.amazon.com/cli/latest/reference/s3/sync.html

## Implementation draft

```txt
GET /sync -> {dirs}
HEAD /sync/dir -> {directorytree with etags}
GET /resumables -> {resumables}
upload (diff = remote:local -> uploadables, deletables), resume if resumable
PUT /files/stream/dir/file
```
## Implementation plan

1. dir1/file1 - one file including a directory path, with resume
2. dir1/file1, dir1/file2 - more than one file including a directory path, with resume
3. #2, uploading modified or new files
4. #3, with removal of files no longer present

## cmd-line UI

`tacl --sync mydir --with-delete`, delete being optional.
