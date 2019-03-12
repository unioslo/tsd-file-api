
## Access control on uploads

The file API writes request data to: `/tsd/pXX/data/durable/file-api`. This folder has the following permissions: `p01-fileapi-user:pXX-member-group`. Data is written as `-rw-------`, so when the file API is done writing to disk, no group members have access yet.

When finished, the file API invokes a data handler, passing along group information supplied by the HTTP client. If no group informaiton was supplied, it defaults to `pXX-member-group`. This handler is invoked with `sudo`. The `p01-fileapi-user` is given the right to invoke this with `sudo` by way on an entry in a sudoers file.

The handler does two things: 1) it moves the data to a group folder `/tsd/pXX/data/durable/file-api/pXX-group-name`. Group folders have the following permissions: `p01-fileapi-user:pXX-group-name`. The uploaded file(s) permissions are set to: `pXX-tsd-user:pXX-group-name`, that is, the identity of the person who uploaded the file becomes the owner. 2) Lastly, the data handler changes the mode of the data from `-rw-------` to `-rw-rw----`.

Now the members of the group in question can read, write, move and delete the data as they please, and the person who initiated the upload is the owner.

## Policy

The default access policy for uploads is: no access if something breaks, member group access if nothing is specified. This ensures that if the pipeline fails along the way, unauthorized data access is not inadvertedly granted. Since all uploads are idempotent (can be perfomed many times without modifying the resource), users can redo the upload to fix the error.
