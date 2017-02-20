
# tsd-file-api

A REST API for upload and download of files, authenticated by JWT.

## Development information

```bash
./uwsgi --ini app-conf.ini --pyargv <config-file.yaml>
# start nginx with config
# to upload a plain text file
curl -i --form "file=@t.csv;filename=t.csv" http://localhost:8080/upload
# to upload a PGP encrypted file
curl -i --form 'file=@t.csv.asc;filename=t.csv.asc' -H 'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"' http://localhost:8080/upload
```

Note on curl example: `--form` This causes curl to POST data using the Content-Type multipart/form-data according to RFC 2388.

## Usage as a standalone service

Authentication and authorization is the same as for the storage and retrieval APIs. Different user credentials are required for writing and reading files. After signing up, a TSD admin must verify the user before they can get an access  token. When that is done, a token can be requested. The upload token lasts 24 hours while the download token lasts only for one hour. Files are limited to 100MB (unless requested otherwise).

### Example: uploading files

Suppose we are working with a file named `file.ext` and that the API is available at URL `url`.

```bash
curl http://url/upload_signup --request POST -H "Content-Type: application/json" --data '{ "email": "your.email@whatever.com", "pass": "your-password"  }'
curl http://url/upload_token --request POST -H "Content-Type: application/json" --data '{ "email": "your.email@whatever.com", "pass": "your-password"  }'
```

The API caters for both plain-text and PGP encrypted files. Clients can upload plain-text file as follows, using the `multipart/form-data` [MIME type](https://tools.ietf.org/html/rfc1341):

```bash
curl -i --form 'file=@file.ext;filename="file.ext"' -H "Authorization: Bearer $token" -H "Content-Type: multipart/form-data" http://url/upload
```

This curl-based example emulates uploading a file from a web form.

PGP encrypted files are also supported. Client are recommended to use the `multipart/encrypted` Content-Type header described in [rfc1847](https://tools.ietf.org/html/rfc1847) and elaborated for PGP in [rfc3156](https://tools.ietf.org/html/rfc3156). Doing so will allow the API to initiate processing, such as decryption, on behalf of the client.

```bash
curl -i --form 'file=@file.ext.asc;filename=file.ext.asc' -H 'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"' http://url/upload
```

### Example: downloading files

```bash
curl http://url/download_signup --request POST -H "Content-Type: application/json" --data '{ "email": "your.email@whatever.com", "pass": "your-password"  }'
curl http://url/download_token --request POST -H "Content-Type: application/json" --data '{ "saml_data": <saml_data> }'
# downloading a file
curl http://url/download/file.ext --request GET -H "Authorization: Bearer <token>"
```

## Usage in combination with tsd-data API (storage and retrieval APIs).

See [link to docs](LINK!).
