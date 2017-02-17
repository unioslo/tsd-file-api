
## tsd-file-api

A REST API for upload and download of files, authenticated by JWT.

```
./uwsgi --ini app-conf.ini --pyargv <config-file.yaml>
# start nginx with config
# to upload a plain text file
curl -i --form "file=@t.csv;filename=t.csv" http://localhost:8080/upload
# to upload a PGP encrypted file
curl -i --form 'file=@t.csv.asc;filename=t.csv.asc' -H 'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"' http://localhost:8080/upload
```
