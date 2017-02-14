
## tsd-file-api

A REST API for upload and download of files, authenticated by JWT.

```
./uwsgi --ini app-conf.ini --pyargv <config-file.yaml>
# start nginx with config
curl -i --form "file=@t.csv;filename=t.csv" http://localhost:8080/upload
```
