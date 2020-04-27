
# tsd-file-api

A REST API for upload and download of files and JSON data.

## Dev environment

A _minimal_ dev environment can be set up as follows:
```bash
# get the latest release: https://github.com/unioslo/tsd-file-api/releases/latest
# extract from archive or unzip it
cd tsd-file-api
pip3 install -r requirements.txt
python3 tsdfileapi/api.py
```

## Build rpms

```bash
# clone the repo
cd tsd-file-api
./build.sh
```
New rpms will be in `tsd-file-api/dist`.
