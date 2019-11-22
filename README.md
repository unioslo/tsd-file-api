
# tsd-file-api

A REST API for upload and streaming of files to TSD.

## Dev environment

1) Install the Auth API
2) Install the File API

```bash
git clone ssh://git@bitbucket.usit.uio.no:7999/tsd/tsd-file-api.git
cd tsd-file-api
pip3 install -r requirements.txt
# make sure you have gpg installed
# import the test keys
gpg --import tsdfileapi/keys/public.pem
gpg --import tsdfileapi/keys/private.pem
# create local upload dirs
mkdir -p /tmp/p12/data/durable/api
mkdir -p /tmp/p11/fx/import_alt/lanthir
mkdir -p /tmp/p11/fx/import/sns-test
# create config files, see tsdfileapi/config/file-api-config.yaml.example
python3 tsdfileapi/api.py test-config.yaml
python3 tsdfileapi/test_file_api.py test-config.yaml
```

## Build and release

```bash
git clone ssh://git@bitbucket.usit.uio.no:7999/tsd/tsd-file-api.git
cd tsd-file-api
docker build -t tsd:fileapi .
export id=$(docker create tsd:fileapi)
docker cp $id:/file-api/dist/ .
```
