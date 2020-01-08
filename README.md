
# tsd-file-api

A REST API for upload and streaming of files to TSD.

## Dev environment

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
# create a config file,
# see tsdfileapi/config/example-file-api-config.yaml
python3 tsdfileapi/api.py test-config.yaml
python3 tsdfileapi/test_file_api.py test-config.yaml
```

## Build and release

```bash
git clone ssh://git@bitbucket.usit.uio.no:7999/tsd/tsd-file-api.git
cd tsd-file-api
./buid.sh
```
New rpms will be in `tsd-file-api/dist`.

## Notes

The API calls `chmod` on uploaded files, so will need the following entry in `/etc/sudoers.d/fileapiuser`:

```txt
fileapiuser ALL = (ALL) NOPASSWD: /usr/bin/chmod
```

And similar entries for any other scripts which may be called as request hooks, as sudo.
