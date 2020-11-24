
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

## Docker Dev environment

Fork the repository on https://github.com/unioslo/tsd-file-api.git and
clone the repository to your development machine and configure it:

    git clone https://github.com/<YOUR_USER>/tsd-file-api.git

Run the containers using docker-compose:

    cd tsd-file-api
    docker-compose --file  docker-compose.yml up -d

And verify that it is running properly:

    $ docker ps
    CONTAINER ID   IMAGE              COMMAND                  CREATED          STATUS          PORTS                    NAMES
    82a1557b9d3d   tsd-file-api       "/bin/sh -c 'python3…"   11 minutes ago   Up 11 minutes   0.0.0.0:3004->3003/tcp   tsd-file-api_tsd-file-api_1
    f7d337ea3d64   tsd-file-api-dev   "/bin/sh -c 'python3…"   11 minutes ago   Up 11 minutes   0.0.0.0:3003->3003/tcp   tsd-file-api_tsd-file-api-dev_1

To run the tests:

    docker exec -it tsd-file-api_tsd-file-api-dev_1  /bin/sh
    python3 ~/tsd-file-api/tsdfileapi/test_file_api.py /etc/tsd/tsd-file-api/config-test.yaml  all

## Build rpms

```bash
# clone the repo
cd tsd-file-api
./build.sh
```
New rpms will be in `tsd-file-api/dist`.
