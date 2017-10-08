
# tsd-file-api

A REST API for upload and streaming of files to TSD, authenticated by JWT.

## Build and release

Download [VirtualBox](https://www.virtualbox.org/wiki/Downloads) and [vagrant](https://www.vagrantup.com/downloads.html)

```
git clone ssh://git@bitbucket.usit.uio.no:7999/tsd/tsd-file-api.git
cd tsd-file-api
vagrant up
```

This will build two rpms and place them in the repo directory:
- tsd-file-api-venv
- python-tsd-file-api

Releasing them is a manual process.

## Performance notes

Some initial indications of performance.

```
30mb                        upload  stream
----
from test-tsd-backend01:       3s       2s

500mb:
-----
from test-tsd-backend01:       32s      7s

1gb
---
on localhost                            6s
from test-tsd-backend01:               32s
from KT's machine:                   1m30s
over wifi:                           4m36s
```

Therefore, highly network dependent, your mileage may vary depending on where you are.
