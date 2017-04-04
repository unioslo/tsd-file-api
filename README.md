
# tsd-file-api

A REST API for upload and streaming of files to TSD, authenticated by JWT.

## timings

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
