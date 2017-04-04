
# tsd-file-api

A REST API for upload and streaming of files to TSD, authenticated by JWT.

## timings

Some initial indications of performance.

```
30mb
----
stream:
from test-tsd-backend01:       2s

upload:
from test-tsd-backend01:       3s

500mb:
-----
upload:
from test-tsd-backend01:       32s

stream:
from test-tsd-backend01:       7s

1gb
---
stream:
on localhost                   6s
from test-tsd-backend01:      32s
from KT's machine:          1m30s
over wifi:                  4m36s
```

Therefore, highly network dependent, your mileage may vary depending on where you are.
