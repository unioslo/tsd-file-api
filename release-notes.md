
# v0.2.1

- bugfix for untar pipeline

# v0.2.0

- introduces stream processing pipelines, triggered by custom Content-Type headers
    - direcories:
        - tar           -> untar
        - tar.gz        -> decompress, untar
        - tar.aes       -> decrypt, untar
        - tar.gz.aes    -> decrypt, uncompress, untar
    - Files:
        - aes           -> decrypt
        - gz            -> uncompress
        - gz.aes        -> decrypt, uncompress

# v0.1.1

- update JWT validation to match new claims issued from auth-api v0.4.2
- anly allows the following roles: import_user, export_user, admin_user

# v0.1.0

- first release: HTTP API for storing data in files and sqlite in TSD
- core data storage functionality
    - JSON data
        - sqlite backend
        - optional PGP encrypted payloads
        - table creation using nettskjema or generic definitions
        - ability to extend tables with more columns
    - streaming data, e.g. video
        - video uploads with HTTP chunked transfer encoding
    - file uploads
        - form-based uploads
        - multipart form-based uploads
        - streaming binary data
- authentication and authorization with JWT
