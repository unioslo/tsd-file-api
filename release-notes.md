
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
