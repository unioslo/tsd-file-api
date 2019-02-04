[Unit]
 Description= p01 minio object storage server (TSD s3 API)

 [Service]
 User=p01-s3api-user
 Group=p01-s3api-user-group
 ExecStart=/usr/local/bin/minio server --address localhost: --config-dir /tsd/p01/data/durable/s3-api-config/p01 /tsd/p01/data/durable/s3-api

 [Install]
 WantedBy=multi-user.target
now 1) start the service, and 2) add it to nginx
