
# Generic tables with sqlite and json1

* [json1 extension](https://www.sqlite.org/json1.html)

## methods

```txt
GET /v1/pXX/tables/generic
GET /v1/pXX/tables/generic/mytable
PUT /v1/pXX/tables/generic/mytable
PATCH /v1/pXX/tables/generic/mytable
DELETE /v1/pXX/tables/generic/mytable
```

## features

- one column, json storage
- protection against duplicate entries
- query language: subset of http://postgrest.org/en/v5.2/api.html#

## access control

Each instance of the handler must specify access control rules

For Nettskjema:
- user has to choose who is a member of pXX-nettskjema-admin-group
- this determines who can:
    - edit and delete data,
    - edit table metadata
- internal API access only for TSD processes

The full ACL is:
```json
{
    "access": {
        "data": {
            "external": {
                "GET": ["data_owner", "nettskjema_admin_user"],
                "PUT": ["data_owner", "import_user"],
                "PATCH": ["data_owner", "nettskjema_admin_user"],
                "DELETE": ["nettskjema_admin_user"]
            },
            "internal": {
                "GET": ["admin_user"],
                "PUT": ["admin_user"],
                "PATCH": ["admin_user"],
                "DELETE": ["admin_user"]
            },
        "metadata": {
            "external": {
                "GET": ["import_user", "nettskjema_admin_user"],
                "PUT": ["import_user"],
                "PATCH": ["nettskjema_admin_user"],
                "DELETE": ["admin_user"]
            },
            "internal": {
                "GET": ["admin_user"],
                "PUT": ["admin_user"],
                "PATCH": ["admin_user"],
                "DELETE": ["admin_user"]
            }
        }
}
```

For generic project use:

```json
{
    "access": {
        "data": {
            "external": {
                "GET": ["export_user", "data_owner"],
                "PUT": ["import_user"],
                "PATCH": ["export_user", "data_owner"],
                "DELETE": ["admin_user"]
            },
            "internal": {
                "GET": ["member_user"],
                "PUT": ["member_user"],
                "PATCH": ["member_user"],
                "DELETE": ["admin_user"]
            },
        "metadata": {
            "external": {
                "GET": ["import_user"],
                "PUT": ["import_user"],
                "PATCH": ["import_user"],
                "DELETE": ["admin_user"]
            },
            "internal": {
                "GET": ["admin_user"],
                "PUT": ["admin_user"],
                "PATCH": ["admin_user"],
                "DELETE": ["admin_user"]
            }
        }
}
```
