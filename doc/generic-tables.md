
# Generic tables with sqlite and json1

* [json1 extension](https://www.sqlite.org/json1.html)

## methods and endpoints

### Generic data

For data:
```txt
GET /v1/pXX/tables/generic
GET /v1/pXX/tables/generic/mytable
PUT /v1/pXX/tables/generic/mytable
PATCH /v1/pXX/tables/generic/mytable
DELETE /v1/pXX/tables/generic/mytable
```
For metadata:
```txt
GET /v1/pXX/tables/generic/metadata
GET /v1/pXX/tables/generic/metadata/mytable
PUT /v1/pXX/tables/generic/metadata/mytable
PATCH /v1/pXX/tables/generic/metadata/mytable
DELETE /v1/pXX/tables/generic/metadata/mytable
```

### Nettskjema

For data:
```txt
GET /v1/pXX/tables/nettskjema
GET /v1/pXX/tables/nettskjema/mytable
PUT /v1/pXX/tables/nettskjema/mytable
PATCH /v1/pXX/tables/nettskjema/mytable
DELETE /v1/pXX/tables/nettskjema/mytable
```
For metadata:
```txt
GET /v1/pXX/tables/nettskjema/metadata
GET /v1/pXX/tables/nettskjema/metadata/mytable
PUT /v1/pXX/tables/nettskjema/metadata/mytable
PATCH /v1/pXX/tables/nettskjema/metadata/mytable
DELETE /v1/pXX/tables/nettskjema/metadata/mytable
```
Requirements, for backward compatility:
- JSON data should be flat, no nesting
- each record should contain a unique submission ID, identified by a key called `_id`
- each record should contain a `formid` field

## features

- one column, json storage
- protection against duplicate entries
- query language: subset of http://postgrest.org/en/v5.2/api.html#

## access control

Each instance of the handler must specify access control rules

For Nettskjema:
- user has to choose who is a member of pXX-nettskjema-admin-group, this could default to e.g. all project members
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
