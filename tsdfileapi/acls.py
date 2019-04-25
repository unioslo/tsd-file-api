
"""Access control config for nettskjema and generic sqlite table endpoints."""

NETTSKJEMA_ACL = {
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

GENERIC_ACL = {
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

ACLS = {
    'nettskjema': NETTSKJEMA_ACL,
    'generic': GENERIC_ACL
}
