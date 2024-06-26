import getpass
import os
import tempfile

HOME = os.path.expanduser("~")
td = tempfile.TemporaryDirectory()
TMP = td.name

_config = {
    "port": 3003,
    "debug": True,
    "test_project": "p11",
    "test_user": "p11-testing",
    "test_keyid": "264CE5ED60A7548B",
    "test_formid": "123456",
    "test_group": "p11-member-group",
    "data_folder": f"{os.getcwd()}/tsdfileapi/data",
    "test_folder": f"{os.getcwd()}/tsdfileapi/tests",
    "api_user": getpass.getuser(),
    "token_check_tenant": True,
    "token_check_exp": True,
    "disallowed_start_chars": "~",
    "requestor_claim_name": "user",
    "tenant_claim_name": "proj",
    "valid_tenant_regex": "^[0-9a-z]+$",
    "tenant_string_pattern": "pXX",
    "export_chunk_size": 512000,
    "max_body_size": 5368709120,
    "default_file_owner": "pXX-nobody",
    "create_tenant_dir": True,
    "jwt_test_secret": "jS25aQbePizfTsetg8LbFsNKl1W6wi4nQaBj705ofWA=",
    "jwt_secret": None,
    "allowed_symlinks": ["/var"],
    "nacl_public": {
        "public": "mZQEzkyi7bCvmDVfHGsU/7HX1+gT/R3PkSnyDU4OaiY=",
        "private": "fTEB1MZz8MskkZHSIM9ypxJc4e45Z8fmLGGXkUrp1hQ=",
    },
    "test_nacl_public": {
        "public": "mZQEzkyi7bCvmDVfHGsU/7HX1+gT/R3PkSnyDU4OaiY=",
        "private": "fTEB1MZz8MskkZHSIM9ypxJc4e45Z8fmLGGXkUrp1hQ=",
    },
    "test_nacl_secret": {
        "key": "rmsGmiADWiQHcq2n6+QUtTg0oWSxAlmEm4KRcpDWveE=",
    },
    "log_level": "info",
    "public_key_id": "264CE5ED60A7548B",
    "request_log": {
        "db": {
            "engine": "sqlite",
            "path": f"{TMP}/p11",
        },
        "backends": {
            "claims": ["name", "host", "pid"],
            "files_export": {"methods": ["GET", "DELETE"]},
        },
    },
    "backends": {
        "disk": {
            "publication": {
                "has_posix_ownership": False,
                "import_path": f"{TMP}/pXX",
                "export_path": f"{TMP}/pXX",
                "allow_export": True,
                "allow_list": True,
                "allow_info": True,
                "allow_delete": True,
                "export_policy": {
                    "default": {"enabled": False},
                },
                "group_logic": {
                    "default_url_group": None,
                    "default_memberships": ["pXX-member-group"],
                    "enabled": False,
                },
                "request_hook": {
                    "enabled": False,
                },
            },
            "apps_files": {
                "has_posix_ownership": False,
                "import_path": f"{TMP}/pXX/apps",
                "export_path": f"{TMP}/pXX/apps",
                "allow_export": True,
                "allow_list": True,
                "allow_info": True,
                "allow_delete": True,
                "allow_rpc": True,
                "export_policy": {
                    "default": {"enabled": False},
                },
                "group_logic": {
                    "default_url_group": None,
                    "default_memberships": ["pXX-member-group"],
                    "enabled": False,
                },
                "request_hook": {
                    "enabled": False,
                },
                "backup_deletes": {
                    "path_regex": "(/.+/apps/.+)/(files)(.*)",
                    "backup_days": 90,
                },
            },
            "survey": {
                "has_posix_ownership": False,
                "import_path": f"{TMP}/pXX/survey",
                "export_path": f"{TMP}/pXX/survey",
                "allow_export": True,
                "allow_list": True,
                "allow_info": True,
                "allow_delete": True,
                "allow_rpc": True,
                "request_hook": {
                    "enabled": False,
                },
                "group_logic": {
                    "default_url_group": "pXX-member-group",
                    "default_memberships": ["pXX-member-group"],
                    "enabled": False,
                    "ensure_tenant_in_group_name": False,
                    "valid_group_regex": "p[0-9]+-[a-z-]+",
                    "enforce_membership": False,
                },
                "export_policy": {
                    "default": {"enabled": False},
                },
                "backup_deletes": {
                    "path_regex": "(/.+/survey/[0-9]+)/(attachments)(.*)",
                    "backup_days": 90,
                },
            },
            "form_data": {
                "import_path": f"{TMP}/pXX/import",
                "request_hook": {"path": False, "sudo": False, "enabled": False},
            },
            "sns": {
                "import_path": f"{TMP}/pXX/data/durable/nettskjema-submissions/KEYID/FORMID",
                "subfolder_path": f"{TMP}/pXX/data/durable/nettskjema-submissions/.tsd/KEYID/FORMID",
                "request_hook": {"path": False, "sudo": False, "enabled": False},
            },
            "files_import": {
                "has_posix_ownership": True,
                "import_path": f"{TMP}/pXX/import",
                "export_path": f"{TMP}/pXX/import",
                "allow_export": True,
                "allow_list": True,
                "allow_info": True,
                "allow_delete": True,
                "export_policy": {
                    "default": {"enabled": False},
                },
                "group_logic": {
                    "default_url_group": "pXX-member-group",
                    "default_memberships": ["pXX-member-group"],
                    "enabled": True,
                    "ensure_tenant_in_group_name": True,
                    "valid_group_regex": "p[0-9]+-[a-zA-Z0-9-]+",
                    "enforce_membership": True,
                },
                "request_hook": {
                    "enabled": False,
                    "path": "/usr/local/bin/chowner",
                    "sudo": False,
                },
            },
            "files_export": {
                "has_posix_ownership": False,
                "import_path": f"{TMP}/pXX",
                "export_path": f"{os.getcwd()}/tsdfileapi/data/tsd/pXX/export",
                "allow_export": True,
                "allow_list": True,
                "allow_info": True,
                "allow_delete": True,
                "export_policy": {
                    "default": {"enabled": False},
                },
                "group_logic": {
                    "default_url_group": None,
                    "default_memberships": ["pXX-member-group"],
                    "enabled": False,
                },
                "request_hook": {
                    "enabled": False,
                },
            },
        },
        "dbs": {
            "apps_tables": {
                "db": {
                    "engine": "sqlite",
                    "path": f"{TMP}/pXX",
                    "table_structure": None,
                    "mq": None,
                },
                "table_structure": None,
            },
            "survey": {
                "db": {
                    "engine": "sqlite",
                    "path": f"{TMP}/pXX/survey",
                    "table_structure": None,
                    "mq": None,
                },
                "table_structure": [
                    "submissions",
                    "attachments",
                    "metadata",
                    "audit",
                    "tasks/definitions",
                    "tasks/deliveries",
                    "config",
                    "schemas/submissions",
                    "schemas/metadata",
                    "schemas/tasks",
                ],
                "backup_deletes": {
                    "backup_days": 90,
                },
            },
            "publication": {
                "db": {
                    "engine": "sqlite",
                    "path": f"{TMP}/pXX",
                    "table_structure": None,
                    "mq": None,
                },
                "table_structure": None,
            },
        },
    },
}
