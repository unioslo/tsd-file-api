
import getpass
import os
import shutil

HOME = os.path.expanduser("~")

_config = {
    'port': 3003,
    'debug': True,
    'test_project': 'p11',
    'test_user': 'p11-testing',
    'test_keyid': '264CE5ED60A7548B',
    'test_formid': '123456',
    'test_group': 'p11-member-group',
    'data_folder': f'{os.getcwd()}/tsdfileapi/data',
    'api_user': getpass.getuser(),
    'token_check_tenant': True,
    'token_check_exp': True,
    'disallowed_start_chars': '~',
    'requestor_claim_name': 'user',
    'tenant_claim_name': 'proj',
    'valid_tenant_regex': '^[0-9a-z]+$',
    'tenant_string_pattern': 'pXX',
    'export_max_num_list': 100,
    'export_chunk_size': 512000,
    'max_body_size': 5368709120,
    'default_file_owner': 'pXX-nobody',
    'create_tenant_dir': True,
    'jwt_test_secret': 'jS25aQbePizfTsetg8LbFsNKl1W6wi4nQaBj705ofWA=',
    'jwt_secret': None,
    'nacl_public': {
        'public': 'mZQEzkyi7bCvmDVfHGsU/7HX1+gT/R3PkSnyDU4OaiY=',
        'private': 'fTEB1MZz8MskkZHSIM9ypxJc4e45Z8fmLGGXkUrp1hQ='
    },
    'log_level': 'info',
    'gpg_binary': shutil.which("gpg"),
    'gpg_homedir': f'{HOME}/.gnupg',
    'gpg_keyring': f'{HOME}/.gnupg/pubring.gpg',
    'gpg_secring': f'{HOME}/.gnupg/secring.gpg',
    'public_key_id': '43FA347ED76EC595',
    'backends': {
        'disk': {
            'publication': {
                'has_posix_ownership': False,
                'export_max_num_list': None,
                'import_path': '/tmp/pXX',
                'export_path': '/tmp/pXX',
                'allow_export': True,
                'allow_list': True,
                'allow_info': True,
                'allow_delete': True,
                'export_policy': {
                    'default': {
                        'enabled': False
                    },
                },
                'group_logic': {
                    'default_url_group': None,
                    'default_memberships': ['pXX-member-group'],
                    'enabled': False,
                },
                'request_hook': {
                    'enabled': False,
                },
            },
            'apps_files': {
                'has_posix_ownership': False,
                'export_max_num_list': None,
                'import_path': '/tmp/pXX',
                'export_path': '/tmp/pXX',
                'allow_export': True,
                'allow_list': True,
                'allow_info': True,
                'allow_delete': True,
                'export_policy': {
                    'default': {
                        'enabled': False
                    },
                },
                'group_logic': {
                    'default_url_group': None,
                    'default_memberships': ['pXX-member-group'],
                    'enabled': False,
                },
                'request_hook': {
                    'enabled': False,
                },
            },
            "survey": {
                'has_posix_ownership': False,
                'export_max_num_list': None,
                "import_path": "/tmp/pXX/survey",
                'export_path': '/tmp/pXX/export',
                'allow_export': True,
                'allow_list': True,
                'allow_info': True,
                'allow_delete': True,
                'request_hook': {
                    'enabled': False,
                },
                'group_logic': {
                    'default_url_group': 'pXX-member-group',
                    'default_memberships': ['pXX-member-group'],
                    'enabled': True,
                    'ensure_tenant_in_group_name': False,
                    'valid_group_regex': 'p[0-9]+-[a-z-]+',
                    'enforce_membership': False
                },
                'export_policy': {
                    'default': {
                        'enabled': False
                    },
                },
            },
            "form_data": {
                "import_path": "/tmp/pXX/",
                "request_hook": {"path": False, "sudo": False, "enabled": False},
            },
            "sns": {
                "import_path": '/tmp/pXX/data/durable/nettskjema-submissions/KEYID/FORMID',
                "subfolder_path": '/tmp/pXX/data/durable/nettskjema-submissions/.tsd/KEYID/FORMID',
                "request_hook": {"path": False, "sudo": False, "enabled": False},
            },
            'files_import': {
                'has_posix_ownership': False,
                'export_max_num_list': None,
                'import_path': '/tmp/pXX',
                'export_path': '/tmp/pXX/export',
                'allow_export': True,
                'allow_list': True,
                'allow_info': True,
                'allow_delete': True,
                'export_policy': {
                    'default': {
                        'enabled': False
                    },
                },
                'group_logic': {
                    'default_url_group': 'pXX-member-group',
                    'default_memberships': ['pXX-member-group'],
                    'enabled': True,
                    'ensure_tenant_in_group_name': False,
                    'valid_group_regex': 'p[0-9]+-[a-z-]+',
                    'enforce_membership': False
                },
                'request_hook': {
                    'enabled': False,
                    'path': '/usr/local/bin/chowner',
                    'sudo': False
                },
            },
            'files_export': {
                'has_posix_ownership': False,
                'export_max_num_list': None,
                'import_path': '/tmp/pXX',
                'export_path': '/tmp/pXX/export',
                'allow_export': True,
                'allow_list': True,
                'allow_info': True,
                'allow_delete': True,
                'export_policy': {
                    'default': {
                        'enabled': False
                    },
                },
                'group_logic': {
                    'default_url_group': None,
                    'default_memberships': ['pXX-member-group'],
                    'enabled': False,
                },
                'request_hook': {
                    'enabled': False,
                },
            }
        },
        "dbs": {
            "apps_tables": {
                "db": {
                    "engine": "sqlite",
                    "path": "/tmp/pXX",
                    "table_structure": None,
                    "mq": None,
                },
                "table_structure": None
            },
            "survey": {
                "db": {
                    "engine": "sqlite",
                    "path": "/tmp/pXX/import",
                    "table_structure": None,
                    "mq": None,
                },
                "table_structure": None
            },
            "publication": {
                "db": {
                    "engine": "sqlite",
                    "path": "/tmp/pXX",
                    "table_structure": None,
                    "mq": None,
                },
                "table_structure": None
            },
        }
    }
}
