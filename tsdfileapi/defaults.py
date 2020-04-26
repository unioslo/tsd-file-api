
import getpass

_config = {
    'port': 3003,
    'debug': True,
    'api_user': getpass.getuser(),
    'token_check_tenant': True,
    'token_check_exp': True,
    'disallowed_start_chars': '.~',
    'requestor_claim_name': 'user',
    'tenant_claim_name': 'proj',
    'valid_tenant_regex': '^[0-9a-z]+$',
    'tenant_string_pattern': 'pXX',
    'export_max_num_list': 100 ,
    'export_chunk_size': 512000,
    'max_body_size': 5368709120,
    'default_file_owner': 'pXX-nobody',
    'create_tenant_dir': True,
    'jwt_test_secret': 'jS25aQbePizfTsetg8LbFsNKl1W6wi4nQaBj705ofWA=',
    'jwt_secret': None,
    'backends': {
        'disk': {
            'store': {
                'has_posix_ownership': False,
                'export_max_num_list': None,
                'admin_path': '',
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
                'group_logic': None,
                'default_url_group': None,
                'default_memberships': ['pXX-member-group'],
                'enabled': False,
                'request_hook': {
                    'enabled': False,
                },
            },
            'apps_files': {
                'has_posix_ownership': False,
                'export_max_num_list': None,
                'admin_path': '',
                'import_path': '/tmp/pXX/apps',
                'export_path': '/tmp/pXX/apps',
                'allow_export': True,
                'allow_list': True,
                'allow_info': True,
                'allow_delete': True,
                'export_policy': {
                    'default': {
                        'enabled': False
                    },
                },
                'group_logic': None,
                'default_url_group': None,
                'default_memberships': ['pXX-member-group'],
                'enabled': False,
                'request_hook': {
                    'enabled': False,
                },
            },
        },
        'sqlite': {
            'generic': {
                'db_path': '/tmp/pXX',
                'table_structure': None,
            },
            'apps_tables': {
                'db_path': '/tmp/pXX',
                'table_structure': None,
            },
        }
    }
}
