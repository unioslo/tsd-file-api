
"""Tools to decrypt PGP encrypted JSON."""

import logging
import json

import gnupg

class PGPKeyLoadError(Exception):
    message = 'Issue with keys'


class JsonDecryptionError(Exception):
    message = 'Could not decrypt data'


def _import_keys(config):
    """
    This assumes you have the necessary keys in the keyring on the host.
    """
    gpg = gnupg.GPG(binary=config['gpg_binary'], homedir=config['gpg_homedir'],
                    keyring=config['gpg_keyring'], secring=config['gpg_secring'])
    return gpg


def decrypt_pgp_json(config, data):
    """
    Decrypt PGP encrypted JSON data. Will load the key specified in
    file-api config file using the public_key_id.

    Currently requires _request_ data to be in the following format (this
    function only receives the 'data' part of the example below, the rest
    is used to detemine which table to write it to in the db):

    {
        'data': '-----BEGIN PGP MESSAGE-----\n\n...n\-----END PGP MESSAGE-----\n',
        'form_id': <id, int>,
        'key_id': <public key id, str>,
        'submission_id': <>,
    }

    The semantics are very closely coupled to Nettskjema data deliveries.
    To accommodate PGP encrypted JSON deliveries from  other clients
    with their own format requires a bit of work here, but also in the
    tsd-db-manager's PGP decryption module for postgrest APIs with PostgreSQL
    backends. All that is needed is to allow using table names instead of form_ids
    and to make some of the keys optional.

    Parameters
    ----------
    config: dict
    data: dict

    Returns
    -------
    dict

    """
    try:
        gpg = _import_keys(config)
    except AssertionError as e:
        logging.error(e.message)
        raise PGPKeyLoadError
    try:
        data = json.loads(str(gpg.decrypt(data)))
    except Exception as e:
        logging.error(e.message)
        raise JsonDecryptionError
    return data
