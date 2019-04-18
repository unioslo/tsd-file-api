
"""Tools to decrypt PGP encrypted JSON."""

import logging
import json

import gnupg

# monkey patch to avoid random error message
# https://github.com/isislovecruft/python-gnupg/issues/207
import gnupg._parsers
gnupg._parsers.Verify.TRUST_LEVELS["DECRYPTION_KEY"] = 23
gnupg._parsers.Verify.TRUST_LEVELS["DECRYPTION_COMPLIANCE_MODE"] = 23


def _import_keys(config):
    """
    This assumes you have the necessary keys in the keyring on the host.
    """
    gpg = gnupg.GPG(binary=config['gpg_binary'], homedir=config['gpg_homedir'],
                    keyring=config['gpg_keyring'], secring=config['gpg_secring'])
    return gpg
