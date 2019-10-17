
"""Tools to decrypt PGP encrypted JSON."""

import logging
import json

from pretty_bad_protocol import gnupg

import pretty_bad_protocol._parsers
pretty_bad_protocol._parsers.Verify.TRUST_LEVELS["DECRYPTION_KEY"] = 23
pretty_bad_protocol._parsers.Verify.TRUST_LEVELS["DECRYPTION_COMPLIANCE_MODE"] = 23


def _import_keys(config):
    """
    This assumes you have the necessary keys in the keyring on the host.
    """
    gpg = gnupg.GPG(binary=config['gpg_binary'], homedir=config['gpg_homedir'],
                    keyring=config['gpg_keyring'], secring=config['gpg_secring'])
    return gpg
