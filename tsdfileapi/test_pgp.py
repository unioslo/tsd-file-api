
import yaml, sys, base64

#from pgp import _import_keys
# some monkey patch
#import gnupg
#import gnupg._parsers
#gnupg._parsers.Verify.TRUST_LEVELS["ENCRYPTION_COMPLIANCE_MODE"] = 23
#gnupg._parsers.Verify.TRUST_LEVELS["DECRYPTION_KEY"] = 23
#gnupg._parsers.Verify.TRUST_LEVELS["DECRYPTION_COMPLIANCE_MODE"] = 23


def _import_keys(config):
    """
    This assumes you have the necessary keys in the keyring on the host.
    """
    gpg = gnupg.GPG(binary=config['gpg_binary'], homedir=config['gpg_homedir'],
                    keyring=config['gpg_keyring'], secring=config['gpg_secring'])
    return gpg


# client generates header value:
def pgp_encrypt_and_base64_encode(string, config):
    gpg = _import_keys(config)
    _id = config['public_key_id']
    encrypted = gpg.encrypt(string, _id, armor=False)
    encoded = base64.b64encode(encrypted.data)
    print('encoded and encrypted: {}'.format(encoded))
    return encoded

# server decrypts header value
def decrypt_aes_key(b64encoded_pgpencrypted_key, config):
    gpg = _import_keys(config)
    try:
        key = base64.b64decode(b64encoded_pgpencrypted_key)
        print('decoded, still encrypted: {}'.format(key))
        decr_aes_key = str(gpg.decrypt(key)).strip()
        print(decr_aes_key)
    except Exception as e:
        print(e)
    return decr_aes_key

def main():
    with open(sys.argv[1]) as f:
        config = yaml.load(f, Loader=yaml.Loader)
    k = 'tOg1qbyhRMdZLg=='
    enc = pgp_encrypt_and_base64_encode(k, config)
    print(decrypt_aes_key(k, config))

if __name__ == '__main__':
    main()
