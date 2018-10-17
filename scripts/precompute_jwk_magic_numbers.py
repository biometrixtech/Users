#!/usr/bin/env python3

import argparse
import base64
import json
import struct

from cryptography.hazmat.primitives.asymmetric import rsa

from components.ui import cprint
from colorama import Fore

from cryptography.utils import int_to_bytes


# These are copied from jose.utils
def long_to_base64(data, size=0):
    return base64.urlsafe_b64encode(int_to_bytes(data, size or None)).strip(b'=')


def int_arr_to_long(arr):
    return int(''.join(["%02x" % byte for byte in arr]), 16)


def base64_to_long(data):
    if isinstance(data, str):
        data = data.encode("ascii")

    # urlsafe_b64decode will happily convert b64encoded data
    _d = base64.urlsafe_b64decode(bytes(data) + b'==')
    return int_arr_to_long(struct.unpack('%sB' % len(_d), _d))


# This is copied from jose.backends.cryptography_backend.CryptographyRSAKey._process_jwk
def _process_jwk(jwk_dict):
    if not jwk_dict.get('kty') == 'RSA':
        raise Exception("Incorrect key type.  Expected: 'RSA', Recieved: %s" % jwk_dict.get('kty'))

    e = base64_to_long(jwk_dict.get('e', 256))
    n = base64_to_long(jwk_dict.get('n'))
    d = base64_to_long(jwk_dict.get('d'))

    extra_params = ['p', 'q', 'dp', 'dq', 'qi']

    if all(k in jwk_dict for k in extra_params):
        # Precomputed private key parameters are all available.
        cprint('All precomputed private key parameters are already present', colour=Fore.YELLOW)
        return jwk_dict
    cprint('Precomputing private key parameters', colour=Fore.CYAN)

    p, q = rsa.rsa_recover_prime_factors(n, e, d)
    jwk_dict['p'] = long_to_base64(p).decode('utf8')
    jwk_dict['q'] = long_to_base64(q).decode('utf8')
    jwk_dict['dp'] = long_to_base64(rsa.rsa_crt_dmp1(d, p)).decode('utf8')
    jwk_dict['dq'] = long_to_base64(rsa.rsa_crt_dmq1(d, q)).decode('utf8')
    jwk_dict['qi'] = long_to_base64(rsa.rsa_crt_iqmp(p, q)).decode('utf8')

    cprint('Done', colour=Fore.CYAN)

    return jwk_dict


def main():
    with open(args.jwk_filename, 'r') as f:
        jwk_dict = json.load(f)

    jwk_dict = _process_jwk(jwk_dict)

    with open(args.jwk_filename + '-extended', 'w') as f:
        json.dump(jwk_dict, f, indent=4)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Expand a JWK with pre-computed magic numbers")
    parser.add_argument('jwk_filename',
                        help='Filename of JWK to expand')

    args = parser.parse_args()

    try:
        main()
    except KeyboardInterrupt:
        cprint('Exiting', colour=Fore.YELLOW)
        exit(1)
    except Exception as ex:
        cprint(str(ex), colour=Fore.RED)
        raise ex
