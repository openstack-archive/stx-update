"""
Copyright (c) 2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import os
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence
from binascii import a2b_base64
from cgcs_patch.patch_verify import read_RSA_key, cert_type_formal_str, cert_type_dev_str

# To save memory, read and hash 1M of files at a time
default_blocksize = 1 * 1024 * 1024

# When we sign patches, look for private keys in the following paths
#
# The (currently hardcoded) path on the signing server will be replaced
# by the capability to specify filename from calling function.
private_key_files = {cert_type_formal_str: '/signing/keys/formal-private-key.pem',
                     cert_type_dev_str: os.path.expandvars('$MY_REPO/build-tools/signing/dev-private-key.pem')
                     }


def sign_files(filenames, signature_file, private_key=None, cert_type=None):
    """
    Utility function for signing data in files.
    :param filenames: A list of files containing the data to be signed
    :param signature_file: The name of the file to which the signature will be
                           stored
    :param private_key: If specified, sign with this private key.  Otherwise,
                        the files in private_key_files will be searched for
                        and used, if found.
    :param cert_type: If specified, and private_key is not specified, sign
                      with a key of the specified type.  e.g. 'dev' or 'formal'
    """

    # Hash the data across all files
    blocksize = default_blocksize
    data_hash = SHA256.new()
    for filename in filenames:
        with open(filename, 'rb') as infile:
            data = infile.read(blocksize)
            while len(data) > 0:
                data_hash.update(data)
                data = infile.read(blocksize)

    # Find a private key to use, if not already provided
    need_resign_with_formal = False
    if private_key is None:
        if cert_type is not None:
            # A Specific key is asked for
            assert (cert_type in private_key_files.keys()), "cert_type=%s is not a known cert type" % cert_type
            dict_key = cert_type
            filename = private_key_files[dict_key]
            # print 'cert_type given: Checking to see if ' + filename + ' exists\n'
            if not os.path.exists(filename) and dict_key == cert_type_formal_str:
                # The formal key is asked for, but is not locally available,
                # substitute the dev key, and we will try to resign with the formal later.
                dict_key = cert_type_dev_str
                filename = private_key_files[dict_key]
                need_resign_with_formal = True
            if os.path.exists(filename):
                # print 'Getting private key from ' + filename + '\n'
                private_key = read_RSA_key(open(filename, 'rb').read())
        else:
            # Search for available keys
            for dict_key in private_key_files.keys():
                filename = private_key_files[dict_key]
                # print 'Search for available keys: Checking to see if ' + filename + ' exists\n'
                if os.path.exists(filename):
                    # print 'Getting private key from ' + filename + '\n'
                    private_key = read_RSA_key(open(filename, 'rb').read())

    assert (private_key is not None), "Could not find signing key"

    # Encrypt the hash (sign the data) with the key we find
    signer = PKCS1_PSS.new(private_key)
    signature = signer.sign(data_hash)

    # Save it
    with open(signature_file, 'wb') as outfile:
        outfile.write(signature)

    return need_resign_with_formal
