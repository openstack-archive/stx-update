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
from cgcs_patch.patch_verify import read_RSA_key

# To save memory, read and hash 1M of files at a time
default_blocksize=1*1024*1024

# When we sign patches, look for private keys in the following paths
#
# The (currently hardcoded) path on the signing server will be replaced
# by the capability to specify filename from calling function.
private_key_files=['/signing/keys/formal-private-key.pem',
                   os.path.expandvars('$MY_REPO/build-tools/signing/dev-private-key.pem')
                   ]


def sign_files(filenames, signature_file, private_key=None):
    """
    Utility function for signing data in files.
    :param filenames: A list of files containing the data to be signed
    :param signature_file: The name of the file to which the signature will be
                           stored
    :param private_key: If specified, sign with this private key.  Otherwise,
                        the files in private_key_files will be searched for
                        and used, if found.
    """

    # Hash the data across all files
    blocksize=default_blocksize
    data_hash = SHA256.new()
    for filename in filenames:
        with open(filename, 'rb') as infile:
            data=infile.read(blocksize)
            while len(data) > 0:
                data_hash.update(data)
                data=infile.read(blocksize)

    # Find a private key to use, if not already provided
    if private_key is None:
        for filename in private_key_files:
            # print 'Checking to see if ' + filename + ' exists\n'
            if os.path.exists(filename):
                # print 'Getting private key from ' + filename + '\n'
                private_key = read_RSA_key(open(filename, 'rb').read())

    assert (private_key is not None),"Could not find private signing key"

    # Encrypt the hash (sign the data) with the key we find
    signer = PKCS1_PSS.new(private_key)
    signature = signer.sign(data_hash)

    # Save it
    with open(signature_file, 'wb') as outfile:
        outfile.write(signature)

