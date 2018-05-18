"""
Copyright (c) 2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import os
import logging

from Crypto.Signature import PKCS1_v1_5
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence
from binascii import a2b_base64

from cgcs_patch.certificates import dev_certificate, formal_certificate

# To save memory, read and hash 1M of files at a time
default_blocksize=1*1024*1024

dev_certificate_marker='/etc/pki/wrs/dev_certificate_enable.bin'
LOG = logging.getLogger('main_logger')

cert_type_dev_str='dev'
cert_type_formal_str='formal'
cert_type_dev=[cert_type_dev_str]
cert_type_formal=[cert_type_formal_str]
cert_type_all=[cert_type_dev_str, cert_type_formal_str]

def verify_hash(data_hash, signature_bytes, certificate_list):
    """
    Checkes that a hash's signature can be validates against an approved
    certificate
    :param data_hash: A hash of the data to be validated
    :param signature_bytes: A pre-generated signature (typically, the hash
                            encrypted with a private key)
    :param certifcate_list: A list of approved certificates or public keys
                            which the signature is validated against
    :return: True if the signature was validated against a certificate
    """
    verified = False
    for cert in certificate_list:
        if verified:
            break
        pub_key = read_RSA_key(cert)
        x = pub_key.exportKey()

        # PSS is the recommended signature scheme, but some tools (like OpenSSL)
        # use the older v1_5 scheme.  We try to validate against both.
        #
        # We use PSS for patch validation, but use v1_5 for ISO validation
        # since we want to generate detached sigs that a customer can validate
        # OpenSSL
        verifier = PKCS1_PSS.new(pub_key)
        try:
            verified = verifier.verify(data_hash, signature_bytes)
        except ValueError as e:
            verified = False
            pass

        if not verified:
            verifier = PKCS1_v1_5.new(pub_key)
            try:
                verified = verifier.verify(data_hash, signature_bytes)
            except ValueError as e:
                verified = False
                pass
    return verified


def get_public_certificates_by_type(cert_type=cert_type_all):
    """
    Builds a list of accepted certificates which can be used to validate
    further things.  This list may contain multiple certificates depending on
    the configuration of the system and the value of cert_type.  

    :param cert_type: A list of strings, certificate types to include in list
        'formal' - include formal certificate if available
        'dev'    - include developer certificate if available
    :return: A list of certificates in PEM format
    """

    cert_list = []

    if cert_type_formal_str in cert_type:
        cert_list.append(formal_certificate)

    if cert_type_dev_str in cert_type:
        cert_list.append(dev_certificate)

    return cert_list


def get_public_certificates():
    """
    Builds a list of accepted certificates which can be used to validate
    further things.  This list may contain multiple certificates depending on
    the configuration of the system (for instance, should we include the
    developer certificate in the list).
    :return: A list of certificates in PEM format
    """
    cert_list = [formal_certificate]

    # We enable the dev certificate based on the presence of a file.  This file
    # contains a hash of an arbitrary string ('Titanum patching') which has been
    # encrypted with our formal private key.  If the file is present (and valid)
    # then we add the developer key to the approved certificates list
    if os.path.exists(dev_certificate_marker):
        with open(dev_certificate_marker) as infile:
            signature = infile.read()
        data_hash = SHA256.new()
        data_hash.update('Titanium patching')
        if verify_hash(data_hash, signature, cert_list):
            cert_list.append(dev_certificate)
        else:
            msg = "Invalid data found in " + dev_certificate_marker
            LOG.error(msg)

    return cert_list


def read_RSA_key(key_data):
    """
    Utility function for reading an RSA key half from encoded data
    :param key_data: PEM data containing raw key or X.509 certificate
    :return: An RSA key object
    """
    try:
        # Handle data that is just a raw key
        key = RSA.importKey(key_data)
    except ValueError:
        # The RSA.importKey function cannot read X.509 certificates directly
        # (depending on the version of the Crypto library).  Instead, we
        # may need to extract the key from the certificate before building
        # the key object
        #
        # We need to strip the BEGIN and END lines from PEM first
        x509lines = key_data.replace(' ','').split()
        x509text = ''.join(x509lines[1:-1])
        x509data = DerSequence()
        x509data.decode(a2b_base64(x509text))

        # X.509 contains a few parts.  The first part (index 0) is the
        # certificate itself, (TBS or "to be signed" cert) and the 7th field
        # of that cert is subjectPublicKeyInfo, which can be imported.
        # RFC3280
        tbsCert = DerSequence()
        tbsCert.decode(x509data[0])

        # Initialize RSA key from the subjectPublicKeyInfo field
        key = RSA.importKey(tbsCert[6])
    return key


def verify_files(filenames, signature_file, cert_type=None):
    """
    Verify data files against a detached signature.
    :param filenames: A list of files containing the data which was signed
    :param public_key_file: A file containing the public key or certificate
                            corresponding to the key which signed the data
    :param signature_file: The name of the file containing the signature
    :param cert_type: Only use specified certififcate type to verify (dev/formal)
    :return: True if the signature was verified, False otherwise
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

    # Get the signature
    with open(signature_file, 'rb') as sig_file:
        signature_bytes = sig_file.read()

    # Verify the signature
    if cert_type is None:
        certificate_list = get_public_certificates()
    else:
        certificate_list = get_public_certificates_by_type(cert_type=cert_type)
    return verify_hash(data_hash, signature_bytes, certificate_list)

