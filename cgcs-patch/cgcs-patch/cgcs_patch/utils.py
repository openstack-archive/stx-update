"""
Copyright (c) 2016-2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from netaddr import IPAddress
import cgcs_patch.constants as constants
import socket

import ctypes
import ctypes.util

libc = ctypes.CDLL(ctypes.util.find_library('c'))


def if_nametoindex(name):
    return libc.if_nametoindex(name)


def gethostbyname(hostname):
    """ gethostbyname with IPv6 support """
    try:
        return socket.getaddrinfo(hostname, None)[0][4][0]
    except Exception:
        return None


def get_management_version():
    """ Determine whether management is IPv4 or IPv6 """
    controller_ip_string = gethostbyname(constants.CONTROLLER_FLOATING_HOSTNAME)
    if controller_ip_string:
        controller_ip_address = IPAddress(controller_ip_string)
        return controller_ip_address.version
    else:
        return constants.ADDRESS_VERSION_IPV4


def get_management_family():
    ip_version = get_management_version()
    if ip_version == constants.ADDRESS_VERSION_IPV6:
        return socket.AF_INET6
    else:
        return socket.AF_INET


def get_versioned_address_all():
    ip_version = get_management_version()
    if ip_version == constants.ADDRESS_VERSION_IPV6:
        return "::"
    else:
        return "0.0.0.0"


def ip_to_url(ip_address_string):
    """ Add brackets if an IPv6 address """
    try:
        ip_address = IPAddress(ip_address_string)
        if ip_address.version == constants.ADDRESS_VERSION_IPV6:
            return "[%s]" % ip_address_string
        else:
            return ip_address_string
    except Exception:
        return ip_address_string


def ip_to_versioned_localhost(ip_address_string):
    """ Add brackets if an IPv6 address """
    ip_address = IPAddress(ip_address_string)
    if ip_address.version == constants.ADDRESS_VERSION_IPV6:
        return "::1"
    else:
        return "localhost"
