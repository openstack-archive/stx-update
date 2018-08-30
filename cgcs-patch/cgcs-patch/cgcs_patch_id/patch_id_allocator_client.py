#!/usr/bin/env python
#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import getopt
import sys

try:
    # Python 2
    from urllib import urlencode
    from urllib2 import urlopen
except ImportError:
    # Python 3
    from urllib.parse import urlencode
    from urllib.request import urlopen


opts = ['sw_version=', 'prefix=']

server = 'yow-cgts2-lx.wrs.com'
port = 8888


def request_patch_id(sw_version="1.01", prefix="CGCS"):
    raw_parms = {}
    raw_parms['sw_version'] = sw_version
    raw_parms['prefix'] = prefix
    print("raw_parms = %s" % str(raw_parms))

    url = "http://%s:%d/get_patch_id" % (server, port)
    params = urlencode(raw_parms)
    response = urlopen(url, params).read()
    return response


def main():
    optlist, remainder = getopt.getopt(sys.argv[1:], '', opts)

    sw_version = None
    prefix = None
    raw_parms = {}

    print("optlist = %s" % str(optlist))
    print("remainder = %s" % str(remainder))
    for key, val in optlist:
        print("key = %s, val = %s" % (key, val))
        if key == '--sw_version':
            sw_version = val
            print("sw_version = %s" % sw_version)
            raw_parms['sw_version'] = sw_version

        if key == '--prefix':
            prefix = val
            print("prefix = %s" % prefix)
            raw_parms['prefix'] = prefix

    # response = request_patch_id(sw_version=sw_version, prefix=prefix)
    response = request_patch_id(**raw_parms)
    print("response = %s" % str(response))


if __name__ == "__main__":
    main()
