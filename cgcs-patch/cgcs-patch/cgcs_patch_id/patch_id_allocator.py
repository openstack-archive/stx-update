#!/usr/bin/python
#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


import posixfile
import string
import time

directory = "/localdisk/designer/jenkins/patch_ids"


def get_unique_id(filename, digits=4):
    counter = 1
    path = "%s/%s" % (directory, filename)
    try:
        # open for update
        file = posixfile.open(path, "r+")
        file.lock("w|", digits)
        counter = int(file.read(digits)) + 1
    except IOError:
        # create it
        try:
            file = posixfile.open(path, "w")
            file.lock("w|", digits)
        except IOError:
            print("creation of file '%s' failed" % path)
            return -1

    file.seek(0)  # rewind
    format = "%%0%dd" % digits
    file.write(format % counter)

    # Note: close releases lock
    file.close()

    return counter


def get_patch_id(version, prefix="CGCS", digits=4):
    filename = "%s_%s_patchid" % (prefix, version)
    id = get_unique_id(filename)
    if id < 0:
        return None
    patch_id_format = "%%s_%%s_PATCH_%%0%dd" % digits
    patch_id = patch_id_format % (prefix, version, id)
    return patch_id
