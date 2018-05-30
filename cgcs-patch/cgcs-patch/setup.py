#!/usr/bin/env python
#
# Copyright (c) 2013-2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


import setuptools

setuptools.setup(name='cgcs_patch',
    version='1.0',
    description='CGCS Patch',
    packages=setuptools.find_packages(),
    package_data = {
        # Include templates
        '': ['templates/*'],
    }
)

