"""
Copyright (c) 2014-2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

# Server Specific Configurations
server = {
    'port': '5487',
    'host': '127.0.0.1'
}

# Pecan Application Configurations
app = {
    'root': 'cgcs_patch.api.controllers.root.RootController',
    'modules': ['cgcs_patch.authapi'],
    'static_root': '%(confdir)s/public',
    'template_path': '%(confdir)s/../templates',
    'debug': False,
    'enable_acl': True,
    'acl_public_routes': [],
}
