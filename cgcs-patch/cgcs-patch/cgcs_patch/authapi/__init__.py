# Copyright (c) 2013-2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_config import cfg

API_SERVICE_OPTS = [
    cfg.StrOpt('auth_api_bind_ip',
               default=None,
               help='IP for the authenticated Patching API server to bind to'),
    cfg.IntOpt('auth_api_port',
               default=5491,
               help='The port for the authenticated Patching API server'),
    cfg.IntOpt('api_limit_max',
               default=1000,
               help='the maximum number of items returned in a single '
                    'response from a collection resource')
]

CONF = cfg.CONF
opt_group = cfg.OptGroup(name='api',
                         title='Options for the patch-api service')
CONF.register_group(opt_group)
CONF.register_opts(API_SERVICE_OPTS)
