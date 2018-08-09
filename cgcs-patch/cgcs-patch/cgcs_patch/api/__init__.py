"""
Copyright (c) 2014-2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from oslo_config import cfg


API_SERVICE_OPTS = [
    cfg.StrOpt('api_bind_ip',
               default='127.0.0.1',
               help='IP for the Patching controller API server to bind to',
               ),
    cfg.IntOpt('api_port',
               default=5487,
               help='The port for the Patching controller API server',
               ),
    cfg.IntOpt('api_limit_max',
               default=1000,
               help='the maximum number of items returned in a single '
                    'response from a collection resource'),
]

CONF = cfg.CONF
opt_group = cfg.OptGroup(name='api',
                         title='Options for the Patching controller api service')
CONF.register_group(opt_group)
CONF.register_opts(API_SERVICE_OPTS)
