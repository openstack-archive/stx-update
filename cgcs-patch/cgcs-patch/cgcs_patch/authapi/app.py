"""
Copyright (c) 2014-2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from oslo_config import cfg
import pecan

from cgcs_patch.authapi import acl
from cgcs_patch.authapi import config
from cgcs_patch.authapi import hooks
from cgcs_patch.authapi import policy

from six.moves import configparser

auth_opts = [
    cfg.StrOpt('auth_strategy',
               default='keystone',
               help='Method to use for auth: noauth or keystone.'),
]

CONF = cfg.CONF
CONF.register_opts(auth_opts)


def get_pecan_config():
    # Set up the pecan configuration
    filename = config.__file__.replace('.pyc', '.py')
    return pecan.configuration.conf_from_file(filename)


def setup_app(pecan_config=None, extra_hooks=None):
    config_parser = configparser.RawConfigParser()
    config_parser.read('/etc/patching/patching.conf')

    policy.init()

    app_hooks = [hooks.ConfigHook(),
                 hooks.ContextHook(pecan_config.app.acl_public_routes),
                 ]
    if extra_hooks:
        app_hooks.extend(extra_hooks)

    if not pecan_config:
        pecan_config = get_pecan_config()

    if pecan_config.app.enable_acl:
        app_hooks.append(hooks.AdminAuthHook())

    pecan.configuration.set_config(dict(pecan_config), overwrite=True)

    app = pecan.make_app(
        pecan_config.app.root,
        static_root=pecan_config.app.static_root,
        template_path=pecan_config.app.template_path,
        debug=False,
        force_canonical=getattr(pecan_config.app, 'force_canonical', True),
        hooks=app_hooks,
        guess_content_type_from_ext=False,  # Avoid mime-type lookup
    )

    if pecan_config.app.enable_acl:
        return acl.install(app, config_parser, pecan_config.app.acl_public_routes)

    return app


class VersionSelectorApplication(object):
    def __init__(self):
        pc = get_pecan_config()
        pc.app.enable_acl = (CONF.auth_strategy == 'keystone')
        self.v1 = setup_app(pecan_config=pc)

    def __call__(self, environ, start_response):
        return self.v1(environ, start_response)
