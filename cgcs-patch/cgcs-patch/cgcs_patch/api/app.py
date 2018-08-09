"""
Copyright (c) 2014-2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import pecan

from cgcs_patch.api import config


def get_pecan_config():
    # Set up the pecan configuration
    filename = config.__file__.replace('.pyc', '.py')
    return pecan.configuration.conf_from_file(filename)


def setup_app(pecan_config=None):
    if not pecan_config:
        pecan_config = get_pecan_config()

    pecan.configuration.set_config(dict(pecan_config), overwrite=True)

    app = pecan.make_app(
        pecan_config.app.root,
        static_root=pecan_config.app.static_root,
        template_path=pecan_config.app.template_path,
        debug=False,
        force_canonical=getattr(pecan_config.app, 'force_canonical', True),
        guess_content_type_from_ext=False,  # Avoid mime-type lookup
    )

    return app


class VersionSelectorApplication(object):
    def __init__(self):
        pc = get_pecan_config()
        self.v1 = setup_app(pecan_config=pc)

    def __call__(self, environ, start_response):
        return self.v1(environ, start_response)
