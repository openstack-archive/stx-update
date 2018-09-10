#!/usr/bin/env python
#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import sys
import web
import patch_id_allocator as pida


port = 8888

urls = (
    '/get_patch_id', 'get_patch_id',
)


class get_patch_id:
    def GET(self):
        data = web.input(sw_version=None, prefix="CGCS")
        output = pida.get_patch_id(data.sw_version, data.prefix)
        return output

    def POST(self):
        data = web.input(sw_version=None, prefix="CGCS")
        output = pida.get_patch_id(data.sw_version, data.prefix)
        return output


class MyApplication(web.application):
    def run(self, port=8080, *middleware):
        func = self.wsgifunc(*middleware)
        return web.httpserver.runsimple(func, ('0.0.0.0', port))


def main():
    app = MyApplication(urls, globals())
    app.run(port=port)


if __name__ == "__main__":
    main()
