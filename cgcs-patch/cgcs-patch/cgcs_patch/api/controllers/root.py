"""
Copyright (c) 2014-2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import os
from pecan import expose
from pecan import request
import cgi
import glob

from cgcs_patch.exceptions import PatchError
from cgcs_patch.patch_controller import pc

from cgcs_patch.patch_functions import LOG


class PatchAPIController(object):

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def index(self):
        return self.query()

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def query(self, **kwargs):
        try:
            pd = pc.patch_query_cached(**kwargs)
        except PatchError as e:
            return dict(error="Error: %s" % e.message)

        return dict(pd=pd)

    @expose('json')
    @expose('show.xml', content_type='application/xml')
    def show(self, *args):
        try:
            result = pc.patch_query_specific_cached(list(args))
        except PatchError as e:
            return dict(error="Error: %s" % e.message)

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def apply(self, *args):
        if pc.any_patch_host_installing():
            return dict(error="Rejected: One or more nodes are installing patches.")

        try:
            result = pc.patch_apply_api(list(args))
        except PatchError as e:
            return dict(error="Error: %s" % e.message)

        pc.patch_sync()

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def remove(self, *args, **kwargs):
        if pc.any_patch_host_installing():
            return dict(error="Rejected: One or more nodes are installing patches.")

        try:
            result = pc.patch_remove_api(list(args), **kwargs)
        except PatchError as e:
            return dict(error="Error: %s" % e.message)

        pc.patch_sync()

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def delete(self, *args):
        try:
            result = pc.patch_delete_api(list(args))
        except PatchError as e:
            return dict(error="Error: %s" % e.message)

        pc.patch_sync()

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def upload(self):
        assert isinstance(request.POST['file'], cgi.FieldStorage)
        fileitem = request.POST['file']

        if not fileitem.filename:
            return dict(error="Error: No file uploaded")

        fn = '/scratch/' + os.path.basename(fileitem.filename)

        if isinstance(fileitem.file, file):
            # This technique cannot copy a very large file. It
            # requires a lot of memory as all data from the
            # source file is read into memory then written to
            # the destination file one chunk
            # open(fn, 'wb').write(fileitem.file.read())

            # Copying file by chunks using OS system calls
            # requires much less memory. A larger chunk
            # size can be used to improve the copy speed;
            # currently 64K chunk size is selected
            dst = os.open(fn, os.O_WRONLY | os.O_CREAT)
            src = fileitem.file.fileno()
            size = 64 * 1024
            n = size
            while n >= size:
                s = os.read(src, size)
                n = os.write(dst, s)
            os.close(dst)
        else:
            open(fn, 'wb').write(fileitem.file.read())

        try:
            result = pc.patch_import_api([fn])
        except PatchError as e:
            os.remove(fn)
            return dict(error=e.message)

        os.remove(fn)

        pc.patch_sync()

        return result

    @expose('json')
    def upload_dir(self, **kwargs):
        files = []
        for key, path in kwargs.items():
            LOG.info("upload-dir: Retrieving patches from %s" % path)
            for f in glob.glob(path + '/*.patch'):
                if os.path.isfile(f):
                    files.append(f)

        if len(files) == 0:
            return dict(error="No patches found")

        try:
            result = pc.patch_import_api(sorted(files))
        except PatchError as e:
            return dict(error=e.message)

        pc.patch_sync()

        return result

    @expose('json')
    def init_release(self, *args):
        if len(list(args)) == 0:
            return dict(error="Release must be specified")

        try:
            result = pc.patch_init_release_api(list(args)[0])
        except PatchError as e:
            return dict(error=e.message)

        pc.patch_sync()

        return result

    @expose('json')
    def del_release(self, *args):
        if len(list(args)) == 0:
            return dict(error="Release must be specified")

        try:
            result = pc.patch_del_release_api(list(args)[0])
        except PatchError as e:
            return dict(error=e.message)

        pc.patch_sync()

        return result

    @expose('json')
    @expose('query_hosts.xml', content_type='application/xml')
    def query_hosts(self, *args):
        return dict(data=pc.query_host_cache())

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def what_requires(self, *args):
        try:
            result = pc.patch_query_what_requires(list(args))
        except PatchError as e:
            return dict(error="Error: %s" % e.message)

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def host_install(self, *args):
        return dict(error="Deprecated: Use host_install_async")

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def host_install_async(self, *args):
        if len(list(args)) == 0:
            return dict(error="Host must be specified for install")
        force = False
        if len(list(args)) > 1 and 'force' in list(args)[1:]:
            force = True

        try:
            result = pc.patch_host_install(list(args)[0], force, async_req=True)
        except PatchError as e:
            return dict(error="Error: %s" % e.message)

        return result

    @expose('json')
    @expose('query.xml', content_type='application/xml')
    def drop_host(self, *args):
        if len(list(args)) == 0:
            return dict(error="Host must be specified")

        try:
            result = pc.drop_host(list(args)[0])
        except PatchError as e:
            return dict(error="Error: %s" % e.message)

        return result

    @expose('json')
    def query_dependencies(self, *args, **kwargs):
        try:
            result = pc.patch_query_dependencies(list(args), **kwargs)
        except PatchError as e:
            return dict(error=e.message)

        return result

    @expose('json')
    def commit(self, *args):
        try:
            result = pc.patch_commit(list(args))
        except PatchError as e:
            return dict(error=e.message)

        pc.patch_sync()

        return result

    @expose('json')
    def commit_dry_run(self, *args):
        try:
            result = pc.patch_commit(list(args), dry_run=True)
        except PatchError as e:
            return dict(error=e.message)

        return result


class RootController(object):

    @expose()
    @expose('json')
    def index(self):
        return "Titanium Cloud Patching API, Available versions: /v1"

    patch = PatchAPIController()
    v1 = PatchAPIController()
