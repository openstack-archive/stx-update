"""
Copyright (c) 2014 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import sys
import os
import shutil
import tempfile
import platform
import collections
import logging
import fnmatch
import getopt
import subprocess
import time
import re
from cgcs_patch.patch_functions import PatchFile
# import twisted.python.lockfile

import xml.etree.ElementTree as ElementTree
from xml.dom import minidom

STATUS_OBSOLETE = 'OBS'
STATUS_RELEASED = 'REL'
STATUS_DEVELOPEMENT = 'DEV'

RPM_DIR = "rpmbuild/RPMS"
RPM_ARCHIVE_DIR = "rpm_archive/RPMS"
REMOTE_COPY_PATCH_DATA_DIR = "export/remote_patch_data"
PATCH_DATA_GIT = "cgcs-patches"
LOCAL_PATCH_DATA_DIR = "export/patch_data"
ORDER_FILE = "patch_order"
ARCH_DEFAULT = "x86_64"

METADATA_TAGS = ['ID', 'SW_VERSION', 'SUMMARY', 'DESCRIPTION',
                 'INSTALL_INSTRUCTIONS', 'WARNINGS', 'STATUS',
                 'UNREMOVABLE', 'REBOOT_REQUIRED']
RMP_EXCLUDES = ['-dev-', '-dbg-', '-doc-']
BUILD_TYPES = ['std', 'rt']


SAME = 0
MINOR_DIFF = 1
MAJOR_DIFF = 2

# These from environment
MY_REPO = None
MY_WORKSPACE = None
PROJECT = None
SRC_BUILD_ENVIRONMENT = None
MY_SRC_RPM_BUILD_DIR = None
MY_BUILD_CFG = None
MY_BUILD_DIR = None

WORKDIR_BUILD_INFO_LOCATION = "build.info"
SRCDIR_UNBUILT_PATTERN_FILE = "build-data/unbuilt_rpm_patterns"
SRCDIR_IMAGE_INC_FILE = "build-tools/build_iso/image.inc"

build_info = {}

temp_rpm_db_dir = None
workdir = None
srcdir = None
branch = None
sw_version = None
formal_flag = False
pre_compiled_flag = False
pre_clean_flag = False
all_flag = False
capture_source_flag = False
capture_rpms_flag = False

capture_source_path = None

logfile = "/var/log/patching.log"

LOG = logging.getLogger(__name__)


def configure_logging(logtofile=True, level=logging.DEBUG):
    if logtofile:
        my_exec = os.path.basename(sys.argv[0])

        log_format = '%(asctime)s: ' \
                     + my_exec + '[%(process)s]: ' \
                     + '%(filename)s(%(lineno)s): ' \
                     + '%(levelname)s: %(message)s'

        logging.basicConfig(filename=logfile, level=level, format=log_format, datefmt="%FT%T")

        # Log uncaught exceptions to file
        sys.excepthook = handle_exception
    else:
        logging.basicConfig(level=level)


def rev_lt(num1, num2):
    n1w = num1.split('.')
    n2w = num2.split('.')
    while True:
        try:
            n1 = int(n1w.pop(0))
        except Exception:
            return True
        try:
            n2 = int(n2w.pop(0))
        except Exception:
            return False
        if n1 < n2:
            return True
        if n1 > n2:
            return False


def add_text_tag_to_xml(parent, name, text):
    """
    Utility function for adding a text tag to an XML object
    :param parent: Parent element
    :param name: Element name
    :param text: Text value
    :return:The created element
    """
    tag = ElementTree.SubElement(parent, name)
    tag.text = text
    return tag


def handle_exception(exc_type, exc_value, exc_traceback):
    """
    Exception handler to log any uncaught exceptions
    """
    LOG.error("Uncaught exception",
              exc_info=(exc_type, exc_value, exc_traceback))
    sys.__excepthook__(exc_type, exc_value, exc_traceback)


def write_xml_file(top, fname):
    # Generate the file, in a readable format if possible
    outfile = open(fname, 'w')
    rough_xml = ElementTree.tostring(top, 'utf-8')
    if platform.python_version() == "2.7.2":
        # The 2.7.2 toprettyxml() function unnecessarily indents
        # childless tags, adding whitespace. In the case of the
        # yum comps.xml file, it makes the file unusable, so just
        # write the rough xml
        outfile.write(rough_xml)
    else:
        outfile.write(minidom.parseString(rough_xml).toprettyxml(indent="  "))


class PatchRecipeError(Exception):
    """Base class for patch recipe exceptions."""

    def __init__(self, message=None):
        self.message = message

    def __str__(self):
        return self.message or ""


class PatchRecipeXMLFail(PatchRecipeError):
    """Problem parsing XML of patch recipe."""
    pass


class PatchBuildFail(PatchRecipeError):
    """Problem Compiling the patch."""
    pass


class PatchPackagingFail(PatchRecipeError):
    """Problem assembling the patch."""
    pass


class PatchPackagingMiss(PatchRecipeError):
    """Problem assembling the patch - might be correctable."""
    pass


class PatchRequirementFail(PatchRecipeError):
    """Missing Requirement."""
    pass


class PatchRecipeCmdFail(PatchRecipeError):
    """Shell command Failure."""
    pass


class PatchList:
    """
    Patch List
    """
    def __init__(self, patch_xml_list):
        self.data_path = "%s/%s" % (workdir, LOCAL_PATCH_DATA_DIR)
        self.remote_copy_data_path = "%s/%s" % (workdir, REMOTE_COPY_PATCH_DATA_DIR)
        self.order_file = "%s" % ORDER_FILE
        self.patch_git = "%s-%s" % (PATCH_DATA_GIT, sw_version)
        self.patch_data = {}           # map patch name to PatchRecipeData
        self.xml_to_patch = {}         # map xml path to patch name
        self.patch_to_xml = {}         # map patch name to xml
        self.patches_to_build = []     # list of patches to build
        self.patches_built = []        # patches already built
        self.patches_to_deliver = []

        self._prep_workspace()
        self._obtain_official_patches()
        self._validate_patch_order()
        self._load_built_patches()
        self._load_official_patches()
        if patch_xml_list is not None:
            for patch_xml in patch_xml_list:
                self.add(patch_xml, built=False, rebuild=True, require_context=False)

    def __str__(self):
        return "[ data_path: %s, order_file: %s, patches_built: %s, patches_to_build: %s, xml_to_patch: %s, patch_to_xml: %s ]" % (str(self.data_path), str(self.order_file), str(self.patches_built), str(self.patches_to_build), str(self.xml_to_patch), str(self.patch_to_xml))

    def myprint(self, indent=""):
        print("%s%s" % (indent, str(self)))

    def _std_xml_patch_recipe_name(self, patch_id):
        xml_name = "%s.xml" % patch_id
        return xml_name

    def _std_local_path(self, name):
        xml_path = "%s/%s" % (self.data_path, name)
        return xml_path

    def _std_remote_copy_path(self, name):
        xml_path = "%s/%s" % (self.remote_copy_data_path, name)
        return xml_path

    def _std_patch_git_path(self, name=None):
        git_path = "%s/%s/%s/%s" % (self.remote_copy_data_path, self.patch_git, sw_version, name)
        return git_path

    def _prep_workspace(self):
        os.chdir(workdir)
        issue_cmd("mkdir -p %s" % self._std_local_path(""))
        issue_cmd("touch %s" % self._std_local_path(self.order_file))

    def find_patch_id(self, patch_id):
        for patch in self.patches_built:
            if patch == patch_id:
                return self.patch_data[patch]
        for patch in self.patches_to_build:
            if patch == patch_id:
                return self.patch_data[patch]
        return None

    def _validate_patch_order(self):
        fix_local_order = False
        remote_order = []
        local_order = []
        validated_order = []
        with open(self._std_patch_git_path(self.order_file)) as f:
            for line in f:
                remote_order.append(line.strip())
        with open(self._std_local_path(self.order_file)) as f:
            for line in f:
                local_order.append(line.strip())
        while len(remote_order) and len(local_order):
            remote_patch = remote_order.pop(0)
            local_patch = local_order.pop(0)
            if remote_patch == local_patch:
                print("_validate_patch_order: %s ok" % local_patch)
                validated_order.append(remote_patch)
            else:
                fix_local_order = True
                print("_validate_patch_order: %s vs %s fail" % (local_patch, remote_patch))
                local_order.insert(0, local_patch)
                break
        if fix_local_order:
            print("_validate_patch_order: fix patch order")
            f = open(self._std_local_path(self.order_file), 'w')
            for patch_id in validated_order:
                f.write("%s\n" % patch_id)
                print("_validate_patch_order:     %s" % patch_id)
            f.close()

            # remove remaining local patches
            for patch_id in local_order:
                xml_path = self._std_local_path(self._std_xml_patch_recipe_name(patch_id))
                print("_validate_patch_order: rm %s" % xml_path)
                os.remove(xml_path)

    def _obtain_official_patches(self):
        os.chdir(workdir)
        issue_cmd("mkdir -p %s" % self._std_remote_copy_path(""))
        os.chdir(self._std_remote_copy_path(""))

        if not os.path.isdir(self.patch_git):
            issue_cmd("git clone ssh://%s@vxgit.wrs.com:7999/cgcs/%s.git" % (os.environ['USER'], self.patch_git))
            os.chdir(self.patch_git)
            issue_cmd("git checkout master")
        else:
            os.chdir(self.patch_git)
            issue_cmd("git checkout master")
            issue_cmd("git pull")

        try:
            issue_cmd("git checkout %s" % sw_version)
        except PatchRecipeCmdFail:
            issue_cmd("git checkout -b %s master" % sw_version)
            issue_cmd("git push -u origin %s:%s" % (sw_version, sw_version))
            issue_cmd("git checkout master")
            issue_cmd("git pull")
            issue_cmd("git checkout %s" % sw_version)

        issue_cmd("git pull")

        os.chdir(workdir)
        if not os.path.isdir(self._std_patch_git_path("")):
            issue_cmd("mkdir -p %s" % self._std_patch_git_path(""))
            os.chdir(self._std_patch_git_path(".."))
            issue_cmd("git add %s" % self._std_patch_git_path(""))
            os.chdir(workdir)
            if not os.path.isfile(self._std_patch_git_path(self.order_file)):
                issue_cmd("touch %s" % self._std_patch_git_path(self.order_file))
                os.chdir(self._std_patch_git_path(".."))
                issue_cmd("git add %s" % self._std_patch_git_path(self.order_file))
                os.chdir(workdir)

    def _load_official_patches(self):
        with open(self._std_patch_git_path(self.order_file)) as f:
            for line in f:
                patch_id = line.strip()
                print("remote patch_id = '%s'" % patch_id)
                xml_path = self._std_patch_git_path(self._std_xml_patch_recipe_name(patch_id))
                self.add(xml_path, built=False, fix=True)

    def sign_official_patches(self):
        for patch_id in self.patches_to_deliver:
            os.chdir(workdir)
            patch = "%s.patch" % patch_id
            print("signing patch '%s'" % self._std_local_path(patch))

            try:
                subprocess.check_call(["sign_patch_formal.sh", self._std_local_path(patch)])
            except subprocess.CalledProcessError as e:
                print("Failed to to sign official patch. Call to sign_patch_formal.sh process returned non-zero exit status %i" % e.returncode)
                raise SystemExit(e.returncode)

    def deliver_official_patch(self):
        something_to_push = False
        os.chdir(workdir)
        issue_cmd("cp %s %s" % (self._std_local_path(self.order_file), self._std_patch_git_path(self.order_file)))
        os.chdir(self._std_patch_git_path("."))
        issue_cmd("git add %s" % self.order_file)

        for patch_id in self.patches_to_deliver:
            prevent_overwrite = False
            os.chdir(workdir)
            patch = "%s.patch" % patch_id
            xml = "%s.xml" % patch_id
            if os.path.isfile(self._std_patch_git_path(patch)):
                answer = PatchFile.query_patch(self._std_patch_git_path(patch), field="status")
                if answer is not None and "status" in answer:
                    if answer["status"] == "REL":
                        prevent_overwrite = True
                        print("Warning: '%s' already exists in git repo and is in released state!  Cowardly refusing to overwrite it." % patch)

            if not prevent_overwrite:
                issue_cmd("cp %s %s" % (self._std_local_path(patch), self._std_patch_git_path(".")))
                issue_cmd("cp %s %s" % (self._std_local_path(xml), self._std_patch_git_path(".")))
                os.chdir(self._std_patch_git_path("."))
                issue_cmd("git add %s" % patch)
                issue_cmd("git add %s" % xml)
                issue_cmd("git commit -m \"%s\"" % patch_id)
                something_to_push = True

        if something_to_push:
            os.chdir(workdir)
            os.chdir(self._std_patch_git_path(".."))
            issue_cmd("git push --dry-run --set-upstream origin %s:%s" % (sw_version, sw_version))
            issue_cmd("git push --set-upstream origin %s:%s" % (sw_version, sw_version))

    def _load_built_patches(self):
        with open(self._std_local_path(self.order_file)) as f:
            for line in f:
                patch_id = line.strip()
                print("local patch_id = '%s'" % patch_id)
                xml_path = self._std_local_path(self._std_xml_patch_recipe_name(patch_id))
                self.add(xml_path, built=True, fix=False)

    def get_implicit_requires(self, patch_id, recipies):
        list = []
        for r in recipies:
            print("get_implicit_requires r=%s" % r)
        for patch in self.patches_built:
            if patch == patch_id:
                continue
            if self.patch_data[patch].has_common_recipies(recipies):
                print("get_implicit_requires built patch '%s' provides one of %s" % (patch, str(recipies)))
                list.append(patch)
        for patch in self.patches_to_build:
            if patch == patch_id:
                continue
            if self.patch_data[patch].has_common_recipies(recipies):
                print("get_implicit_requires unbuilt patch '%s' provides one of %s" % (patch, str(recipies)))
                list.append(patch)
        return list

    def is_built(self, patch):
        if patch not in self.patches_built:
            print("Queried patch '%s' is not built" % patch)
            return False
        return True

    def is_known(self, patch):
        if patch not in self.patches_built:
            if patch not in self.patches_to_build:
                print("Queried patch '%s' is not known" % patch)
                return False
        return True

    def add(self, patch_xml, built=False, fix=False, rebuild=False, require_context=True):
        print("processing patch_xml %s, built=%s, fix=%s, rebuild=%s, require_context=%s" % (patch_xml, str(built), str(fix), str(rebuild), str(require_context)))
        prd = PatchRecipeData(built, self)
        prd.parse_xml(patch_xml)
        if prd.patch_id is None:
            msg = "Invalid patch '%s' patch_xml contains no patch_id" % patch_xml
            LOG.exception(msg)
            print(msg)
            raise PatchRecipeXMLFail(msg)
            sys.exit(2)
        if len(prd.recipies) <= 0:
            msg = "Invalid patch '%s' contains no recipies" % prd.patch_id
            LOG.exception(msg)
            print(msg)
            raise PatchRecipeXMLFail(msg)
            sys.exit(2)
        if require_context and prd.build_context is None:
            msg = "Invalid patch '%s' contains no context" % prd.patch_id
            LOG.exception(msg)
            print(msg)
            raise PatchRecipeXMLFail(msg)
            sys.exit(2)
        if not rebuild:
            if prd.patch_id in self.patch_to_xml:
                if self.patch_to_xml[prd.patch_id] == patch_xml:
                    msg = "Previously added patch '%s' from same xml '%s'" % (prd.patch_id, patch_xml)
                    LOG.warn(msg)
                    print("%s\n" % msg)
                    return
                rc = issue_cmd_rc("diff %s %s" % (self.patch_to_xml[prd.patch_id], patch_xml))
                if rc != 0:
                    msg = "Previously added patch '%s' from different xml '%s' and different content" % (prd.patch_id, patch_xml)
                    LOG.exception(msg)
                    print("%s\n" % msg)
                    raise PatchRecipeXMLFail(msg)
                    sys.exit(2)
                else:
                    msg = "Previously added patch '%s' from different xml '%s' but same content" % (prd.patch_id, patch_xml)
                    LOG.warn(msg)
                    print("%s\n" % msg)
                    return
        if prd.patch_id in self.patch_data.keys():
            if not rebuild:
                # Already know about this patch, perhaps local vs remote
                rc2 = prd.compare(self.patch_data[prd.patch_id])
                if (fix and (rc2 > MAJOR_DIFF)) or (not fix and (rc2 > MINOR_DIFF)):
                    msg = "Patch '%s' added twice with differing content"
                    LOG.exception(msg)
                    print(msg)
                    raise PatchRequirementFail(msg)
                    sys.exit(2)
                if fix and (rc2 > MINOR_DIFF):
                    new_status = self.get_status()
                    old_status = prd.get_status()
                    # TODO(slittle) should we update status
                    prd.set_status(new_status)
                    rc2 = prd.compare(self.patch_data[prd.patch_id])
                    if rc2 > MINOR_DIFF:
                        msg = "Failed to resolve patch difference by status update for patch '%s'" % prd.patch_id
                        LOG.exception(msg)
                        print(msg)
                        raise PatchRequirementFail(msg)
                        sys.exit(2)
                    # TODO(slittle) write revised xml to local/remote ?
                # patch is already known and has same content
                # nothing more to do since rebuild is not requested
                return

        self.patch_to_xml[prd.patch_id] = patch_xml
        self.xml_to_patch[patch_xml] = prd.patch_id
        self.patch_data[prd.patch_id] = prd

        prd.set_implicit_requires(self)

        rc = prd.check_requires_known(self)
        if not rc:
            msg = "Can't proceed because patch %s has requirements on an unknown patch." % prd.patch_id
            LOG.exception(msg)
            print(msg)
            raise PatchRequirementFail(msg)
            sys.exit(2)
        rc = prd.check_requires_built(self)
        if built and not rc:
            msg = "Patch %s claims to be built yet it requires a patch that is unbuilt."
            LOG.exception(msg)
            print(msg)
            raise PatchRequirementFail(msg)
            sys.exit(2)

        rc = prd.check_requires_buildable(self)
        if not rc:
            msg = "Can't proceed because patch %s has requirements on a patch that lacks a build context." % prd.patch_id
            LOG.exception(msg)
            print(msg)
            raise PatchRequirementFail(msg)
            sys.exit(2)

        if built:
            self.patches_built.append(prd.patch_id)
        else:
            self.patches_to_build.append(prd.patch_id)

        prd.gen_xml(fname=self._std_local_path(self._std_xml_patch_recipe_name(prd.patch_id)))

    def build_patches(self):
        global capture_source_flag
        # While unbuild patches exist
        while len(self.patches_to_build) > 0:
            built = 0
            # Search for a buildable patch, i.e. one for whom all requirements are built
            for patch_id in self.patches_to_build:
                prd = self.patch_data[patch_id]
                rc = prd.check_requires_built(self)
                print("check_requires_built(%s) -> %s" % (patch_id, str(rc)))
                if rc:
                    # This patch is ready to build, build it now
                    print("Ready to build patch %s." % patch_id)
                    rc = prd.build_patch()
                    if rc:
                        # append new built patch to order file
                        issue_cmd("sed -i '/^%s$/d' %s" % (patch_id, self._std_local_path(self.order_file)))
                        issue_cmd("echo %s >> %s" % (patch_id, self._std_local_path(self.order_file)))
                        print("Built patch %s." % patch_id)
                        self.patches_built.append(patch_id)
                        self.patches_to_deliver.append(patch_id)
                        self.patches_to_build.remove(patch_id)
                        built += 1

                        if capture_rpms_flag:
                            capture_rpms()

                        if capture_source_flag:
                            prd.capture_source()

                        # It is important to break here.
                        # We just edited the patches_to_build which an enclosing for loop is iterating over.
                        # without the break, the result is skipping patches and/or building patches out of order.
                        break
                    else:
                        msg = "Failed to build patch %s" % patch_id
                        LOG.exception(msg)
                        print(msg)
                        raise PatchBuildFail(msg)
                        sys.exit(2)
            if built == 0:
                msg = "No patches are buildable, Remaining patches: %s" % str(self.patches_to_build)
                LOG.exception(msg)
                print(msg)
                raise PatchBuildFail(msg)
                sys.exit(2)
        print("All patches built.")


class PackageData:
    """
    Package data
    """
    def __init__(self, e):
        self.name = None
        self.personalities = []
        self.architectures = []
        self._parse_package(e)

    def __str__(self):
        return "[ name: %s, personalities: %s, architectures: %s ]" % (str(self.name), str(self.personalities), str(self.architectures))

    def myprint(self, indent=""):
        print("%s%s" % (indent, str(self)))

    def compare(self, package):
        rc = SAME
        if self.name != package.name:
            return MAJOR_DIFF
        if len(self.personalities) != len(package.personalities):
            return MAJOR_DIFF
        if len(self.architectures) != len(package.architectures):
            return MAJOR_DIFF
        for personality in self.personalities:
            if personality not in package.personalities:
                return MAJOR_DIFF
        for arch in self.architectures:
            if arch not in package.architectures:
                return MAJOR_DIFF
        return rc

    def _parse_package(self, e):
        for key in e.attrib:
            val = e.attrib[key]
            # DBG print "_parse_package attr %s" % key
            if key == "name":
                self.name = val
            else:
                msg = "Unknow attribute '%s' in <PATCH_RECIPE><BUILD><RECIPE><PACKAGE>" % key
                LOG.exception(msg)
                print(msg)
                raise PatchRecipeXMLFail(msg)
                sys.exit(2)

        for child in e:
            # DBG print "_parse_package child %s" % child.tag
            if child.tag == "PERSONALITY":
                txt = child.text and child.text.strip() or None
                if txt is None:
                    msg = "personality missing under <PATCH_RECIPE><BUILD><RECIPE><PACKAGE><PERSONALITY>"
                    LOG.exception(msg)
                    print(msg)
                    raise PatchRecipeXMLFail(msg)
                    sys.exit(2)
                self.personalities.append(txt)
            elif child.tag == "ARCH":
                txt = child.text and child.text.strip() or None
                if txt is None:
                    msg = "personality missing under <PATCH_RECIPE><BUILD><RECIPE><PACKAGE><ARCH>"
                    LOG.exception(msg)
                    print(msg)
                    raise PatchRecipeXMLFail(msg)
                    sys.exit(2)
                self.architectures.append(txt)
            else:
                msg = "Unknow tag '%s' under <PATCH_RECIPE><BUILD><RECIPE><PACKAGE>" % child.tag
                LOG.exception(msg)
                print(msg)
                raise PatchRecipeXMLFail(msg)
                sys.exit(2)

    def gen_xml(self, e_package):
        for personality in self.personalities:
            add_text_tag_to_xml(e_package, 'PERSONALITY', personality)
        for arch in self.architectures:
            add_text_tag_to_xml(e_package, 'ARCH', arch)

    def _get_rpm_dir(self, build_type='std', arch=ARCH_DEFAULT, prebuilt=False):
        if prebuilt:
            if build_type == 'std':
                rpm_dir = "%s/%s/repo/cgcs-centos-repo/Binary/%s" % (workdir, build_type, arch)
            else:
                # Any directory with no rpm's would do
                rpm_dir = "%s/%s/repo/cgcs-centos-repo/Data" % (workdir, build_type)
        else:
            rpm_dir = "%s/%s/%s" % (workdir, build_type, RPM_DIR)
        print("================= rpm_dir=%s ============" % rpm_dir)
        return rpm_dir

    def _clean_rpms(self, prebuilt=False):
        global BUILD_TYPES

        print("cleaning self.name %s\n" % self.name)
        for build_type in BUILD_TYPES:
            for arch in self.architectures:
                rpm_dir = self._get_rpm_dir(build_type=build_type, arch=arch, prebuilt=prebuilt)
                rpm_search_pattern = "%s-*%s.rpm" % (self.name, arch)
                print("cleaning arch %s\n" % arch)
                print("cleaning dir %s\n" % rpm_dir)
                print("cleaning rpm_search_pattern %s\n" % rpm_search_pattern)
                for file in os.listdir(rpm_dir):
                    if fnmatch.fnmatch(file, rpm_search_pattern):
                        file_path = "%s/%s" % (rpm_dir, file)
                        if os.path.isfile(file_path):
                            print("cleaning match %s\n" % file)
                            rpm_name_cmd = ["rpm", "-qp", "--dbpath", temp_rpm_db_dir, "--queryformat", "%{NAME}", "%s" % file_path]
                            rpm_name = issue_cmd_w_stdout(rpm_name_cmd)
                            if rpm_name == self.name:
                                rpm_release_cmd = ["rpm", "-qp", "--dbpath", temp_rpm_db_dir, "--queryformat", "%{RELEASE}", "%s" % file_path]
                                rpm_release = issue_cmd_w_stdout(rpm_release_cmd)
                                print("cleaning release %s" % rpm_release)
                                rm_cmd = "rm -f %s/%s-*-%s.%s.rpm" % (rpm_dir, self.name, rpm_release, arch)
                                issue_cmd(rm_cmd)

    def clean(self, prebuilt=False):
        print("package clean")
        self._clean_rpms(prebuilt=prebuilt)

    def _add_rpms(self, pf, arch=ARCH_DEFAULT, fatal=True, prebuilt=False):
        global BUILD_TYPES

        added = 0
        for build_type in BUILD_TYPES:
            rpm_dir = self._get_rpm_dir(build_type=build_type, arch=arch, prebuilt=prebuilt)
            rpm_search_pattern = "%s*%s.rpm" % (self.name, arch)
            for file in os.listdir(rpm_dir):
                if fnmatch.fnmatch(file, rpm_search_pattern):
                    reject = False
                    with open("%s/%s" % (srcdir, SRCDIR_UNBUILT_PATTERN_FILE)) as myfile:
                        for line in myfile:
                            line = line.strip()
                            if line.startswith('#'):
                                continue
                            if len(line) == 0:
                                continue
                            exclude = line
                            exclude_search_pattern = ""
                            if exclude[0] == '^':
                                if exclude[-1] == '$':
                                    exclude_search_pattern = "%s" % (exclude[1:-1])
                                else:
                                    exclude_search_pattern = "%s*" % (exclude[1:])
                            else:
                                if exclude[-1] == '$':
                                    exclude_search_pattern = "*%s" % (exclude[:-1])
                                else:
                                    exclude_search_pattern = "*%s*" % (exclude)
                            if fnmatch.fnmatch(file, exclude_search_pattern):
                                print("reject file '%s' due to pattern '%s' -> '%s'" % (file, exclude, exclude_search_pattern))
                                reject = True
                                break
                    if reject:
                        with open("%s/%s" % (srcdir, SRCDIR_IMAGE_INC_FILE)) as myfile:
                            for line in myfile:
                                line = line.strip()
                                if line.startswith('#'):
                                    continue
                                if len(line) == 0:
                                    continue
                                include_search_pattern = "%s-[0-9]*.rpm" % (line)
                                if fnmatch.fnmatch(file, include_search_pattern):
                                    print("Including file '%s' due to match in IMAGE_INC_FILE '%s'" % (file, SRCDIR_IMAGE_INC_FILE))
                                    reject = False
                                    break

                    # for exclude in RMP_EXCLUDES:
                    #     exclude_search_pattern = "%s%s*.rpm" % (self.name, exclude)
                    #     if fnmatch.fnmatch(file, exclude_search_pattern):
                    #         print "reject file '%s' due to pattern '%s'" % (file, exclude)
                    #         reject = True
                    #         break

                    if not reject:
                        rpm_name_cmd = ["rpm", "-qp", "--dbpath", temp_rpm_db_dir, "--queryformat", "%{NAME}", "%s/%s" % (rpm_dir, file)]
                        rpm_name = issue_cmd_w_stdout(rpm_name_cmd)
                        if rpm_name != self.name:
                            print("reject file '%s' due to rpm_name '%s'" % (file, rpm_name))
                            reject = True
                    if reject:
                        # proceed to next matching file
                        continue
                    print("accept file '%s'" % file)
                    rpm_path = "%s/%s" % (rpm_dir, file)
                    if len(self.personalities) > 0:
                        print("pf.add_rpm(%s, personality=%s)" % (rpm_path, str(self.personalities)))
                        pf.add_rpm(rpm_path, personality=self.personalities)
                        added += 1
                    else:
                        print("pf.add_rpm(%s)" % (rpm_path))
                        pf.add_rpm(rpm_path)
                        added += 1
        if added == 0:
            if fatal:
                msg = "No rpms found matching %s/%s" % (rpm_dir, rpm_search_pattern)
                LOG.exception(msg)
                print(msg)
                raise PatchPackagingFail(msg)
                sys.exit(2)
            msg = "No rpms found matching %s/%s" % (rpm_dir, rpm_search_pattern)
            print(msg)
            raise PatchPackagingMiss(msg)

    def build_patch(self, pf, fatal=True, prebuilt=False):
        if len(self.architectures) > 0:
            for arch in self.architectures:
                self._add_rpms(pf, arch=arch, fatal=fatal, prebuilt=prebuilt)
        else:
            self._add_rpms(pf, fatal=fatal, prebuilt=prebuilt)

    def check_release(self, recipe_name, release_map, prev_release_map):
        if self.name in release_map.keys():
            if self.name in prev_release_map.keys():
                if not rev_lt(prev_release_map[self.name], release_map[self.name]):
                    msg = "Failed to upversion rpm %s in recipe %s: old release %s, new release %s" % (self.name, recipe_name, prev_release_map[self.name], release_map[self.name])
                    LOG.exception(msg)
                    print(msg)
                    raise PatchPackagingFail(msg)
                    sys.exit(2)


class RecipeData:
    """
    Recipe data
    """
    def __init__(self, e):
        self.name = None
        self.prebuilt = False
        self.packages = collections.OrderedDict()  # map package name to PackageData
        self._parse_recipe(e)

    def __str__(self):
        return "name: %s, packages: %s" % (self.name, str(self.packages.keys()))

    def myprint(self, indent=""):
        print("%sname: %s" % (indent, self.name))
        for key in self.packages:
            self.packages[key].myprint("%s   " % indent)

    def compare(self, recipe):
        rc = SAME
        if self.name != recipe.name:
            return MAJOR_DIFF
        if len(self.packages) != len(recipe.packages):
            return MAJOR_DIFF
        if self.prebuilt != recipe.prebuilt:
            return MAJOR_DIFF
        for key in self.packages.keys():
            if key not in recipe.packages.keys():
                return MAJOR_DIFF
            rc2 = self.packages[key].compare(recipe.packages[key])
            if rc2 >= MAJOR_DIFF:
                return MAJOR_DIFF
            if rc2 >= rc:
                rc = rc2
        return rc

    def in_list(self, recipies):
        for recipe in recipies:
            if self.name == recipe.name:
                return True
        return False

    def _parse_recipe(self, e):
        for key in e.attrib:
            val = e.attrib[key]
            # DBG print "_parse_recipe attr %s" % key
            if key == "name":
                self.name = val
            else:
                msg = "Unknow attribute '%s' in <PATCH_RECIPE><BUILD><RECIPE>" % key
                LOG.exception(msg)
                print(msg)
                raise PatchRecipeXMLFail(msg)
                sys.exit(2)

        for child in e:
            # DBG print "_parse_recipe child %s" % child.tag
            if child.tag == "PACKAGE":
                p = PackageData(child)
                self.packages[p.name] = p
            elif child.tag == "PREBUILT":
                self.prebuilt = True
                print("=========== set prebuilt=%s for %s =============" % (self.prebuilt, self.name))
            else:
                msg = "Unknow tag '%s' under <PATCH_RECIPE><BUILD><RECIPE>" % child.tag
                LOG.exception(msg)
                print(msg)
                raise PatchRecipeXMLFail(msg)
                sys.exit(2)

    def gen_xml(self, e_recipe):
        if self.prebuilt:
            ElementTree.SubElement(e_recipe, 'PREBUILT')

        for package in self.packages.keys():
            e_package = ElementTree.SubElement(e_recipe, 'PACKAGE', attrib={'name': package})
            self.packages[package].gen_xml(e_package)

    def clean(self):
        print("recipe clean")
        if not self.prebuilt:
            for package in self.packages:
                self.packages[package].clean(prebuilt=self.prebuilt)

    def capture_source(self):
        self.name
        my_repo = None
        path = capture_source_path
        extra_arg = ""

        if 'MY_REPO' in os.environ.keys():
            my_repo = os.environ['MY_REPO']

        if 'MY_PATCH_REPO' in os.environ.keys():
            my_repo = os.environ['MY_PATCH_REPO']

        if my_repo is not None:
            altpath = "%s/stx/extras.ND/scripts/source_collect_package" % my_repo
            if os.path.isfile(altpath):
                path = altpath

        if self.prebuilt:
            extra_arg = "--prebuilt"

        if os.path.isfile(path):
            rc = issue_cmd_rc("%s %s %s >> %s/%s.log" % (path, self.name, extra_arg, os.environ['DEST'], os.environ['PREFIX']))

    def build_patch(self, pf, fatal=True):
        for package in self.packages:
            self.packages[package].build_patch(pf, fatal=fatal, prebuilt=self.prebuilt)

    def check_release(self, release_map, prev_release_map):
        for package in self.packages:
            self.packages[package].check_release(self.name, release_map, prev_release_map)

    def is_prebuilt(self):
        print("=========== is_prebuilt prebuilt=%s for %s =============" % (self.prebuilt, self.name))
        return self.prebuilt


class PatchRecipeData:
    """
    Patch recipe data
    """
    def __init__(self, built=False, pl=None):
        self.patch_id = None
        self.sw_version = None
        self.built = built
        self.build_context = None
        self.metadata = collections.OrderedDict()
        self.requires = []
        self.auto_requires = []
        self.recipies = collections.OrderedDict()   # recipe name to RecipeData
        self.pl = pl

    def compare(self, prd):
        rc = SAME
        if self.patch_id != prd.patch_id:
            return MAJOR_DIFF
        if self.built != prd.built:
            rc = MINOR_DIFF
        if len(self.metadata) != len(prd.metadata):
            return MAJOR_DIFF
        if len(self.requires) != len(prd.requires):
            return MAJOR_DIFF
        if len(self.recipies) != len(prd.recipies):
            return MAJOR_DIFF
        for require in self.requires:
            if require not in prd.requires:
                return MAJOR_DIFF
        for item in self.metadata.keys():
            if item not in prd.metadata.keys():
                return MAJOR_DIFF
            if self.metadata[item] != prd.metadata[item]:
                if item == "STATUS":
                    rc = MINOR_DIFF
                else:
                    return MAJOR_DIFF
        for recipe in self.recipies.keys():
            if recipe not in prd.recipies.keys():
                return MAJOR_DIFF
            rc2 = self.recipies[recipe].compare(prd.recipies[recipe])
            if rc2 >= MAJOR_DIFF:
                return MAJOR_DIFF
            if rc2 >= rc:
                rc = rc2
        return rc

    def set_implicit_requires(self, patch_list):
        self.auto_requires = patch_list.get_implicit_requires(self.patch_id, self.recipies.keys())

    def get_build_context(self):
        return self.build_context

    def check_requires_known(self, patch_list):
        rc = True
        for patch in self.requires:
            if not patch_list.is_known(patch):
                print("patch '%s' is missing required patch '%s'" % (self.patch_id, patch))
                rc = False
        for patch in self.auto_requires:
            if not patch_list.is_known(patch):
                print("patch '%s' is missing implicitly required patch '%s'" % (self.patch_id, patch))
                rc = False
        return rc

    def check_requires_buildable(self, patch_list):
        rc = True
        for patch in self.requires:
            if not patch_list.is_built(patch):
                ctx = patch_list.patch_data[patch].get_build_context()
                if ctx is None:
                    print("patch '%s' requires patch '%s' to be built first, but lack a context to do so" % (self.patch_id, patch))
                    rc = False
        for patch in self.auto_requires:
            if not patch_list.is_built(patch):
                ctx = patch_list.patch_data[patch].get_build_context()
                if ctx is None:
                    print("patch '%s' requires patch '%s' to be built first, but lack a context to do so" % (self.patch_id, patch))
                    rc = False
        return rc

    def check_requires_built(self, patch_list):
        rc = True
        for patch in self.requires:
            if not patch_list.is_built(patch):
                print("patch '%s' requires patch '%s' to be built first" % (self.patch_id, patch))
                rc = False
        for patch in self.auto_requires:
            if not patch_list.is_built(patch):
                print("patch '%s' requires patch '%s' to be built first" % (self.patch_id, patch))
                rc = False
        return rc

    def has_common_recipies(self, recipies):
        for recipe in self.recipies.keys():
            if recipe in recipies:
                return True
        return False

    def build(self):
        if self.built:
            return 0
        return 0

    def _parse_requires(self, e):
        for child in e:
            # DBG print "_parse_requires %s" % child.tag
            if child.tag == "ID":
                req = child.text and child.text.strip() or None
                if req is None:
                    msg = "Patch id missing under <PATCH_RECIPE><METADATA><REQUIRES><ID>"
                    LOG.exception(msg)
                    print(msg)
                    raise PatchRecipeXMLFail(msg)
                    sys.exit(2)
                self.requires.append(req)
            else:
                msg = "Unknow tag '%s' under <PATCH_RECIPE><METADATA><REQUIRES>" % child.tag
                LOG.exception(msg)
                print(msg)
                raise PatchRecipeXMLFail(msg)
                sys.exit(2)

    def _parse_metadata(self, e):
        for child in e:
            # DBG print "_parse_metadata %s" % child.tag
            if child.tag == "REQUIRES":
                self._parse_requires(child.getchildren())
            elif child.tag in METADATA_TAGS:
                self.metadata[child.tag] = child.text and child.text.strip() or ""
            else:
                msg = "Unknow tag '%s' under <PATCH_RECIPE><METADATA>" % child.tag
                LOG.exception(msg)
                print(msg)
                raise PatchRecipeXMLFail(msg)
                sys.exit(2)

    def _parse_build(self, e):
        for child in e:
            # DBG print "_parse_build %s" % child.tag
            if child.tag == "RECIPE":
                r = RecipeData(child)
                self.recipies[r.name] = r
            elif child.tag == "CONTEXT":
                self.build_context = child.text and child.text.strip() or None
                print("====== CONTEXT = %s ========" % self.build_context)
            else:
                msg = "Unknow tag '%s' under <PATCH_RECIPE><BUILD>" % child.tag
                LOG.exception(msg)
                print(msg)
                raise PatchRecipeXMLFail(msg)
                sys.exit(2)

    def _parse_root(self, e):
        for child in e:
            # DBG print "_parse_root %s" % child.tag
            if child.tag == "METADATA":
                self._parse_metadata(child.getchildren())
            elif child.tag == "BUILD":
                self._parse_build(child.getchildren())
            else:
                msg = "Unknow tag '%s' under <PATCH_RECIPE>" % child.tag
                LOG.exception(msg)
                print(msg)
                raise PatchRecipeXMLFail(msg)
                sys.exit(2)
        if 'ID' in self.metadata:
            self.patch_id = self.metadata['ID']
        else:
            msg = "patch is missing required field <PATCH_RECIPE><METADATA><ID>"
            LOG.exception(msg)
            print(msg)
            raise PatchRecipeXMLFail(msg)
            sys.exit(2)

        if 'SW_VERSION' in self.metadata:
            self.sw_version = self.metadata['SW_VERSION']
            if self.sw_version != build_info['SW_VERSION']:
                msg = "patch '%s' SW_VERSION is inconsistent with that of workdir '%s'" % (self.patch_id, workdir)
                LOG.exception(msg)
                print(msg)
                raise PatchRecipeXMLFail(msg)
                sys.exit(2)

        else:
            msg = "patch '%s' is missing required field <PATCH_RECIPE><METADATA><SW_VERSION>" % self.patch_id
            LOG.exception(msg)
            print(msg)
            raise PatchRecipeXMLFail(msg)
            sys.exit(2)

        print("_parse_root patch_id = '%s'" % self.patch_id)

    def recursive_print(self, e, depth=0):
        for child in e:
            print("%sTag: %s, attr: %s, text: %s" % (" " * depth, child.tag, child.attrib, child.text and child.text.strip() or ""))
            self.recursive_print(child.getchildren(), depth + 1)
        # for child in e.iter('BUILD'):
        #     print "Tag: %s, attr: %s" % (child.tag, child.attrib)

    def parse_xml(self,
                  filename,
                  adminstate=None):
        """
        Parse an individual patch recipe XML file
        :param filename: XML file
        :param adminstate: Indicates Applied or Available
        :return: Patch ID
        """
        tree = ElementTree.parse(filename)
        root = tree.getroot()

        # DBG print("tree: %r" % dir(tree))
        # DBG print("root: %r" % dir(root))
        # DBG self.recursive_print(root)
        self._parse_root(root)
        self.myprint()

    def write_xml_file(self, top, fname):
        # Generate the file, in a readable format if possible
        outfile = open(fname, 'w')
        rough_xml = ElementTree.tostring(top, 'utf-8')
        if platform.python_version() == "2.7.2":
            # The 2.7.2 toprettyxml() function unnecessarily indents
            # childless tags, adding whitespace. In the case of the
            # yum comps.xml file, it makes the file unusable, so just
            # write the rough xml
            outfile.write(rough_xml)
        else:
            outfile.write(minidom.parseString(rough_xml).toprettyxml(indent="  "))

    def gen_xml(self, fname="metadata.xml"):
        """
        Generate patch recipe XML file
        :param fname: Path to output file
        :return:
        """
        e_top = ElementTree.Element('PATCH_RECIPE')
        e_metadata = ElementTree.SubElement(e_top, 'METADATA')
        for key in self.metadata.keys():
            add_text_tag_to_xml(e_metadata, key, self.metadata[key])
        if len(self.requires) > 0:
            e_requires = ElementTree.SubElement(e_metadata, 'REQUIRES')
            for require in self.requires:
                add_text_tag_to_xml(e_requires, 'ID', require)
        e_build = ElementTree.SubElement(e_top, 'BUILD')
        if self.build_context:
            add_text_tag_to_xml(e_build, 'CONTEXT', self.build_context)
        else:
            add_text_tag_to_xml(e_build, 'CONTEXT', patch_id_to_tag(self.patch_id))
        for recipe in self.recipies.keys():
            e_recipe = ElementTree.SubElement(e_build, 'RECIPE', attrib={'name': recipe})
            self.recipies[recipe].gen_xml(e_recipe)

        write_xml_file(e_top, fname)

    def __str__(self):
        return "[ patch_id: %s, context:  %s, metadata: %s, requires: %s, recipies: %s ]" % (str(self.patch_id), str(self.build_context), str(self.metadata), str(self.requires), str(self.recipies.keys()))

    def myprint(self, indent=""):
        print("patch_id: %s" % str(self.patch_id))
        print("context:  %s" % str(self.build_context))
        print("metadata: %s" % str(self.metadata))
        print("requires: %s" % str(self.requires))
        for key in self.recipies:
            self.recipies[key].myprint("%s   " % indent)

    def _configure(self):
        if workdir is None:
            msg = "workdir not provided"
            LOG.exception(msg)
            print(msg)
            raise PatchBuildFail(msg)
            sys.exit(2)
            return False

        os.chdir(workdir)

    def _set_context(self):
        global pre_compiled_flag

        if pre_compiled_flag:
            return

        if (self.build_context is None) and (branch is None):
            # Nothing to do
            return

        if srcdir is None:
            msg = "srcdir not provided"
            LOG.exception(msg)
            print(msg)
            raise PatchBuildFail(msg)
            sys.exit(2)
            return False

        os.chdir(srcdir)

        if self.build_context is not None:
            # Before checkout, make sure there are no untracked temporary files
            # left by a previous build that may prevent the checkout...
            # e.g. horizon's pbr-2015.1.0-py2.7.egg directory is a build artifact
            issue_cmd("for d in $(find . -type d -name .git | xargs --max-args=1 dirname); do (cd $d; echo $d; git clean -df; git reset --hard; git ls-files --others --exclude-standard | xargs --no-run-if-empty rm; if [ ! -f .subgits ]; then if [ -f .gitignore ]; then git ls-files --others --ignored --exclude-from=.gitignore  | xargs --no-run-if-empty rm; fi; fi); done")
            issue_cmd("wrgit checkout %s" % self.build_context)
        elif branch is not None:
            issue_cmd("wrgit checkout %s" % branch)
        else:
            msg = "Don't know what build context to use for patch %s" % self.patch_id
            LOG.exception(msg)
            print(msg)
            raise PatchBuildFail(msg)
            sys.exit(2)
            return False

        if workdir is None:
            msg = "workdir not provided"
            LOG.exception(msg)
            print(msg)
            raise PatchBuildFail(msg)
            sys.exit(2)
            return False

        return True

    def _get_prev_patch_id(self, patch_id):
        patch_order_file = self.pl._std_local_path(self.pl.order_file)
        prev_patch_id = None
        with open(patch_order_file) as f:
            for line in f:
                this_patch_id = line.strip()
                if patch_id == this_patch_id:
                    return prev_patch_id
                prev_patch_id = this_patch_id
        return prev_patch_id

    def _get_rpm_db_path(self, patch_id):
        rpm_db = self.pl._std_local_path("%s.rpm_db" % patch_id)
        return rpm_db

    def _write_rpm_db(self):
        global BUILD_TYPES

        for build_type in BUILD_TYPES:
            rpm_dir = "%s/%s/%s" % (workdir, build_type, RPM_DIR)
            rpm_db = self._get_rpm_db_path(self.patch_id)
            issue_cmd("echo > %s" % rpm_db)
            for subdir in os.walk(rpm_dir).next()[1]:
                rpm_sub_dir = "%s/%s" % (rpm_dir, subdir)
                issue_cmd("rpm -qp --dbpath %s --queryformat '%s %%{NAME} %%{RELEASE}\n' %s/*rpm >> %s 2> /dev/null" % (temp_rpm_db_dir, subdir, rpm_sub_dir, rpm_db))

    def _read_rpm_db(self, patch_id):
        release_map = {}
        rpm_db_dir = "export/patch_data"
        rpm_db = self._get_rpm_db_path(patch_id)
        with open(rpm_db) as f:
            for line in f:
                words = line.split()
                if len(words) == 3:
                    arch = words[0]
                    rpm = words[1]
                    release = words[2]
                    release_map[rpm] = release[1:]
        return release_map

    def check_release(self):
        prev_patch_id = self._get_prev_patch_id(self.patch_id)
        if prev_patch_id is None:
            delim = "_"
            words = self.patch_id.split(delim)
            word_lens = len(words[-1])
            words[-1] = '0' * word_lens
            prev_patch_id = delim.join(words)
        prev_release_map = self._read_rpm_db(prev_patch_id)
        release_map = self._read_rpm_db(self.patch_id)
        for recipe in self.recipies.keys():
            self.recipies[recipe].check_release(release_map, prev_release_map)

    def capture_source(self):
        os.environ['PREFIX'] = self.patch_id
        os.environ['MY_REPO'] = os.environ['MY_PATCH_REPO']
        os.environ['MY_WORKSPACE'] = os.environ['MY_PATCH_WORKSPACE']
        os.environ['DEST'] = "%s/export/patch_source/%s" % (os.environ['MY_PATCH_WORKSPACE'], self.patch_id)
        issue_cmd("mkdir -p %s" % os.environ['DEST'])
        for recipe in self.recipies.keys():
            print("capture source of recipe %s" % recipe)
            self.recipies[recipe].capture_source()

    def build_patch(self, local_path="."):
        global pre_compiled_flag
        global pre_clean_flag
        self._set_context()
        self._configure()

        recipe_str = ""
        build_recipe_str = ""
        for recipe in self.recipies.keys():
            recipe_str += recipe + " "
            if not self.recipies[recipe].is_prebuilt():
                build_recipe_str += recipe + " "
        print("recipe_str = %s" % recipe_str)
        print("build_recipe_str = %s" % build_recipe_str)
        if recipe_str == "":
            msg = "No recipies for patch %s" % self.patch_id
            LOG.exception(msg)
            print(msg)
            raise PatchBuildFail(msg)
            sys.exit(2)
            return False

        if pre_compiled_flag and pre_clean_flag:
            print("pre clean")
            for recipe in self.recipies.keys():
                print("pre clean recipe %s" % recipe)
                self.recipies[recipe].clean()
            print("done")
            sys.exit(0)

        if not pre_compiled_flag:
            # compile patch
            os.chdir(workdir)
            print("pre clean")
            if build_recipe_str == "":
                print(" ... nothing to clean")
            else:
                issue_cmd("build-pkgs  --no-build-info --clean %s" % build_recipe_str)
                for recipe in self.recipies.keys():
                    print("pre clean recipe %s" % recipe)
                    self.recipies[recipe].clean()
            print("Build")
            if build_recipe_str == "":
                print(" ... nothing to build")
            else:
                issue_cmd("build-pkgs --no-build-info --careful %s" % build_recipe_str)

        # create rpm release number db
        self._write_rpm_db()

        if not pre_compiled_flag:
            # check rpm release numbers
            self.check_release()

        # assemble patch
        pf = PatchFile()
        if self.patch_id:
            pf.meta.id = self.patch_id
        if 'STATUS' in self.metadata:
            pf.meta.status = self.metadata['STATUS']
        else:
            pf.meta.status = STATUS_DEVELOPEMENT
        if 'UNREMOVABLE' in self.metadata:
            pf.meta.removable = self.metadata['UNREMOVABLE']
        if 'SUMMARY' in self.metadata:
            pf.meta.summary = self.metadata['SUMMARY']
        if 'DESCRIPTION' in self.metadata:
            pf.meta.description = self.metadata['DESCRIPTION']
        if 'INSTALL_INSTRUCTIONS' in self.metadata:
            pf.meta.install_instructions = self.metadata['INSTALL_INSTRUCTIONS']
        if 'WARNINGS' in self.metadata:
            pf.meta.warnings = self.metadata['WARNINGS']
        if 'SW_VERSION' in self.metadata:
            pf.meta.sw_version = self.metadata['SW_VERSION']
        if 'REBOOT_REQUIRED' in self.metadata:
            pf.meta.reboot_required = self.metadata['REBOOT_REQUIRED']

        for patch in list(set(self.requires) | set(self.auto_requires)):
            pf.meta.requires.append(patch)

        for recipe in self.recipies.keys():
            if not pre_compiled_flag:
                self.recipies[recipe].build_patch(pf, fatal=True)
            else:
                try:
                    self.recipies[recipe].build_patch(pf, fatal=False)
                except PatchPackagingMiss:
                    print("Warning: attempting rebuild of recipe %s" % self.recipies[recipe].name)
                    if not self.recipies[recipe].is_prebuilt():
                        issue_cmd("build-pkgs --no-build-info --careful %s" % self.recipies[recipe].name)
                    self.recipies[recipe].build_patch(pf, fatal=True)

        local_path = self.pl._std_local_path("")
        print("=== local_path = %s ===" % local_path)
        pf.gen_patch(outdir=local_path)

        return True


def _tag_build_context(patch_id):
    os.chdir(srcdir)
    issue_cmd("for e in . `wrgit all-core-gits` ; do (cd $e ; git tag v%s) done" % patch_id)


def read_build_info():
    try:
        build_info_find_cmd = ["find", "std/rpmbuild/RPMS/", "-name", "build-info-[0-9]*.x86_64.rpm"]
        build_info_path = issue_cmd_w_stdout(build_info_find_cmd)
        if build_info_path == "":
            issue_cmd("build-pkgs --no-descendants build-info")

        issue_cmd("rpm2cpio std/rpmbuild/RPMS/build-info-[0-9]*.x86_64.rpm | cpio -i --to-stdout --quiet ./etc/build.info > %s" % WORKDIR_BUILD_INFO_LOCATION)
        with open(WORKDIR_BUILD_INFO_LOCATION) as myfile:
            for line in myfile:
                line = line.strip()
                if line.startswith('#'):
                    continue
                if len(line) == 0:
                    continue

                name, var = line.partition("=")[::2]
                name = name.strip()
                var = var.strip()
                if var.startswith('"') and var.endswith('"'):
                    var = var[1:-1]
                build_info[name] = var
    except Exception:
        return False
    return True


def patch_id_to_tag(patch_id):
    tag = "v%s" % patch_id
    return tag


def validate_tag(tag):
    try:
        cmd = "git tag | grep %s" % tag
        issue_cmd(cmd)
    except PatchRecipeCmdFail:
        msg = "TAG '%s' is invalid" % tag
        LOG.exception(msg)
        print(msg)
        return False
    return True


def issue_cmd_w_stdout(cmd):
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = p.communicate()[0]
    rc = p.returncode
    if rc != 0:
        msg = "CMD failed: %s" % str(cmd)
        LOG.exception(msg)
        print(msg)
        raise PatchRecipeCmdFail(msg)
    return out


def issue_cmd(cmd):
    print("CMD: %s" % cmd)
    rc = subprocess.call(cmd, shell=True)
    if rc != 0:
        msg = "CMD failed: %s" % cmd
        LOG.exception(msg)
        print(msg)
        raise PatchRecipeCmdFail(msg)


def issue_cmd_no_raise(cmd):
    print("CMD: %s" % cmd)
    rc = subprocess.call(cmd, shell=True)
    if rc != 0:
        msg = "CMD failed: %s" % cmd
        LOG.exception(msg)
        print(msg)


def issue_cmd_rc(cmd):
    print("CMD: %s" % cmd)
    rc = subprocess.call(cmd, shell=True)
    return rc


def set_capture_source_path():
    global capture_source_path
    my_repo = None
    new_dir = "/tmp/%s" % os.environ['USER']
    new_path = "%s/source_collect_package" % new_dir

    if 'MY_REPO' in os.environ.keys():
        my_repo = os.environ['MY_REPO']

    if 'MY_PATCH_REPO' in os.environ.keys():
        my_repo = os.environ['MY_PATCH_REPO']

    if my_repo is not None:
        old_path = "%s/stx/extras.ND/scripts/source_collect_package" % my_repo
        if os.path.isfile(old_path):
            rc = issue_cmd_rc("mkdir -p %s" % new_dir)
            rc = issue_cmd_rc("\cp -f %s %s" % (old_path, new_path))
            if rc == 0:
                capture_source_path = new_path


def capture_rpms():
    for build_type in BUILD_TYPES:
        src_rpm_dir = "%s/%s/%s" % (workdir, build_type, RPM_DIR)
        if os.path.isdir(src_rpm_dir):
            dest_rpm_dir = "%s/%s/%s" % (workdir, build_type, RPM_ARCHIVE_DIR)
            issue_cmd("mkdir -p %s" % dest_rpm_dir)
            issue_cmd("rsync -avu %s/*.rpm %s" % (src_rpm_dir, dest_rpm_dir))


def modify_patch_usage():
    msg = "modify_patch [ --obsolete | --released | --development ] [ --sw_version <version> --id <patch_id> | --file <patch_path.patch> ]"
    LOG.exception(msg)
    print(msg)
    sys.exit(1)


def modify_patch():
    global workdir
    global temp_rpm_db_dir
    global sw_version
    global build_info

    configure_logging(logtofile=False)

    try:
        opts, remainder = getopt.getopt(sys.argv[1:],
                                        'h',
                                        ['help',
                                         'obsolete',
                                         'released',
                                         'development',
                                         'sw_version=',
                                         'id=',
                                         'file=',
                                         ])
    except getopt.GetoptError as e:
        print(str(e))
        modify_patch_usage()

    patch_path = None
    cwd = os.getcwd()

    status_set = False

    for opt, arg in opts:
        if opt == "--obsolete":
            if status_set:
                modify_patch_usage()
            status_set = True
            new_status = STATUS_OBSOLETE
        elif opt == "--released":
            if status_set:
                modify_patch_usage()
            status_set = True
            new_status = STATUS_RELEASED
        elif opt == "--development":
            if status_set:
                modify_patch_usage()
            status_set = True
            new_status = STATUS_DEVELOPEMENT
        elif opt == "--file":
            patch_path = os.path.normpath(os.path.join(cwd, os.path.expanduser(arg)))
        elif opt == "--sw_version":
            sw_version = arg
        elif opt == "--id":
            patch_id = arg
        elif opt in ("-h", "--help"):
            modify_patch_usage()
        else:
            print("unknown option '%s'" % opt)
            modify_patch_usage()

    if not status_set:
        print("new status not specified")
        modify_patch_usage()

    workdir = tempfile.mkdtemp(prefix="patch_modify_")
    os.chdir(workdir)
    try:
        temp_rpm_db_dir = "%s/%s" % (workdir, ".rpmdb")
        if patch_path is not None:
            rc = PatchFile.modify_patch(patch_path, "status", new_status)
            assert(rc)
            print("Patch '%s' has been modified to status '%s'" % (patch_path, new_status))
        else:
            if sw_version is None or patch_id is None:
                print("--sw_version and --id are required")
                shutil.rmtree(workdir)
                modify_patch_usage()

            build_info['SW_VERSION'] = sw_version
            pl = PatchList([])
            patch_file_name = "%s.patch" % patch_id
            patch_path = pl._std_patch_git_path(patch_file_name)
            print("patch_id = %s" % patch_id)
            print("patch_file_name = %s" % patch_file_name)
            print("patch_path = %s" % patch_path)
            rc = PatchFile.modify_patch(patch_path, "status", new_status)
            assert(rc)
            os.chdir(pl._std_patch_git_path(".."))
            issue_cmd("git add %s" % patch_path)
            issue_cmd("git commit -m \"Modify status of patch '%s' to '%s'\"" % (patch_id, new_status))
            issue_cmd("git push --dry-run --set-upstream origin %s:%s" % (sw_version, sw_version))
            issue_cmd("git push --set-upstream origin %s:%s" % (sw_version, sw_version))
            print("Patch '%s' has been modified to status '%s'" % (patch_id, new_status))

            if new_status == STATUS_RELEASED:
                tm = time.localtime(time.time())
                ts = time.strftime("%Y%m%d", tm)
                munged_patch_id = re.sub('[_.]', '-', patch_id.lower())
                swv = sw_version.split(".")
                sw_mjr = swv[0]
                local_dest = ""
                deliver_dest = ""

                local_dest = "/folk/cgts/rel-ops/%s/patches/" % sw_version
                deliver_dest = "/folk/prj-wrlinux/release/tis/tis-%s/update/ti%s-%s/Titanium-Cloud-%s/patches" % (sw_mjr, ts, munged_patch_id, sw_mjr)
                human_release = "Titanium Cloud %s" % sw_mjr
                windshare_folder = "Titanium-Cloud-%s" % sw_mjr

                if sw_version == "14.10":
                    local_dest = "/folk/cgts/rel-ops/Titanium-Server-14/patches/%s" % sw_version
                    deliver_dest = "/folk/prj-wrlinux/release/tis/tis-14/update/ti%s-%s/Titanium-Server-14/patches" % (ts, munged_patch_id)
                    human_release = "Titanium server 14"
                    windshare_folder = "Titanium-server-14"

                if sw_version == "15.04" or sw_version == "15.10":
                    local_dest = "/folk/cgts/rel-ops/%s/patches/" % sw_version
                    deliver_dest = ""
                    human_release = "Titanium server 15"
                    windshare_folder = ""

                if sw_version == "15.05":
                    local_dest = "/folk/cgts/rel-ops/%s/patches/" % sw_version
                    deliver_dest = "/folk/prj-wrlinux/release/tis/tis-15/update/ti%s-%s/Titanium-Server-15.05-ER/patches" % (ts, munged_patch_id)
                    human_release = "Titanium server 15"
                    windshare_folder = "Titanium-server-15.05-ER"

                if sw_version == "15.09":
                    local_dest = "/folk/cgts/rel-ops/%s/patches/" % sw_version
                    deliver_dest = "/folk/prj-wrlinux/release/tis/tis-15/update/ti%s-%s/Titanium-Server-15.09-ER/patches" % (ts, munged_patch_id)
                    human_release = "Titanium server 15"
                    windshare_folder = "Titanium-server-15.09-ER"

                if sw_version == "15.12":
                    local_dest = "/folk/cgts/rel-ops/%s/patches/" % sw_version
                    deliver_dest = "/folk/prj-wrlinux/release/tis/tis-2/update/ti%s-%s/Titanium-Server-2/patches" % (ts, munged_patch_id)
                    human_release = "Titanium Cloud 2"
                    windshare_folder = "Titanium-Cloud-2"

                if sw_version == "16.10":
                    local_dest = "/folk/cgts/rel-ops/%s/patches/" % sw_version
                    deliver_dest = "/folk/prj-wrlinux/release/tis/tis-3/update/ti%s-%s/Titanium-Server-3/patches" % (ts, munged_patch_id)
                    human_release = "Titanium Cloud 3"
                    windshare_folder = "Titanium-Cloud-3"

                if sw_version == "17.06":
                    local_dest = "/folk/cgts/rel-ops/%s/patches/" % sw_version
                    deliver_dest = "/folk/prj-wrlinux/release/tis/tis-4/update/ti%s-%s/Titanium-Cloud-4/patches" % (ts, munged_patch_id)
                    human_release = "Titanium Cloud 4"
                    windshare_folder = "Titanium-Cloud-4"

                if sw_version == "18.03" or sw_version == "18.03":
                    local_dest = "/folk/cgts/rel-ops/%s/patches/" % sw_version
                    deliver_dest = "/folk/prj-wrlinux/release/tis/tis-5/update/ti%s-%s/Titanium-Cloud-5/patches" % (ts, munged_patch_id)
                    human_release = "Titanium Cloud 5"
                    windshare_folder = "Titanium-Cloud-5"

                if local_dest != "":
                    issue_cmd("mkdir -p %s" % local_dest)
                    issue_cmd_no_raise("chmod 775 %s" % os.path.dirname(os.path.dirname(local_dest)))
                    issue_cmd_no_raise("chmod 775 %s" % os.path.dirname(local_dest))
                    issue_cmd_no_raise("chmod 775 %s" % local_dest)
                    issue_cmd("cp %s %s" % (patch_path, local_dest))
                    issue_cmd("md5sum %s | sed 's:%s:%s:' > %s/%s.md5" % (patch_path, patch_path, patch_file_name, local_dest, patch_file_name))
                    issue_cmd_no_raise("chmod 664 %s/%s" % (local_dest, patch_file_name))
                    issue_cmd_no_raise("chmod 664 %s/%s.md5" % (local_dest, patch_file_name))

                if deliver_dest != "":
                    issue_cmd("mkdir -p %s" % deliver_dest)
                    issue_cmd_no_raise("chmod 775 %s" % os.path.dirname(os.path.dirname(deliver_dest)))
                    issue_cmd_no_raise("chmod 775 %s" % os.path.dirname(deliver_dest))
                    issue_cmd_no_raise("chmod 775 %s" % deliver_dest)
                    issue_cmd("cp %s %s" % (patch_path, deliver_dest))
                    issue_cmd("md5sum %s | sed 's:%s:%s:' > %s/%s.md5" % (patch_path, patch_path, patch_file_name, deliver_dest, patch_file_name))
                    issue_cmd_no_raise("chmod 664 %s/%s" % (deliver_dest, patch_file_name))
                    issue_cmd_no_raise("chmod 664 %s/%s.md5" % (deliver_dest, patch_file_name))

                    print("")
                    print("Go here to deliver the patch")
                    print("   http://deliveryplus.windriver.com/update/release")
                    print("Login if required")
                    print("")
                    print("Release to be updated:")
                    print("   select '%s'" % human_release)
                    print("press 'select' and wait for next page to load.")
                    print("")
                    print("Windshare folder to be uploaded:")
                    print("   select '%s'" % windshare_folder)
                    print("Subdirectory of WindShare folder in which to place updates:")
                    print("   select 'patches'")
                    print("Pathname from which to copy update content:")
                    print("   %s" % deliver_dest)
                    print("press 'Release to Production'")
                    print("")

    except Exception:
        print("Failed to modify patch!")
    finally:
        shutil.rmtree(workdir)


def query_patch_usage():
    msg = "query_patch [ --sw_version <version> --id <patch_id> | --file <patch_path.patch> ] [ --field <field_name> ]"
    LOG.exception(msg)
    print(msg)
    msg = "   field_name = [ status | summary | description | install_instructions | warnings | contents | requires ]"
    LOG.exception(msg)
    print(msg)
    sys.exit(1)


def query_patch():
    global workdir
    global temp_rpm_db_dir
    global sw_version
    global build_info

    configure_logging(logtofile=False)

    try:
        opts, remainder = getopt.getopt(sys.argv[1:],
                                        'h',
                                        ['help',
                                         'sw_version=',
                                         'id=',
                                         'file=',
                                         'field=',
                                         ])
    except getopt.GetoptError as e:
        print(str(e))
        query_patch_usage()

    patch_path = None
    cwd = os.getcwd()
    field = None

    for opt, arg in opts:
        if opt == "--file":
            patch_path = os.path.normpath(os.path.join(cwd, os.path.expanduser(arg)))
        elif opt == "--sw_version":
            sw_version = arg
        elif opt == "--id":
            patch_id = arg
        elif opt == "--field":
            field = arg
        elif opt in ("-h", "--help"):
            query_patch_usage()
        else:
            print("unknown option '%s'" % opt)
            query_patch_usage()

    workdir = tempfile.mkdtemp(prefix="patch_modify_")
    os.chdir(workdir)
    try:
        temp_rpm_db_dir = "%s/%s" % (workdir, ".rpmdb")
        if patch_path is not None:
            answer = PatchFile.query_patch(patch_path, field=field)
            field_order = ['id', 'sw_version', 'status', 'cert', 'reboot_required', 'unremovable', 'summary', 'description', 'install_instructions', 'warnings']
            for k in field_order:
                if k in answer.keys():
                    print("%s: '%s'" % (k, answer[k]))
            # Print any remaining fields, any order
            for k in answer.keys():
                if k not in field_order:
                    print("%s: '%s'" % (k, answer[k]))
        else:
            if sw_version is None or patch_id is None:
                print("--sw_version and --id are required")
                shutil.rmtree(workdir)
                query_patch_usage()

            build_info['SW_VERSION'] = sw_version
            pl = PatchList([])
            patch_file_name = "%s.patch" % patch_id
            patch_path = pl._std_patch_git_path(patch_file_name)
            print("patch_id = %s" % patch_id)
            print("patch_file_name = %s" % patch_file_name)
            print("patch_path = %s" % patch_path)
            answer = PatchFile.query_patch(patch_path, field=field)
            print(str(answer))

    except Exception:
        print("Failed to query patch!")
    finally:
        shutil.rmtree(workdir)


def make_patch_usage():
    msg = "make_patch [--formal | --pre-compiled [--pre-clean]] [--workdir <path>] [--srcdir <path>] [--branch <name>] [--capture_source] [--capture_rpms] [ --all --sw_version <version> | <patch_recipe.xml> ]"
    LOG.exception(msg)
    print(msg)
    sys.exit(1)


def make_patch():
    global workdir
    global temp_rpm_db_dir
    global srcdir
    global branch
    global sw_version
    global formal_flag
    global pre_compiled_flag
    global pre_clean_flag
    global all_flag
    global capture_source_flag
    global capture_rpms_flag
    patch_list = []

    configure_logging(logtofile=False)

    try:
        opts, remainder = getopt.getopt(sys.argv[1:],
                                        'h',
                                        ['help',
                                         'all',
                                         'capture_source',
                                         'capture_rpms',
                                         'formal',
                                         'pre-compiled',
                                         'pre-clean',
                                         'release=',
                                         'workdir=',
                                         'srcdir=',
                                         'branch=',
                                         'sw_version=',
                                         ])
    except getopt.GetoptError as e:
        print(str(e))
        make_patch_usage()

    cwd = os.getcwd()

    for opt, arg in opts:
        if opt == "--formal":
            formal_flag = True
        elif opt == "--pre-compiled":
            pre_compiled_flag = True
        elif opt == "--pre-clean":
            pre_clean_flag = True
        elif opt == "--all":
            all_flag = True
        elif opt == "--capture_source":
            capture_source_flag = True
            set_capture_source_path()
        elif opt == "--capture_rpms":
            capture_rpms_flag = True
        elif opt == "--workdir":
            workdir = os.path.normpath(os.path.join(cwd, os.path.expanduser(arg)))
        elif opt == "--srcdir":
            srcdir = os.path.normpath(os.path.join(cwd, os.path.expanduser(arg)))
        elif opt == "--branch":
            branch = arg
        elif opt == "--sw_version":
            sw_version = arg
        elif opt in ("-h", "--help"):
            make_patch_usage()
        else:
            print("unknown option '%s'" % opt)
            make_patch_usage()

    for x in remainder:
        patch_list.append(os.path.normpath(os.path.join(cwd, os.path.expanduser(x))))

    if len(patch_list) <= 0 and not all_flag:
        print("Either '--all' or a patch.xml must be specified")
        make_patch_usage()

    if all_flag and len(patch_list) > 0:
        print("only specify one of '--all' or a patch.xml")
        make_patch_usage()

    if len(patch_list) > 1:
        print("only one patch.xml can be specified")
        make_patch_usage()

    if all_flag:
        if sw_version is None:
            print("'--sw_version' must be specified when using '--all'")
            make_patch_usage()

    if branch is not None:
        if workdir is None or srcdir is None:
            print("If --branch is specified, then a srcdir and workdir must also be specified")
            make_patch_usage()

    if pre_compiled_flag:
        print("pre_compiled_flag = %s" % str(pre_compiled_flag))

    if formal_flag:
        os.environ["FORMAL_BUILD"] = "1"
        print("formal_flag = %s" % str(formal_flag))
        # TODO(slittle) determine if this next commented out block is needed.
        # if branch is not None or workdir is not None or srcdir is not None:
        #     print "If --formal is specified, then srcdir, workdir and branch are automatic and must not be specified"
        #     make_patch_usage()

    if pre_compiled_flag and formal_flag:
        print("invalid options: --formal and --pre-compiled can't be used together.")
        make_patch_usage()

    if workdir is not None:
        if not os.path.isdir(workdir):
            print("invalid directory: workdir = '%s'" % workdir)
            make_patch_usage()

    temp_rpm_db_dir = "%s/%s" % (workdir, ".rpmdb")

    if srcdir is not None:
        if not os.path.isdir(srcdir):
            print("invalid directory: srcdir = '%s'" % srcdir)
            make_patch_usage()

    for patch in patch_list:
        if not os.path.isfile(patch):
            print("invalid patch file path: '%s'" % patch)
            make_patch_usage()

    if 'MY_REPO' in os.environ:
        MY_REPO = os.path.normpath(os.path.join(cwd, os.path.expanduser(os.environ['MY_REPO'])))
    else:
        print("ERROR: environment variable 'MY_REPO' is not defined")
        sys.exit(1)

    if 'MY_WORKSPACE' in os.environ:
        MY_WORKSPACE = os.path.normpath(os.path.join(cwd, os.path.expanduser(os.environ['MY_WORKSPACE'])))
    else:
        print("ERROR: environment variable 'MY_REPO' is not defined")
        sys.exit(1)

    if 'PROJECT' in os.environ:
        PROJECT = os.path.normpath(os.path.join(cwd, os.path.expanduser(os.environ['PROJECT'])))
    else:
        print("ERROR: environment variable 'PROJECT' is not defined")
        sys.exit(1)

    if 'SRC_BUILD_ENVIRONMENT' in os.environ:
        SRC_BUILD_ENVIRONMENT = os.path.normpath(os.path.join(cwd, os.path.expanduser(os.environ['SRC_BUILD_ENVIRONMENT'])))
    else:
        print("ERROR: environment variable 'SRC_BUILD_ENVIRONMENT' is not defined")
        sys.exit(1)

    if 'MY_SRC_RPM_BUILD_DIR' in os.environ:
        MY_SRC_RPM_BUILD_DIR = os.path.normpath(os.path.join(cwd, os.path.expanduser(os.environ['MY_SRC_RPM_BUILD_DIR'])))
    else:
        print("ERROR: environment variable 'MY_SRC_RPM_BUILD_DIR' is not defined")
        sys.exit(1)

    if 'MY_BUILD_CFG' in os.environ:
        MY_BUILD_CFG = os.path.normpath(os.path.join(cwd, os.path.expanduser(os.environ['MY_BUILD_CFG'])))
    else:
        print("ERROR: environment variable 'MY_BUILD_CFG' is not defined")
        sys.exit(1)

    if 'MY_BUILD_DIR' in os.environ:
        MY_BUILD_DIR = os.path.normpath(os.path.join(cwd, os.path.expanduser(os.environ['MY_BUILD_DIR'])))
    else:
        print("ERROR: environment variable 'MY_BUILD_DIR' is not defined")
        sys.exit(1)

    print("formal: %s" % formal_flag)
    print("pre_compiled_flag: %s" % pre_compiled_flag)
    print("pre_clean_flag: %s" % pre_clean_flag)
    print("capture_source_flag: %s" % capture_source_flag)
    print("capture_rpms_flag: %s" % capture_rpms_flag)
    print("workdir: %s" % workdir)
    print("srcdir: %s" % srcdir)
    print("branch: %s" % branch)
    print("sw_version: %s" % sw_version)
    print("patch_list: %s" % patch_list)
    print("")

    if workdir is not None:
        os.chdir(workdir)

    if not read_build_info():
        print("build.info is missing. workdir is invalid, or has never completed initial loadbuild:  workdir = '%s'" % workdir)
        make_patch_usage()

    # Capture initial state before any patches are built
    if capture_rpms_flag:
        capture_rpms()

    pl = PatchList(patch_list)
    pl.myprint()
    pl.build_patches()
    if formal_flag:

        # sign formal patch
        pl.sign_official_patches()
        # deliver to git repo
        pl.deliver_official_patch()
