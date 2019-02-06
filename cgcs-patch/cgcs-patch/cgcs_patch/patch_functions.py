"""
Copyright (c) 2014-2018 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import getopt
import glob
import hashlib
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ElementTree
from xml.dom import minidom

from cgcs_patch.patch_verify import verify_files
from cgcs_patch.patch_verify import cert_type_all
from cgcs_patch.patch_signing import sign_files
from cgcs_patch.exceptions import MetadataFail
from cgcs_patch.exceptions import PatchFail
from cgcs_patch.exceptions import PatchValidationFailure
from cgcs_patch.exceptions import PatchMismatchFailure

import cgcs_patch.constants as constants
import rpm

try:
    # The tsconfig module is only available at runtime
    from tsconfig.tsconfig import SW_VERSION
except Exception:
    SW_VERSION = "unknown"

# Constants
patch_dir = "/opt/patching"
avail_dir = "%s/metadata/available" % patch_dir
applied_dir = "%s/metadata/applied" % patch_dir
committed_dir = "%s/metadata/committed" % patch_dir

repo_root_dir = "/www/pages/updates"
repo_dir = {SW_VERSION: "%s/rel-%s" % (repo_root_dir, SW_VERSION)}

root_package_dir = "%s/packages" % patch_dir
package_dir = {SW_VERSION: "%s/%s" % (root_package_dir, SW_VERSION)}

logfile = "/var/log/patching.log"
apilogfile = "/var/log/patching-api.log"

LOG = logging.getLogger('main_logger')
auditLOG = logging.getLogger('audit_logger')
audit_log_msg_prefix = 'User: wrsroot/admin Action: '

detached_signature_file = "signature.v2"


def handle_exception(exc_type, exc_value, exc_traceback):
    """
    Exception handler to log any uncaught exceptions
    """
    LOG.error("Uncaught exception",
              exc_info=(exc_type, exc_value, exc_traceback))
    sys.__excepthook__(exc_type, exc_value, exc_traceback)


def configure_logging(logtofile=True, level=logging.INFO):
    if logtofile:
        my_exec = os.path.basename(sys.argv[0])

        log_format = '%(asctime)s: ' \
                     + my_exec + '[%(process)s]: ' \
                     + '%(filename)s(%(lineno)s): ' \
                     + '%(levelname)s: %(message)s'

        formatter = logging.Formatter(log_format, datefmt="%FT%T")

        LOG.setLevel(level)
        main_log_handler = logging.FileHandler(logfile)
        main_log_handler.setFormatter(formatter)
        LOG.addHandler(main_log_handler)

        auditLOG.setLevel(level)
        api_log_handler = logging.FileHandler(apilogfile)
        api_log_handler.setFormatter(formatter)
        auditLOG.addHandler(api_log_handler)

        # Log uncaught exceptions to file
        sys.excepthook = handle_exception
    else:
        logging.basicConfig(level=level)


def audit_log_info(msg=''):
    msg = audit_log_msg_prefix + msg
    auditLOG.info(msg)


def get_md5(path):
    """
    Utility function for generating the md5sum of a file
    :param path: Path to file
    """
    md5 = hashlib.md5()
    block_size = 8192
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(block_size), b''):
            md5.update(chunk)
    return int(md5.hexdigest(), 16)


def add_text_tag_to_xml(parent,
                        name,
                        text):
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


def write_xml_file(top,
                   fname):
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


def parse_rpm_filename(filename):

    # Drop the extension
    (basename, ext) = os.path.splitext(os.path.basename(filename))

    # RPM name format is:
    # [<epoch>:]<pkgname>-<version>-<release>.<arch>
    #
    pattern = re.compile(r'((([^:]):)?)(.*)-([^-]+)-(.*)\.([^\.]*)$')

    m = pattern.match(basename)

    if m is None:
        raise ValueError("Filename does not match expected RPM format: %s" % basename)

    epoch = m.group(3)
    pkgname = m.group(4)
    version = m.group(5)
    release = m.group(6)
    arch = m.group(7)

    return (pkgname, arch, PackageVersion(epoch, version, release))


class PackageVersion(object):
    """
    The PackageVersion class provides a structure for RPM version information,
    along with suport for comparison operators.
    """
    def __init__(self, epoch, version, release):
        self.epoch = epoch
        self.version = version
        self.release = release

    def __cmp__(self, other):
        """
        This function is called by comparison operators to compare
        two versions. The rpm.labelCompare() function takes two versions,
        specified in a list structure, and returns -1, 0, or 1.
        """
        return rpm.labelCompare((self.epoch, self.version, self.release),
                                (other.epoch, other.version, other.release))

    def __str__(self):
        """
        This function is called by str() and print to compute the
        informal string representation of a PackageVersion object.
        """
        prefix = ""
        if self.epoch is not None and self.epoch != '':
            # Prefix the version with epoch, if specified
            prefix = "%s:" % self.epoch

        return "%s%s-%s" % (prefix, self.version, self.release)

    def __hash__(self):
        return hash(self.__str__())

    def generate_rpm_filename(self, pkgname, arch):
        prefix = ""
        if self.epoch is not None and self.epoch != '':
            # Prefix the version with epoch, if specified
            prefix = "%s:" % self.epoch

        return "%s%s-%s-%s.%s.rpm" % (prefix, pkgname, self.version, self.release, arch)


class BasePackageData:
    """
    Information about the base package data provided by the load
    """
    def __init__(self):
        self.pkgs = {}
        self.loaddirs()

    def loaddirs(self):
        # Load up available package info
        base_dir = "/www/pages/feed"
        if not os.path.exists(base_dir):
            # Return, since this could be running off-box
            return

        # Look for release dirs
        for reldir in glob.glob("%s/rel-*" % base_dir):
            pattern = re.compile("%s/rel-(.*)" % base_dir)
            m = pattern.match(reldir)
            sw_rel = m.group(1)

            if sw_rel in self.pkgs:
                # We've already parsed this dir once
                continue

            self.pkgs[sw_rel] = {}
            for root, dirs, files in os.walk("%s/Packages" % reldir):
                for name in files:
                    if name.endswith(".rpm"):
                        try:
                            pkgname, arch, pkgver = parse_rpm_filename(name)
                        except ValueError as e:
                            raise e

                        if pkgname not in self.pkgs[sw_rel]:
                            self.pkgs[sw_rel][pkgname] = {}
                        self.pkgs[sw_rel][pkgname][arch] = pkgver

        # Clean up deleted data
        for sw_rel in self.pkgs:
            if not os.path.exists("%s/rel-%s" % (base_dir, sw_rel)):
                del self.pkgs[sw_rel]

    def check_release(self, sw_rel):
        return (sw_rel in self.pkgs)

    def find_version(self, sw_rel, pkgname, arch):
        if sw_rel not in self.pkgs or \
           pkgname not in self.pkgs[sw_rel] or \
           arch not in self.pkgs[sw_rel][pkgname]:
            return None

        return self.pkgs[sw_rel][pkgname][arch]


class PatchData:
    """
    Aggregated patch data
    """
    def __init__(self):
        #
        # The groups dict provides information about targetted (new) packages,
        # identifying the software group in which to include the package.
        # This allows the patch agent to identify new packages to install
        # (or erase) as appropriate.
        # This dict is nested as follows:
        #   [ patch_sw_version ] - Release associated with the patch
        #     [ group/ptype ] - Group (personality) in which the pkg belongs
        #       [ patch_id ]
        #         [ package ]
        #
        self.groups = {}

        #
        # The metadata dict stores all metadata associated with a patch.
        # This dict is keyed on patch_id, with metadata for each patch stored
        # in a nested dict. (See parse_metadata method for more info)
        #
        self.metadata = {}

        #
        # The contents dict stores the lists of RPMs provided by each patch,
        # indexed by patch_id.
        #
        self.contents = {}

        #
        # The content_versions dict provides a simple list of packages and their
        # versions for each patch, used by the patch controller in determining
        # patch states.
        # content_versions[patch_id][pkgname] = "%s-%s" % (pkgver.version, pkgver.release)
        #
        self.content_versions = {}

        #
        # The package_versions dict provides a mapping of packages to the patch_id,
        # including the package arch.
        #   [ patch_sw_version ]
        #     [ pkgname ]
        #       [ arch ]
        #         [ pkgver ]
        #           -> patch_id
        self.package_versions = {}

    def add_patch(self, patch_id, new_patch):
        # We can just use "update" on these dicts because they are indexed by patch_id
        self.metadata.update(new_patch.metadata)
        self.contents.update(new_patch.contents)
        self.content_versions.update(new_patch.content_versions)

        # Need to recursively update package_version and keys dicts
        for patch_sw_version in new_patch.package_versions.keys():
            if patch_sw_version not in self.package_versions:
                self.package_versions[patch_sw_version] = {}
            for pkgname in new_patch.package_versions[patch_sw_version].keys():
                if pkgname not in self.package_versions[patch_sw_version]:
                    self.package_versions[patch_sw_version][pkgname] = {}
                for arch in new_patch.package_versions[patch_sw_version][pkgname].keys():
                    if arch not in self.package_versions[patch_sw_version][pkgname]:
                        self.package_versions[patch_sw_version][pkgname][arch] = {}
                    for pkgver in new_patch.package_versions[patch_sw_version][pkgname][arch].keys():
                        self.package_versions[patch_sw_version][pkgname][arch][pkgver] = patch_id

        for patch_sw_version in new_patch.groups.keys():
            if patch_sw_version not in self.groups:
                self.groups[patch_sw_version] = {}
            for ptype in new_patch.groups[patch_sw_version].keys():
                if ptype not in self.groups[patch_sw_version]:
                    self.groups[patch_sw_version][ptype] = {}
                for patch_id in new_patch.groups[patch_sw_version][ptype].keys():
                    if patch_id not in self.groups[patch_sw_version][ptype]:
                        self.groups[patch_sw_version][ptype][patch_id] = {}
                    self.groups[patch_sw_version][ptype][patch_id].update(
                        new_patch.groups[patch_sw_version][ptype][patch_id])

    def update_patch(self, updated_patch):
        for patch_id in updated_patch.metadata.keys():
            # Update all fields except repostate
            cur_repostate = self.metadata[patch_id]['repostate']
            self.metadata[patch_id].update(updated_patch.metadata[patch_id])
            self.metadata[patch_id]['repostate'] = cur_repostate

    def delete_patch(self, patch_id):
        for patch_sw_version in self.package_versions.keys():
            for pkgname in self.package_versions[patch_sw_version].keys():
                for arch in self.package_versions[patch_sw_version][pkgname].keys():
                    for pkgver in self.package_versions[patch_sw_version][pkgname][arch].keys():
                        if self.package_versions[patch_sw_version][pkgname][arch][pkgver] == patch_id:
                            del self.package_versions[patch_sw_version][pkgname][arch][pkgver]
                    if len(self.package_versions[patch_sw_version][pkgname][arch]) is 0:
                        del self.package_versions[patch_sw_version][pkgname][arch]
                if len(self.package_versions[patch_sw_version][pkgname]) is 0:
                    del self.package_versions[patch_sw_version][pkgname]
            if len(self.package_versions[patch_sw_version]) is 0:
                del self.package_versions[patch_sw_version]

        for patch_sw_version in self.groups.keys():
            for ptype in self.groups[patch_sw_version].keys():
                if patch_id in self.groups[patch_sw_version][ptype]:
                    del self.groups[patch_sw_version][ptype][patch_id]

        del self.content_versions[patch_id]
        del self.contents[patch_id]
        del self.metadata[patch_id]

    @staticmethod
    def modify_metadata_text(filename,
                             key,
                             value):
        """
        Open an xml file, find first element matching 'key' and replace the text with 'value'
        """
        new_filename = "%s.new" % filename
        tree = ElementTree.parse(filename)

        # Prevent a proliferation of carriage returns when we write this XML back out to file.
        for e in tree.getiterator():
            if e.text is not None:
                e.text = e.text.rstrip()
            if e.tail is not None:
                e.tail = e.tail.rstrip()

        root = tree.getroot()

        # Make the substitution
        e = root.find(key)
        if e is None:
            msg = "modify_metadata_text: failed to find tag '%s'" % key
            LOG.error(msg)
            raise PatchValidationFailure(msg)
        e.text = value

        # write the modified file
        outfile = open(new_filename, 'w')
        rough_xml = ElementTree.tostring(root, 'utf-8')
        if platform.python_version() == "2.7.2":
            # The 2.7.2 toprettyxml() function unnecessarily indents
            # childless tags, adding whitespace. In the case of the
            # yum comps.xml file, it makes the file unusable, so just
            # write the rough xml
            outfile.write(rough_xml)
        else:
            outfile.write(minidom.parseString(rough_xml).toprettyxml(indent="  "))
        outfile.close()
        os.rename(new_filename, filename)

    def parse_metadata(self,
                       filename,
                       repostate=None):
        """
        Parse an individual patch metadata XML file
        :param filename: XML file
        :param repostate: Indicates Applied, Available, or Committed
        :return: Patch ID
        """
        tree = ElementTree.parse(filename)
        root = tree.getroot()

        #
        #    <patch>
        #        <id>PATCH_0001</id>
        #        <summary>Brief description</summary>
        #        <description>Longer description</description>
        #        <install_instructions/>
        #        <warnings/>
        #        <status>Dev</status>
        #        <unremovable/>
        #        <reboot_required/>
        #        <personality type="worker">
        #            <package>pkgA</package>
        #            <package>pkgB</package>
        #        </personality>
        #        <personality type="controller">
        #            <package>pkgB</package>
        #        </personality>
        #    </patch>
        #

        patch_id = root.findtext("id")
        if patch_id is None:
            LOG.error("Patch metadata contains no id tag")
            return None

        self.metadata[patch_id] = {}

        self.metadata[patch_id]["repostate"] = repostate

        # Patch state is unknown at this point
        self.metadata[patch_id]["patchstate"] = "n/a"

        self.metadata[patch_id]["sw_version"] = "unknown"

        for key in ["status",
                    "unremovable",
                    "sw_version",
                    "summary",
                    "description",
                    "install_instructions",
                    "warnings"]:
            value = root.findtext(key)
            if value is not None:
                self.metadata[patch_id][key] = value

        # Default reboot_required to Y
        rr_value = root.findtext("reboot_required")
        if rr_value is None or rr_value != "N":
            self.metadata[patch_id]["reboot_required"] = "Y"
        else:
            self.metadata[patch_id]["reboot_required"] = "N"

        patch_sw_version = self.metadata[patch_id]["sw_version"]
        global package_dir
        if patch_sw_version not in package_dir:
            package_dir[patch_sw_version] = "%s/%s" % (root_package_dir, patch_sw_version)
            repo_dir[patch_sw_version] = "%s/rel-%s" % (repo_root_dir, patch_sw_version)

        # Specifying personality for given packages is optional,
        # intended to allow a patch to include a new package.
        # For each configured personality type, create a software group.
        for personality in root.findall("personality"):
            ptype = personality.attrib["type"]
            tag = "personality-%s" % ptype
            self.metadata[patch_id][tag] = list()
            for pkg in personality.findall("package"):
                self.metadata[patch_id][tag].append(pkg.text)
                if patch_sw_version not in self.groups:
                    self.groups[patch_sw_version] = {}
                if ptype not in self.groups[patch_sw_version]:
                    self.groups[patch_sw_version][ptype] = {}
                if patch_id not in self.groups[patch_sw_version][ptype]:
                    self.groups[patch_sw_version][ptype][patch_id] = {}
                self.groups[patch_sw_version][ptype][patch_id][pkg.text] = True

        self.metadata[patch_id]["requires"] = []
        for req in root.findall("requires"):
            for req_patch in req.findall("req_patch_id"):
                self.metadata[patch_id]["requires"].append(req_patch.text)

        self.contents[patch_id] = list()
        self.content_versions[patch_id] = {}

        for content in root.findall("contents"):
            for rpmname in content.findall("rpm"):
                try:
                    pkgname, arch, pkgver = parse_rpm_filename(rpmname.text)
                except ValueError as e:
                    LOG.exception(e)
                    return None

                self.contents[patch_id].append(rpmname.text)
                self.content_versions[patch_id][pkgname] = "%s-%s" % (pkgver.version, pkgver.release)

                if patch_sw_version not in self.package_versions:
                    self.package_versions[patch_sw_version] = {}
                if pkgname not in self.package_versions[patch_sw_version]:
                    self.package_versions[patch_sw_version][pkgname] = {}
                if arch not in self.package_versions[patch_sw_version][pkgname]:
                    self.package_versions[patch_sw_version][pkgname][arch] = {}

                self.package_versions[patch_sw_version][pkgname][arch][pkgver] = patch_id

        return patch_id

    def find_patch_with_pkgver(self, sw_ver, pkgname, arch, pkgver):
        if sw_ver not in self.package_versions or \
           pkgname not in self.package_versions[sw_ver] or \
           arch not in self.package_versions[sw_ver][pkgname] or \
           pkgver not in self.package_versions[sw_ver][pkgname][arch]:
            return None

        return self.package_versions[sw_ver][pkgname][arch][pkgver]

    def load_all_metadata(self,
                          loaddir=os.getcwd(),
                          repostate=None):
        """
        Parse all metadata files in the specified dir
        :return:
        """
        for fname in glob.glob("%s/*.xml" % loaddir):
            self.parse_metadata(fname, repostate)

    def load_all(self):
        # Reset the data
        self.__init__()
        self.load_all_metadata(applied_dir, repostate=constants.APPLIED)
        self.load_all_metadata(avail_dir, repostate=constants.AVAILABLE)
        self.load_all_metadata(committed_dir, repostate=constants.COMMITTED)

    def gen_release_groups_xml(self, sw_version, output_dir=None):
        """
        Generate the groups configuration file for the patching repo
        """
        if output_dir is None:
            output_dir = repo_dir[sw_version]

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        fname = "%s/comps.xml" % output_dir
        top = ElementTree.Element('comps')
        if sw_version in self.groups:
            for groupname in sorted(self.groups[sw_version].keys()):
                if self.groups[sw_version][groupname]:
                    group = ElementTree.SubElement(top, 'group')

                    add_text_tag_to_xml(group, 'id',
                                        "updates-%s" % groupname)
                    add_text_tag_to_xml(group, 'default',
                                        "false")
                    add_text_tag_to_xml(group, 'uservisible',
                                        "true")
                    add_text_tag_to_xml(group, 'display_order',
                                        "1024")
                    add_text_tag_to_xml(group, 'name',
                                        "updates-%s" % groupname)
                    add_text_tag_to_xml(group, 'description',
                                        "Patches for %s" % groupname)

                    package_element = ElementTree.SubElement(group,
                                                             'packagelist')

                    for patch_id in sorted(self.groups[sw_version][groupname]):
                        if self.metadata[patch_id]["repostate"] == constants.APPLIED \
                                or self.metadata[patch_id]["repostate"] == constants.COMMITTED:
                            for pkg in sorted(self.groups[sw_version][groupname][patch_id]):
                                tag = ElementTree.SubElement(package_element,
                                                             'packagereq',
                                                             type="mandatory")
                                tag.text = pkg

        write_xml_file(top, fname)

    def gen_groups_xml(self):
        for ver, rdir in repo_dir.items():
            self.gen_release_groups_xml(ver)

    def query_line(self,
                   patch_id,
                   index):
        if index is None:
            return None

        if index == "contents":
            return self.contents[patch_id]

        if index not in self.metadata[patch_id]:
            return None

        value = self.metadata[patch_id][index]
        return value


class PatchMetadata:
    """
    Creating metadata for a single patch
    """
    def __init__(self):
        self.id = None
        self.sw_version = None
        self.summary = None
        self.description = None
        self.install_instructions = None
        self.warnings = None
        self.status = None
        self.unremovable = None
        self.reboot_required = None
        self.requires = []
        self.groups = {}
        self.contents = {}

    def add_package(self,
                    groupname,
                    pkg):
        """
        Add a package to a particular group
        :param groupname: Yum software group, eg. "controller"
        :param pkg: Name of the package
        :return:
        """
        if groupname not in self.groups:
            self.groups[groupname] = {}

        self.groups[groupname][pkg] = True

    def add_rpm(self,
                fname):
        """
        Add an RPM to the patch
        :param fname: RPM filename
        :return:
        """
        rpmname = os.path.basename(fname)
        self.contents[rpmname] = True

    def gen_xml(self,
                fname="metadata.xml"):
        """
        Generate patch metadata XML file
        :param fname: Path to output file
        :return:
        """
        top = ElementTree.Element('patch')

        add_text_tag_to_xml(top, 'id',
                            self.id)
        add_text_tag_to_xml(top, 'sw_version',
                            self.sw_version)
        add_text_tag_to_xml(top, 'summary',
                            self.summary)
        add_text_tag_to_xml(top, 'description',
                            self.description)
        add_text_tag_to_xml(top, 'install_instructions',
                            self.install_instructions)
        add_text_tag_to_xml(top, 'warnings',
                            self.warnings)
        add_text_tag_to_xml(top, 'status',
                            self.status)
        add_text_tag_to_xml(top, 'unremovable',
                            self.unremovable)
        add_text_tag_to_xml(top, 'reboot_required',
                            self.reboot_required)

        for groupname in sorted(self.groups.keys()):
            if self.groups[groupname]:
                group = ElementTree.SubElement(top,
                                               'personality',
                                               type=groupname)

                for pkg in sorted(self.groups[groupname]):
                    add_text_tag_to_xml(group, 'package', pkg)

        content = ElementTree.SubElement(top, 'contents')
        for rpmname in sorted(self.contents.keys()):
            add_text_tag_to_xml(content, 'rpm', rpmname)

        req = ElementTree.SubElement(top, 'requires')
        for req_patch in sorted(self.requires):
            add_text_tag_to_xml(req, 'req_patch_id', req_patch)

        write_xml_file(top, fname)


class PatchFile:
    """
    Patch file
    """
    def __init__(self):
        self.meta = PatchMetadata()
        self.rpmlist = {}

    def add_rpm(self,
                fname,
                personality=None):
        """
        Add an RPM to the patch
        :param fname: Path to RPM
        :param personality: Optional: Node type to which
                            the package belongs. Can be a
                            string or a list of strings.
        :return:
        """
        # Add the RPM to the metadata
        self.meta.add_rpm(fname)

        # Add the RPM to the patch
        self.rpmlist[os.path.abspath(fname)] = True

        if personality is not None:
            # Get the package name from the RPM itself,
            # and add it to the appropriate group(s)
            pkgname = subprocess.check_output(["rpm",
                                               "-qp",
                                               "--queryformat",
                                               "%{NAME}",
                                               "--nosignature",
                                               fname])
            if isinstance(personality, list):
                for p in personality:
                    self.meta.add_package(p, pkgname)
            elif isinstance(personality, str):
                self.meta.add_package(personality, pkgname)

    def gen_patch(self,
                  outdir=os.getcwd()):
        """
        Generate the patch file, named PATCHID.patch
        :param outdir: Output directory for the patch
        :return:
        """
        if self.meta.sw_version is None or self.meta.sw_version == '':
            raise MetadataFail("The release version must be specified in the sw_version field")

        patchfile = "%s/%s.patch" % (outdir, self.meta.id)

        # Create a temporary working directory
        tmpdir = tempfile.mkdtemp(prefix="patch_")

        # Save the current directory, so we can chdir back after
        orig_wd = os.getcwd()

        # Change to the tmpdir
        os.chdir(tmpdir)

        # Copy RPM files to tmpdir
        for rpmfile in self.rpmlist.keys():
            shutil.copy(rpmfile, tmpdir)

        # add file signatures to RPMs
        try:
            subprocess.check_call(["sign-rpms", "-d", tmpdir])
        except subprocess.CalledProcessError as e:
            print("Failed to to add file signatures to RPMs. Call to sign-rpms process returned non-zero exit status %i" % e.returncode)
            os.chdir(orig_wd)
            shutil.rmtree(tmpdir)
            raise SystemExit(e.returncode)

        # generate tar file
        tar = tarfile.open("software.tar", "w")
        for rpmfile in self.rpmlist.keys():
            tar.add(os.path.basename(rpmfile))
        tar.close()

        # Generate the metadata xml file
        self.meta.gen_xml("metadata.xml")

        # assemble the patch
        PatchFile.write_patch(patchfile)

        # Change back to original working dir
        os.chdir(orig_wd)

        shutil.rmtree(tmpdir)

        print("Patch is %s" % patchfile)

    @staticmethod
    def write_patch(patchfile, cert_type=None):
        # Write the patch file. Assumes we are in a directory containing metadata.tar, and software.tar.

        # Generate the metadata tarfile
        tar = tarfile.open("metadata.tar", "w")
        tar.add("metadata.xml")
        tar.close()

        # Generate the signature file
        md_md5 = get_md5("metadata.tar")
        sw_md5 = get_md5("software.tar")
        ff = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        sig = (md_md5 ^ sw_md5) ^ ff
        sigfile = open("signature", "w")
        sigfile.write("%x" % sig)
        sigfile.close()

        # Generate the detached signature
        #
        # Note: if cert_type requests a formal signature, but the signing key
        #    is not found, we'll instead sign with the 'dev' key and
        #    need_resign_with_formal is set to True.
        need_resign_with_formal = sign_files(
            ['metadata.tar', 'software.tar'],
            detached_signature_file,
            cert_type=cert_type)

        # Create the patch
        tar = tarfile.open(patchfile, "w:gz")
        tar.add("metadata.tar")
        tar.add("software.tar")
        tar.add("signature")
        tar.add(detached_signature_file)
        tar.close()

        if need_resign_with_formal:
            try:
                # Try to ensure "sign_patch_formal.sh" will be in our PATH
                if 'MY_REPO' in os.environ:
                    os.environ['PATH'] += os.pathsep + os.environ['MY_REPO'] + "/build-tools"
                if 'MY_PATCH_REPO' in os.environ:
                    os.environ['PATH'] += os.pathsep + os.environ['MY_PATCH_REPO'] + "/build-tools"

                # Note: This can fail if the user is not authorized to sign with the formal key.
                subprocess.check_call(["sign_patch_formal.sh", patchfile])
            except subprocess.CalledProcessError as e:
                print("Failed to sign official patch. Call to sign_patch_formal.sh process returned non-zero exit status %i" % e.returncode)
                raise SystemExit(e.returncode)

    @staticmethod
    def read_patch(path, metadata_only=False, cert_type=None):
        # We want to enable signature checking by default
        # Note: cert_type=None is required if we are to enforce 'no dev patches on a formal load' rule.
        verify_signature = True

        # Open the patch file and extract the contents to the current dir
        tar = tarfile.open(path, "r:gz")
        tar.extract("metadata.tar")
        tar.extract("software.tar")
        tar.extract("signature")
        try:
            tar.extract(detached_signature_file)
        except KeyError:
            msg = "Patch has not been signed"
            LOG.warning(msg)

        # Verify the data integrity signature first
        sigfile = open("signature", "r")
        sig = int(sigfile.read(), 16)
        sigfile.close()

        md_md5 = get_md5("metadata.tar")
        sw_md5 = get_md5("software.tar")
        ff = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        expected_sig = (md_md5 ^ sw_md5) ^ ff

        if sig != expected_sig:
            msg = "Patch failed verification"
            LOG.error(msg)
            raise PatchValidationFailure(msg)

        # Lookahead into metadata to get patch sw_version -- if older than
        # 18.03, don't do the check
        tar = tarfile.open("metadata.tar")
        tar.extractall()
        xml_root = ElementTree.parse('metadata.xml').getroot()
        sw_version = xml_root.find('sw_version')
        if str(sw_version) == '17.06':
            verify_signature = False

        # Clean up lookahead
        os.unlink('metadata.xml')

        if verify_signature:
            # If there should be a detached signature, verify it
            if os.path.exists(detached_signature_file):
                filenames = ["metadata.tar", "software.tar"]
                sig_valid = verify_files(
                    filenames,
                    detached_signature_file,
                    cert_type=cert_type)
                if sig_valid is True:
                    msg = "Signature verified, patch has been signed"
                    if cert_type is None:
                        LOG.info(msg)
                else:
                    msg = "Signature check failed"
                    if cert_type is None:
                        LOG.error(msg)
                    raise PatchValidationFailure(msg)
            else:
                msg = "Patch has not been signed"
                if cert_type is None:
                    LOG.error(msg)
                raise PatchValidationFailure(msg)

        tar = tarfile.open("metadata.tar")
        tar.extractall()

        if not metadata_only:
            tar = tarfile.open("software.tar")
            tar.extractall()

    @staticmethod
    def query_patch(patch, field=None):

        abs_patch = os.path.abspath(patch)

        # Create a temporary working directory
        tmpdir = tempfile.mkdtemp(prefix="patch_")

        # Save the current directory, so we can chdir back after
        orig_wd = os.getcwd()

        # Change to the tmpdir
        os.chdir(tmpdir)

        r = {}

        try:
            if field is None or field == "cert":
                # Need to determine the cert_type
                for cert_type_str in cert_type_all:
                    try:
                        PatchFile.read_patch(abs_patch, metadata_only=True, cert_type=[cert_type_str])
                    except PatchValidationFailure as e:
                        pass
                    else:
                        # Successfully opened the file for reading, and we have discovered the cert_type
                        r["cert"] = cert_type_str
                        break

            if "cert" not in r:
                # If cert is unknown, then file is not yet open for reading.
                # Try to open it for reading now, using all available keys.
                # We can't omit cert_type, or pass None, because that will trigger the code
                # path used by installed product, in which dev keys are not accepted unless
                # a magic file exists.
                PatchFile.read_patch(abs_patch, metadata_only=True, cert_type=cert_type_all)

            thispatch = PatchData()
            patch_id = thispatch.parse_metadata("metadata.xml")

            if field is None or field == "id":
                r["id"] = patch_id

            if field is None:
                for f in ["status", "sw_version", "unremovable", "summary",
                          "description", "install_instructions",
                          "warnings", "reboot_required"]:
                    r[f] = thispatch.query_line(patch_id, f)
            else:
                if field not in ['id', 'cert']:
                    r[field] = thispatch.query_line(patch_id, field)

        except PatchValidationFailure as e:
            msg = "Patch validation failed during extraction"
            LOG.exception(msg)
            raise e
        except PatchMismatchFailure as e:
            msg = "Patch Mismatch during extraction"
            LOG.exception(msg)
            raise e
        except tarfile.TarError:
            msg = "Failed during patch extraction"
            LOG.exception(msg)
            raise PatchValidationFailure(msg)
        finally:
            # Change back to original working dir
            os.chdir(orig_wd)
            shutil.rmtree(tmpdir)

        return r

    @staticmethod
    def modify_patch(patch,
                     key,
                     value):
        rc = False
        abs_patch = os.path.abspath(patch)
        new_abs_patch = "%s.new" % abs_patch

        # Create a temporary working directory
        tmpdir = tempfile.mkdtemp(prefix="patch_")

        # Save the current directory, so we can chdir back after
        orig_wd = os.getcwd()

        # Change to the tmpdir
        os.chdir(tmpdir)

        try:
            cert_type = None
            meta_data = PatchFile.query_patch(abs_patch)
            if 'cert' in meta_data:
                cert_type = meta_data['cert']
            PatchFile.read_patch(abs_patch, metadata_only=True, cert_type=cert_type)
            PatchData.modify_metadata_text("metadata.xml", key, value)
            PatchFile.write_patch(new_abs_patch, cert_type=cert_type)
            os.rename(new_abs_patch, abs_patch)
            rc = True

        except PatchValidationFailure as e:
            raise e
        except PatchMismatchFailure as e:
            raise e
        except tarfile.TarError:
            msg = "Failed during patch extraction"
            LOG.exception(msg)
            raise PatchValidationFailure(msg)
        except Exception as e:
            template = "An exception of type {0} occurred. Arguments:\n{1!r}"
            message = template.format(type(e).__name__, e.args)
            print(message)
        finally:
            # Change back to original working dir
            os.chdir(orig_wd)
            shutil.rmtree(tmpdir)

        return rc

    @staticmethod
    def extract_patch(patch,
                      metadata_dir=avail_dir,
                      metadata_only=False,
                      existing_content=None,
                      allpatches=None,
                      base_pkgdata=None):
        """
        Extract the metadata and patch contents
        :param patch: Patch file
        :param metadata_dir: Directory to store the metadata XML file
        :return:
        """
        thispatch = None

        abs_patch = os.path.abspath(patch)
        abs_metadata_dir = os.path.abspath(metadata_dir)

        # Create a temporary working directory
        tmpdir = tempfile.mkdtemp(prefix="patch_")

        # Save the current directory, so we can chdir back after
        orig_wd = os.getcwd()

        # Change to the tmpdir
        os.chdir(tmpdir)

        try:
            # Open the patch file and extract the contents to the tmpdir
            PatchFile.read_patch(abs_patch, metadata_only)

            thispatch = PatchData()
            patch_id = thispatch.parse_metadata("metadata.xml")

            if patch_id is None:
                print("Failed to import patch")
                # Change back to original working dir
                os.chdir(orig_wd)
                shutil.rmtree(tmpdir)
                return None

            if not metadata_only and base_pkgdata is not None:
                # Run version validation tests first
                patch_sw_version = thispatch.metadata[patch_id]["sw_version"]
                if not base_pkgdata.check_release(patch_sw_version):
                    msg = "Patch %s software release (%s) is not installed" % (patch_id, patch_sw_version)
                    LOG.exception(msg)
                    raise PatchValidationFailure(msg)

                for rpmname in thispatch.contents[patch_id]:
                    pkgname, arch, pkgver = parse_rpm_filename(rpmname)
                    base_pkgver = base_pkgdata.find_version(patch_sw_version, pkgname, arch)
                    if base_pkgver is not None:
                        # Compare the patch RPM's version against the base
                        if pkgver <= base_pkgver:
                            msg = "RPM %s in patch %s must be higher version than original (%s)" % \
                                  (rpmname, patch_id, base_pkgver)
                            LOG.exception(msg)
                            raise PatchValidationFailure(msg)

                    if allpatches is not None:
                        # Compare the patch RPM's version against other patches
                        other = allpatches.find_patch_with_pkgver(patch_sw_version, pkgname, arch, pkgver)
                        if other is not None:
                            msg = "Patch %s contains rpm %s, which is already provided by patch %s" % \
                                  (patch_id, rpmname, other)
                            LOG.exception(msg)
                            raise PatchValidationFailure(msg)

            if metadata_only:
                # This is a re-import. Ensure the content lines up
                if existing_content is None \
                        or len(existing_content) != len(thispatch.contents[patch_id]):
                    msg = "Contents of re-imported patch do not match"
                    LOG.exception(msg)
                    raise PatchMismatchFailure(msg)
                for rpmname in existing_content:
                    if rpmname not in thispatch.contents[patch_id]:
                        msg = "Contents of re-imported patch do not match"
                        LOG.exception(msg)
                        raise PatchMismatchFailure(msg)

            shutil.move("metadata.xml",
                        "%s/%s-metadata.xml" % (abs_metadata_dir, patch_id))

            if not metadata_only:
                for rpmname in thispatch.contents[patch_id]:
                    patch_sw_version = thispatch.metadata[patch_id]["sw_version"]
                    rpm_dir = package_dir[patch_sw_version]
                    if not os.path.exists(rpm_dir):
                        os.makedirs(rpm_dir)
                    shutil.move(rpmname, "%s/" % rpm_dir)
        except PatchValidationFailure as e:
            raise e
        except PatchMismatchFailure as e:
            raise e
        except tarfile.TarError:
            msg = "Failed during patch extraction"
            LOG.exception(msg)
            raise PatchValidationFailure(msg)
        except KeyError:
            msg = "Failed during patch extraction"
            LOG.exception(msg)
            raise PatchValidationFailure(msg)
        except OSError:
            msg = "Failed during patch extraction"
            LOG.exception(msg)
            raise PatchFail(msg)
        except IOError:
            msg = "Failed during patch extraction"
            LOG.exception(msg)
            raise PatchFail(msg)
        finally:
            # Change back to original working dir
            os.chdir(orig_wd)
            shutil.rmtree(tmpdir)

        return thispatch


def patch_build():
    configure_logging(logtofile=False)

    try:
        opts, remainder = getopt.getopt(sys.argv[1:],
                                        '',
                                        ['id=',
                                         'release=',
                                         'summary=',
                                         'status=',
                                         'unremovable',
                                         'reboot-required=',
                                         'desc=',
                                         'warn=',
                                         'inst=',
                                         'req=',
                                         'controller=',
                                         'controller-worker=',
                                         'controller-worker-lowlatency=',
                                         'worker=',
                                         'worker-lowlatency=',
                                         'storage=',
                                         'all-nodes='])
    except getopt.GetoptError:
        print("Usage: %s [ <args> ] ... <rpm list>"
              % os.path.basename(sys.argv[0]))
        print("Options:")
        print("\t--id <id>               Patch ID")
        print("\t--release <version>     Platform release version")
        print("\t--status <status>       Patch Status Code (ie. O, R, V)")
        print("\t--unremovable           Marks patch as unremovable")
        print("\t--reboot-required <Y|N> Marks patch as reboot-required (default=Y)")
        print("\t--summary <summary>     Patch Summary")
        print("\t--desc <description>    Patch Description")
        print("\t--warn <warnings>       Patch Warnings")
        print("\t--inst <instructions>   Patch Install Instructions")
        print("\t--req <patch_id>        Required Patch")
        print("\t--controller <rpm>      New package for controller")
        print("\t--worker <rpm>         New package for worker node")
        print("\t--worker-lowlatency <rpm>   New package for worker-lowlatency node")
        print("\t--storage <rpm>         New package for storage node")
        print("\t--controller-worker <rpm>   New package for combined node")
        print("\t--controller-worker-lowlatency <rpm>   New package for lowlatency combined node")
        print("\t--all-nodes <rpm>       New package for all node types")
        exit(1)

    pf = PatchFile()

    # Default the release
    pf.meta.sw_version = os.environ['PLATFORM_RELEASE']

    for opt, arg in opts:
        if opt == "--id":
            pf.meta.id = arg
        elif opt == "--release":
            pf.meta.sw_version = arg
        elif opt == "--summary":
            pf.meta.summary = arg
        elif opt == "--status":
            pf.meta.status = arg
        elif opt == "--unremovable":
            pf.meta.unremovable = "Y"
        elif opt == "--reboot-required":
            if arg != "Y" and arg != "N":
                print("The --reboot-required option requires either Y or N as argument.")
                exit(1)
            pf.meta.reboot_required = arg
        elif opt == "--desc":
            pf.meta.description = arg
        elif opt == "--warn":
            pf.meta.warnings = arg
        elif opt == "--inst":
            pf.meta.install_instructions = arg
        elif opt == "--req":
            pf.meta.requires.append(arg)
        elif opt == "--all-nodes":
            for p in ("controller",
                      "worker",
                      "worker-lowlatency",
                      "storage",
                      "controller-worker",
                      "controller-worker-lowlatency"):
                pf.add_rpm(arg, personality=p)
        elif opt in ("--controller",
                     "--worker",
                     "--worker-lowlatency",
                     "--storage",
                     "--controller-worker",
                     "--controller-worker-lowlatency"):
            pf.add_rpm(arg, personality=opt[2:])

    if pf.meta.id is None:
        print("The --id argument is mandatory.")
        exit(1)

    for rpmfile in remainder:
        pf.add_rpm(rpmfile)

    pf.gen_patch()
