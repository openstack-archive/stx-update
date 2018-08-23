"""
Copyright (c) 2014-2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import os
import time
import socket
import json
import select
import subprocess
import random
import requests
import xml.etree.ElementTree as ElementTree
import rpm
import sys
import yaml
import shutil

from rpmUtils.miscutils import stringToVersion  # pylint: disable=import-error

from cgcs_patch.patch_functions import (configure_logging, LOG)
import cgcs_patch.config as cfg
from cgcs_patch.base import PatchService
import cgcs_patch.utils as utils
import cgcs_patch.messages as messages
import cgcs_patch.constants as constants

from tsconfig.tsconfig import (SW_VERSION, subfunctions, install_uuid)

pidfile_path = "/var/run/patch_agent.pid"
node_is_patched_file = "/var/run/node_is_patched"
node_is_patched_rr_file = "/var/run/node_is_patched_rr"
patch_installing_file = "/var/run/patch_installing"
patch_failed_file = "/var/run/patch_install_failed"
node_is_locked_file = "/var/run/.node_locked"

insvc_patch_scripts = "/run/patching/patch-scripts"
insvc_patch_flags = "/run/patching/patch-flags"
insvc_patch_restart_agent = "/run/patching/.restart.patch-agent"

run_insvc_patch_scripts_cmd = "/usr/sbin/run-patch-scripts"

pa = None

# Smart commands
smart_cmd = ["/usr/bin/smart"]
smart_quiet = smart_cmd + ["--quiet"]
smart_update = smart_quiet + ["update"]
smart_newer = smart_quiet + ["newer"]
smart_orphans = smart_quiet + ["query", "--orphans", "--show-format", "$name\n"]
smart_query = smart_quiet + ["query"]
smart_query_repos = smart_quiet + ["query", "--channel=base", "--channel=updates"]
smart_install_cmd = smart_cmd + ["install", "--yes", "--explain"]
smart_remove_cmd = smart_cmd + ["remove", "--yes", "--explain"]
smart_query_installed = smart_quiet + ["query", "--installed", "--show-format", "$name $version\n"]
smart_query_base = smart_quiet + ["query", "--channel=base", "--show-format", "$name $version\n"]
smart_query_updates = smart_quiet + ["query", "--channel=updates", "--show-format", "$name $version\n"]


def setflag(fname):
    try:
        with open(fname, "w") as f:
            f.write("%d\n" % os.getpid())
    except:
        LOG.exception("Failed to update %s flag" % fname)


def clearflag(fname):
    if os.path.exists(fname):
        try:
            os.remove(fname)
        except:
            LOG.exception("Failed to clear %s flag" % fname)


def check_install_uuid():
    controller_install_uuid_url = "http://controller/feed/rel-%s/install_uuid" % SW_VERSION
    try:
        req = requests.get(controller_install_uuid_url)
        if req.status_code != 200:
            # If we're on controller-1, controller-0 may not have the install_uuid
            # matching this release, if we're in an upgrade. If the file doesn't exist,
            # bypass this check
            if socket.gethostname() == "controller-1":
                return True

            LOG.error("Failed to get install_uuid from controller")
            return False
    except requests.ConnectionError:
        LOG.error("Failed to connect to controller")
        return False

    controller_install_uuid = str(req.text).rstrip()

    if install_uuid != controller_install_uuid:
        LOG.error("Local install_uuid=%s doesn't match controller=%s" % (install_uuid, controller_install_uuid))
        return False

    return True


class PatchMessageHelloAgent(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_HELLO_AGENT)
        self.patch_op_counter = 0

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        if 'patch_op_counter' in data:
            self.patch_op_counter = data['patch_op_counter']

    def encode(self):
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        # Send response

        # Run the smart config audit
        global pa
        pa.timed_audit_smart_config()

        #
        # If a user tries to do a host-install on an unlocked node,
        # without bypassing the lock check (either via in-service
        # patch or --force option), the agent will set its state
        # to Install-Rejected in order to report back the rejection.
        # However, since this should just be a transient state,
        # we don't want the client reporting the Install-Rejected
        # state indefinitely, so reset it to Idle after a minute or so.
        #
        if pa.state == constants.PATCH_AGENT_STATE_INSTALL_REJECTED:
            if os.path.exists(node_is_locked_file):
                # Node has been locked since rejected attempt. Reset the state
                pa.state = constants.PATCH_AGENT_STATE_IDLE
            elif (time.time() - pa.rejection_timestamp) > 60:
                # Rejected state for more than a minute. Reset it.
                pa.state = constants.PATCH_AGENT_STATE_IDLE

        if self.patch_op_counter > 0:
            pa.handle_patch_op_counter(self.patch_op_counter)

        resp = PatchMessageHelloAgentAck()
        resp.send(sock)

    def send(self, sock):
        LOG.error("Should not get here")


class PatchMessageHelloAgentAck(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_HELLO_AGENT_ACK)

    def encode(self):
        global pa
        messages.PatchMessage.encode(self)
        self.message['query_id'] = pa.query_id
        self.message['out_of_date'] = pa.changes
        self.message['hostname'] = socket.gethostname()
        self.message['requires_reboot'] = pa.node_is_patched
        self.message['patch_failed'] = pa.patch_failed
        self.message['sw_version'] = SW_VERSION
        self.message['state'] = pa.state

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock):
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(message, (cfg.controller_mcast_group, cfg.controller_port))


class PatchMessageQueryDetailed(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_QUERY_DETAILED)

    def decode(self, data):
        messages.PatchMessage.decode(self, data)

    def encode(self):
        # Nothing to add to the HELLO_AGENT, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        # Send response
        LOG.info("Handling detailed query")
        resp = PatchMessageQueryDetailedResp()
        resp.send(sock)

    def send(self, sock):
        LOG.error("Should not get here")


class PatchMessageQueryDetailedResp(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_QUERY_DETAILED_RESP)

    def encode(self):
        global pa
        messages.PatchMessage.encode(self)
        self.message['installed'] = pa.installed
        self.message['to_remove'] = pa.to_remove
        self.message['missing_pkgs'] = pa.missing_pkgs
        self.message['nodetype'] = cfg.nodetype
        self.message['sw_version'] = SW_VERSION
        self.message['subfunctions'] = subfunctions
        self.message['state'] = pa.state

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock):
        self.encode()
        message = json.dumps(self.message)
        sock.sendall(message)


class PatchMessageAgentInstallReq(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_AGENT_INSTALL_REQ)
        self.force = False

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        if 'force' in data:
            self.force = data['force']

    def encode(self):
        # Nothing to add to the HELLO_AGENT, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        LOG.info("Handling host install request, force=%s" % self.force)
        global pa
        resp = PatchMessageAgentInstallResp()

        if not os.path.exists(node_is_locked_file):
            if self.force:
                LOG.info("Installing on unlocked node, with force option")
            else:
                LOG.info("Rejecting install request on unlocked node")
                pa.state = constants.PATCH_AGENT_STATE_INSTALL_REJECTED
                pa.rejection_timestamp = time.time()
                resp.status = False
                resp.reject_reason = 'Node must be locked.'
                resp.send(sock, addr)
                return

        resp.status = pa.handle_install()
        resp.send(sock, addr)

    def send(self, sock):
        LOG.error("Should not get here")


class PatchMessageAgentInstallResp(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_AGENT_INSTALL_RESP)
        self.status = False
        self.reject_reason = None

    def encode(self):
        global pa
        messages.PatchMessage.encode(self)
        self.message['status'] = self.status
        if self.reject_reason is not None:
            self.message['reject_reason'] = self.reject_reason

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock, addr):
        address = (addr[0], cfg.controller_port)
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(message, address)

        # Send a hello ack to follow it
        resp = PatchMessageHelloAgentAck()
        resp.send(sock)


class PatchAgent(PatchService):
    def __init__(self):
        PatchService.__init__(self)
        self.sock_out = None
        self.sock_in = None
        self.listener = None
        self.changes = False
        self.installed = {}
        self.to_install = {}
        self.to_remove = []
        self.missing_pkgs = []
        self.patch_op_counter = 0
        self.node_is_patched = os.path.exists(node_is_patched_file)
        self.node_is_patched_timestamp = 0
        self.query_id = 0
        self.state = constants.PATCH_AGENT_STATE_IDLE
        self.last_config_audit = 0
        self.rejection_timestamp = 0

        # Check state flags
        if os.path.exists(patch_installing_file):
            # We restarted while installing. Change to failed
            setflag(patch_failed_file)
            os.remove(patch_installing_file)

        if os.path.exists(patch_failed_file):
            self.state = constants.PATCH_AGENT_STATE_INSTALL_FAILED

        self.patch_failed = os.path.exists(patch_failed_file)

    def update_config(self):
        cfg.read_config()

        if self.port != cfg.agent_port:
            self.port = cfg.agent_port

        if self.mcast_addr != cfg.agent_mcast_group:
            self.mcast_addr = cfg.agent_mcast_group

    def setup_tcp_socket(self):
        address_family = utils.get_management_family()
        self.listener = socket.socket(address_family, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('', self.port))
        self.listener.listen(2)  # Allow two connections, for two controllers

    def audit_smart_config(self):
        LOG.info("Auditing smart configuration")

        # Get the current channel config
        try:
            output = subprocess.check_output(smart_cmd +
                                             ["channel", "--yaml"],
                                             stderr=subprocess.STDOUT)
            config = yaml.load(output)
        except subprocess.CalledProcessError as e:
            LOG.exception("Failed to query channels")
            LOG.error("Command output: %s" % e.output)
            return False
        except Exception:
            LOG.exception("Failed to query channels")
            return False

        expected = [{'channel': 'rpmdb',
                     'type': 'rpm-sys',
                     'name': 'RPM Database',
                     'baseurl': None},
                    {'channel': 'base',
                     'type': 'rpm-md',
                     'name': 'Base',
                     'baseurl': "http://controller/feed/rel-%s" % SW_VERSION},
                    {'channel': 'updates',
                     'type': 'rpm-md',
                     'name': 'Patches',
                     'baseurl': "http://controller/updates/rel-%s" % SW_VERSION}]

        updated = False

        for item in expected:
            channel = item['channel']
            ch_type = item['type']
            ch_name = item['name']
            ch_baseurl = item['baseurl']

            add_channel = False

            if channel in config:
                # Verify existing channel config
                if (config[channel].get('type') != ch_type or
                        config[channel].get('name') != ch_name or
                        config[channel].get('baseurl') != ch_baseurl):
                    # Config is invalid
                    add_channel = True
                    LOG.warning("Invalid smart config found for %s" % channel)
                    try:
                        output = subprocess.check_output(smart_cmd +
                                                         ["channel", "--yes",
                                                          "--remove", channel],
                                                         stderr=subprocess.STDOUT)
                    except subprocess.CalledProcessError as e:
                        LOG.exception("Failed to configure %s channel" % channel)
                        LOG.error("Command output: %s" % e.output)
                        return False
            else:
                # Channel is missing
                add_channel = True
                LOG.warning("Channel %s is missing from config" % channel)

            if add_channel:
                LOG.info("Adding channel %s" % channel)
                cmd_args = ["channel", "--yes", "--add", channel,
                            "type=%s" % ch_type,
                            "name=%s" % ch_name]
                if ch_baseurl is not None:
                    cmd_args += ["baseurl=%s" % ch_baseurl]

                try:
                    output = subprocess.check_output(smart_cmd + cmd_args,
                                                     stderr=subprocess.STDOUT)
                except subprocess.CalledProcessError as e:
                    LOG.exception("Failed to configure %s channel" % channel)
                    LOG.error("Command output: %s" % e.output)
                    return False

                updated = True

        # Validate the smart config
        try:
            output = subprocess.check_output(smart_cmd +
                                             ["config", "--yaml"],
                                             stderr=subprocess.STDOUT)
            config = yaml.load(output)
        except subprocess.CalledProcessError as e:
            LOG.exception("Failed to query smart config")
            LOG.error("Command output: %s" % e.output)
            return False
        except Exception:
            LOG.exception("Failed to query smart config")
            return False

        # Check for the rpm-nolinktos flag
        nolinktos = 'rpm-nolinktos'
        if config.get(nolinktos) is not True:
            # Set the flag
            LOG.warning("Setting %s option" % nolinktos)
            try:
                output = subprocess.check_output(smart_cmd +
                                                 ["config", "--set",
                                                  "%s=true" % nolinktos],
                                                 stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                LOG.exception("Failed to configure %s option" % nolinktos)
                LOG.error("Command output: %s" % e.output)
                return False

            updated = True

        # Check for the rpm-check-signatures flag
        nosignature = 'rpm-check-signatures'
        if config.get(nosignature) is not False:
            # Set the flag
            LOG.warning("Setting %s option" % nosignature)
            try:
                output = subprocess.check_output(smart_cmd +
                                                 ["config", "--set",
                                                  "%s=false" % nosignature],
                                                 stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                LOG.exception("Failed to configure %s option" % nosignature)
                LOG.error("Command output: %s" % e.output)
                return False

            updated = True

        if updated:
            try:
                subprocess.check_output(smart_update, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                LOG.exception("Failed to update smartpm")
                LOG.error("Command output: %s" % e.output)
                return False

            # Reset the patch op counter to force a detailed query
            self.patch_op_counter = 0

        self.last_config_audit = time.time()
        return True

    def timed_audit_smart_config(self):
        rc = True
        if (time.time() - self.last_config_audit) > 1800:
            # It's been 30 minutes since the last completed audit
            LOG.info("Kicking timed audit")
            rc = self.audit_smart_config()

        return rc

    @staticmethod
    def parse_smart_pkglist(output):
        pkglist = {}
        for line in output.splitlines():
            if line == '':
                continue

            fields = line.split()
            pkgname = fields[0]
            (version, arch) = fields[1].split('@')

            if pkgname not in pkglist:
                pkglist[pkgname] = {}
                pkglist[pkgname][arch] = version
            elif arch not in pkglist[pkgname]:
                pkglist[pkgname][arch] = version
            else:
                stored_ver = pkglist[pkgname][arch]

                # The rpm.labelCompare takes version broken into 3 components
                # It returns:
                #     1, if first arg is higher version
                #     0, if versions are same
                #     -1, if first arg is lower version
                rc = rpm.labelCompare(stringToVersion(version),
                                      stringToVersion(stored_ver))

                if rc > 0:
                    # Update version
                    pkglist[pkgname][arch] = version

        return pkglist

    @staticmethod
    def get_pkg_version(pkglist, pkg, arch):
        if pkg not in pkglist:
            return None
        if arch not in pkglist[pkg]:
            return None
        return pkglist[pkg][arch]

    def parse_smart_newer(self, output):
        # Skip the first two lines, which are headers
        for line in output.splitlines()[2:]:
            if line == '':
                continue

            fields = line.split()
            pkgname = fields[0]
            installedver = fields[2]
            newver = fields[5]

            self.installed[pkgname] = installedver
            self.to_install[pkgname] = newver

    def parse_smart_orphans(self, output):
        for pkgname in output.splitlines():
            if pkgname == '':
                continue

            highest_version = None

            try:
                query = subprocess.check_output(smart_query_repos + ["--show-format", '$version\n', pkgname])
                # The last non-blank version is the highest
                for version in query.splitlines():
                    if version == '':
                        continue
                    highest_version = version.split('@')[0]

            except subprocess.CalledProcessError:
                # Package is not in the repo
                highest_version = None

            if highest_version is None:
                # Package is to be removed
                self.to_remove.append(pkgname)
            else:
                # Rollback to the highest version
                self.to_install[pkgname] = highest_version

            # Get the installed version
            try:
                query = subprocess.check_output(smart_query + ["--installed", "--show-format", '$version\n', pkgname])
                for version in query.splitlines():
                    if version == '':
                        continue
                    self.installed[pkgname] = version.split('@')[0]
                    break
            except subprocess.CalledProcessError:
                LOG.error("Failed to query installed version of %s" % pkgname)

            self.changes = True

    def check_groups(self):
        # Get the groups file
        mygroup = "updates-%s" % "-".join(subfunctions)
        self.missing_pkgs = []
        installed_pkgs = []

        groups_url = "http://controller/updates/rel-%s/comps.xml" % SW_VERSION
        try:
            req = requests.get(groups_url)
            if req.status_code != 200:
                LOG.error("Failed to get groups list from server")
                return False
        except requests.ConnectionError:
            LOG.error("Failed to connect to server")
            return False

        # Get list of installed packages
        try:
            query = subprocess.check_output(["rpm", "-qa", "--queryformat", "%{NAME}\n"])
            installed_pkgs = query.split()
        except subprocess.CalledProcessError:
            LOG.exception("Failed to query RPMs")
            return False

        root = ElementTree.fromstring(req.text)
        for child in root:
            group_id = child.find('id')
            if group_id is None or group_id.text != mygroup:
                continue

            pkglist = child.find('packagelist')
            if pkglist is None:
                continue

            for pkg in pkglist.findall('packagereq'):
                if pkg.text not in installed_pkgs and pkg.text not in self.missing_pkgs:
                    self.missing_pkgs.append(pkg.text)
                    self.changes = True

    def query(self):
        """ Check current patch state """
        if not check_install_uuid():
            LOG.info("Failed install_uuid check. Skipping query")
            return False

        if not self.audit_smart_config():
            # Set a state to "unknown"?
            return False

        try:
            subprocess.check_output(smart_update, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            LOG.error("Failed to update smartpm")
            LOG.error("Command output: %s" % e.output)
            # Set a state to "unknown"?
            return False

        # Generate a unique query id
        self.query_id = random.random()

        self.changes = False
        self.installed = {}
        self.to_install = {}
        self.to_remove = []
        self.missing_pkgs = []

        # Get the repo data
        pkgs_installed = {}
        pkgs_base = {}
        pkgs_updates = {}

        try:
            output = subprocess.check_output(smart_query_installed)
            pkgs_installed = self.parse_smart_pkglist(output)
        except subprocess.CalledProcessError as e:
            LOG.error("Failed to query installed pkgs: %s" % e.output)
            # Set a state to "unknown"?
            return False

        try:
            output = subprocess.check_output(smart_query_base)
            pkgs_base = self.parse_smart_pkglist(output)
        except subprocess.CalledProcessError as e:
            LOG.error("Failed to query base pkgs: %s" % e.output)
            # Set a state to "unknown"?
            return False

        try:
            output = subprocess.check_output(smart_query_updates)
            pkgs_updates = self.parse_smart_pkglist(output)
        except subprocess.CalledProcessError as e:
            LOG.error("Failed to query patched pkgs: %s" % e.output)
            # Set a state to "unknown"?
            return False

        # There are four possible actions:
        # 1. If installed pkg is not in base or updates, remove it.
        # 2. If installed pkg version is higher than highest in base
        #    or updates, downgrade it.
        # 3. If installed pkg version is lower than highest in updates,
        #    upgrade it.
        # 4. If pkg in grouplist is not in installed, install it.

        for pkg in pkgs_installed:
            for arch in pkgs_installed[pkg]:
                installed_version = pkgs_installed[pkg][arch]
                updates_version = self.get_pkg_version(pkgs_updates, pkg, arch)
                base_version = self.get_pkg_version(pkgs_base, pkg, arch)

                if updates_version is None and base_version is None:
                    # Remove it
                    self.to_remove.append(pkg)
                    self.changes = True
                    continue

                compare_version = updates_version
                if compare_version is None:
                    compare_version = base_version

                # Compare the installed version to what's in the repo
                rc = rpm.labelCompare(stringToVersion(installed_version),
                                      stringToVersion(compare_version))
                if rc == 0:
                    # Versions match, nothing to do.
                    continue
                else:
                    # Install the version from the repo
                    self.to_install[pkg] = "@".join([compare_version, arch])
                    self.installed[pkg] = "@".join([installed_version, arch])
                    self.changes = True

        # Look for new packages
        self.check_groups()

        LOG.info("Patch state query returns %s" % self.changes)
        LOG.info("Installed: %s" % self.installed)
        LOG.info("To install: %s" % self.to_install)
        LOG.info("To remove: %s" % self.to_remove)
        LOG.info("Missing: %s" % self.missing_pkgs)

        return True

    def handle_install(self, verbose_to_stdout=False, disallow_insvc_patch=False):
        #
        # The disallow_insvc_patch parameter is set when we're installing
        # the patch during init. At that time, we don't want to deal with
        # in-service patch scripts, so instead we'll treat any patch as
        # a reboot-required when this parameter is set. Rather than running
        # any scripts, the RR flag will be set, which will result in the node
        # being rebooted immediately upon completion of the installation.
        #

        LOG.info("Handling install")

        # Check the INSTALL_UUID first. If it doesn't match the active
        # controller, we don't want to install patches.
        if not check_install_uuid():
            LOG.error("Failed install_uuid check. Skipping install")

            self.patch_failed = True
            setflag(patch_failed_file)
            self.state = constants.PATCH_AGENT_STATE_INSTALL_FAILED

            # Send a hello to provide a state update
            if self.sock_out is not None:
                hello_ack = PatchMessageHelloAgentAck()
                hello_ack.send(self.sock_out)

            return False

        self.state = constants.PATCH_AGENT_STATE_INSTALLING
        setflag(patch_installing_file)

        try:
            # Create insvc patch directories
            if os.path.exists(insvc_patch_scripts):
                shutil.rmtree(insvc_patch_scripts, ignore_errors=True)
            if os.path.exists(insvc_patch_flags):
                shutil.rmtree(insvc_patch_flags, ignore_errors=True)
            os.mkdir(insvc_patch_scripts, 0700)
            os.mkdir(insvc_patch_flags, 0700)
        except:
            LOG.exception("Failed to create in-service patch directories")

        # Send a hello to provide a state update
        if self.sock_out is not None:
            hello_ack = PatchMessageHelloAgentAck()
            hello_ack.send(self.sock_out)

        # Build up the install set
        if verbose_to_stdout:
            print "Checking for software updates..."
        self.query()
        install_set = []
        for pkg, version in self.to_install.iteritems():
            install_set.append("%s-%s" % (pkg, version))

        install_set += self.missing_pkgs

        changed = False
        rc = True

        if len(install_set) > 0:
            try:
                if verbose_to_stdout:
                    print "Installing software updates..."
                LOG.info("Installing: %s" % ", ".join(install_set))
                output = subprocess.check_output(smart_install_cmd + install_set, stderr=subprocess.STDOUT)
                changed = True
                for line in output.split('\n'):
                    LOG.info("INSTALL: %s" % line)
                if verbose_to_stdout:
                    print "Software updated."
            except subprocess.CalledProcessError as e:
                LOG.exception("Failed to install RPMs")
                LOG.error("Command output: %s" % e.output)
                rc = False
                if verbose_to_stdout:
                    print "WARNING: Software update failed."
        else:
            if verbose_to_stdout:
                print "Nothing to install."
            LOG.info("Nothing to install")

        if rc:
            self.query()
            remove_set = self.to_remove

            if len(remove_set) > 0:
                try:
                    if verbose_to_stdout:
                        print "Handling patch removal..."
                    LOG.info("Removing: %s" % ", ".join(remove_set))
                    output = subprocess.check_output(smart_remove_cmd + remove_set, stderr=subprocess.STDOUT)
                    changed = True
                    for line in output.split('\n'):
                        LOG.info("REMOVE: %s" % line)
                    if verbose_to_stdout:
                        print "Patch removal complete."
                except subprocess.CalledProcessError as e:
                    LOG.exception("Failed to remove RPMs")
                    LOG.error("Command output: %s" % e.output)
                    rc = False
                    if verbose_to_stdout:
                        print "WARNING: Patch removal failed."
            else:
                if verbose_to_stdout:
                    print "Nothing to remove."
                LOG.info("Nothing to remove")

        if changed:
            # Update the node_is_patched flag
            setflag(node_is_patched_file)

            self.node_is_patched = True
            if verbose_to_stdout:
                print "This node has been patched."

            if os.path.exists(node_is_patched_rr_file):
                LOG.info("Reboot is required. Skipping patch-scripts")
            elif disallow_insvc_patch:
                LOG.info("Disallowing patch-scripts. Treating as reboot-required")
                setflag(node_is_patched_rr_file)
            else:
                LOG.info("Running in-service patch-scripts")

                try:
                    subprocess.check_output(run_insvc_patch_scripts_cmd, stderr=subprocess.STDOUT)

                    # Clear the node_is_patched flag, since we've handled it in-service
                    clearflag(node_is_patched_file)
                    self.node_is_patched = False
                except subprocess.CalledProcessError as e:
                    LOG.exception("In-Service patch scripts failed")
                    LOG.error("Command output: %s" % e.output)
                    # Fail the patching operation
                    rc = False

        # Clear the in-service patch dirs
        if os.path.exists(insvc_patch_scripts):
            shutil.rmtree(insvc_patch_scripts, ignore_errors=True)
        if os.path.exists(insvc_patch_flags):
            shutil.rmtree(insvc_patch_flags, ignore_errors=True)

        if rc:
            self.patch_failed = False
            clearflag(patch_failed_file)
            self.state = constants.PATCH_AGENT_STATE_IDLE
        else:
            # Update the patch_failed flag
            self.patch_failed = True
            setflag(patch_failed_file)
            self.state = constants.PATCH_AGENT_STATE_INSTALL_FAILED

        clearflag(patch_installing_file)
        self.query()

        # Send a hello to provide a state update
        if self.sock_out is not None:
            hello_ack = PatchMessageHelloAgentAck()
            hello_ack.send(self.sock_out)

        return rc

    def handle_patch_op_counter(self, counter):
        changed = False
        if os.path.exists(node_is_patched_file):
            # The node has been patched. Run a query if:
            # - node_is_patched didn't exist previously
            # - node_is_patched timestamp changed
            timestamp = os.path.getmtime(node_is_patched_file)
            if not self.node_is_patched:
                self.node_is_patched = True
                self.node_is_patched_timestamp = timestamp
                changed = True
            elif self.node_is_patched_timestamp != timestamp:
                self.node_is_patched_timestamp = timestamp
                changed = True
        elif self.node_is_patched:
            self.node_is_patched = False
            self.node_is_patched_timestamp = 0
            changed = True

        if self.patch_op_counter < counter:
            self.patch_op_counter = counter
            changed = True

        if changed:
            rc = self.query()
            if not rc:
                # Query failed. Reset the op counter
                self.patch_op_counter = 0

    def run(self):
        self.setup_socket()

        while self.sock_out is None:
            # Check every thirty seconds?
            # Once we've got a conf file, tied into packstack,
            # we'll get restarted when the file is updated,
            # and this should be unnecessary.
            time.sleep(30)
            self.setup_socket()

        self.setup_tcp_socket()

        # Ok, now we've got our socket.
        # Let's let the controllers know we're here
        hello_ack = PatchMessageHelloAgentAck()
        hello_ack.send(self.sock_out)

        first_hello = True

        connections = []

        timeout = time.time() + 30.0
        remaining = 30

        while True:
            inputs = [self.sock_in, self.listener] + connections
            outputs = []

            rlist, wlist, xlist = select.select(inputs, outputs, inputs, remaining)

            remaining = int(timeout - time.time())
            if remaining <= 0 or remaining > 30:
                timeout = time.time() + 30.0
                remaining = 30

            if (len(rlist) == 0 and
                    len(wlist) == 0 and
                    len(xlist) == 0):
                # Timeout hit
                self.audit_socket()
                continue

            for s in rlist:
                if s == self.listener:
                    conn, addr = s.accept()
                    connections.append(conn)
                    continue

                data = ''
                addr = None
                msg = None

                if s == self.sock_in:
                    # Receive from UDP
                    data, addr = s.recvfrom(1024)
                else:
                    # Receive from TCP
                    while True:
                        try:
                            packet = s.recv(1024)
                        except socket.error:
                            LOG.exception("Socket error on recv")
                            data = ''
                            break

                        if packet:
                            data += packet

                            if data == '':
                                break

                            try:
                                datachk = json.loads(data)
                                break
                            except ValueError:
                                # Message is incomplete
                                continue
                        else:
                            # End of TCP message received
                            break

                    if data == '':
                        # Connection dropped
                        connections.remove(s)
                        s.close()
                        continue

                msgdata = json.loads(data)

                # For now, discard any messages that are not msgversion==1
                if 'msgversion' in msgdata and msgdata['msgversion'] != 1:
                    continue

                if 'msgtype' in msgdata:
                    if msgdata['msgtype'] == messages.PATCHMSG_HELLO_AGENT:
                        if first_hello:
                            self.query()
                            first_hello = False

                        msg = PatchMessageHelloAgent()
                    elif msgdata['msgtype'] == messages.PATCHMSG_QUERY_DETAILED:
                        msg = PatchMessageQueryDetailed()
                    elif msgdata['msgtype'] == messages.PATCHMSG_AGENT_INSTALL_REQ:
                        msg = PatchMessageAgentInstallReq()

                if msg is None:
                    msg = messages.PatchMessage()

                msg.decode(msgdata)
                if s == self.sock_in:
                    msg.handle(self.sock_out, addr)
                else:
                    msg.handle(s, addr)

            for s in xlist:
                if s in connections:
                    connections.remove(s)
                    s.close()

            # Check for in-service patch restart flag
            if os.path.exists(insvc_patch_restart_agent):
                # Make sure it's safe to restart, ie. no reqs queued
                rlist, wlist, xlist = select.select(inputs, outputs, inputs, 0)
                if (len(rlist) == 0 and
                        len(wlist) == 0 and
                        len(xlist) == 0):
                    # Restart
                    LOG.info("In-service patch restart flag detected. Exiting.")
                    os.remove(insvc_patch_restart_agent)
                    exit(0)


def main():
    global pa

    configure_logging()

    cfg.read_config()

    pa = PatchAgent()
    pa.query()

    if len(sys.argv) <= 1:
        pa.run()
    elif sys.argv[1] == "--install":
        pa.handle_install(verbose_to_stdout=True, disallow_insvc_patch=True)
    elif sys.argv[1] == "--status":
        rc = 0
        if pa.changes:
            rc = 1
        exit(rc)
