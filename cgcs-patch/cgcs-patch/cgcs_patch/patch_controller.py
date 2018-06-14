"""
Copyright (c) 2014-2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import shutil
import threading
import time
import socket
import json
import select
import subprocess
import ConfigParser
import rpm
import os

from rpmUtils.miscutils import stringToVersion

from wsgiref import simple_server
from cgcs_patch.api import app
from cgcs_patch.authapi import app as auth_app
from cgcs_patch.patch_functions import \
    configure_logging, BasePackageData, \
    avail_dir, applied_dir, committed_dir, \
    PatchFile, parse_rpm_filename, \
    package_dir, repo_dir, SW_VERSION, root_package_dir
from cgcs_patch.exceptions import MetadataFail, RpmFail, PatchFail, PatchValidationFailure, PatchMismatchFailure
from cgcs_patch.patch_functions import LOG
from cgcs_patch.patch_functions import audit_log_info
from cgcs_patch.patch_functions import patch_dir, repo_root_dir
from cgcs_patch.patch_functions import PatchData
from cgcs_patch.base import PatchService

import cgcs_patch.config as cfg
import cgcs_patch.utils as utils
# noinspection PyUnresolvedReferences
from oslo_config import cfg as oslo_cfg

import cgcs_patch.messages as messages
import cgcs_patch.constants as constants

CONF = oslo_cfg.CONF

pidfile_path = "/var/run/patch_controller.pid"

pc = None
state_file = "/opt/patching/.controller.state"

insvc_patch_restart_controller = "/run/patching/.restart.patch-controller"

stale_hosts = []
pending_queries = []

thread_death = None
keep_running = True

# Limit socket blocking to 5 seconds to allow for thread to shutdown
api_socket_timeout = 5.0


class ControllerNeighbour(object):
    def __init__(self):
        self.last_ack = 0
        self.synced = False

    def rx_ack(self):
        self.last_ack = time.time()

    def get_age(self):
        return int(time.time() - self.last_ack)

    def rx_synced(self):
        self.synced = True

    def clear_synced(self):
        self.synced = False

    def get_synced(self):
        return self.synced


class AgentNeighbour(object):
    def __init__(self, ip):
        self.ip = ip
        self.last_ack = 0
        self.last_query_id = 0
        self.out_of_date = False
        self.hostname = "n/a"
        self.requires_reboot = False
        self.patch_failed = False
        self.stale = False
        self.pending_query = False
        self.installed = {}
        self.to_remove = []
        self.missing_pkgs = []
        self.nodetype = None
        self.sw_version = "unknown"
        self.subfunctions = []
        self.state = None

    def rx_ack(self,
               hostname,
               out_of_date,
               requires_reboot,
               query_id,
               patch_failed,
               sw_version,
               state):
        self.last_ack = time.time()
        self.hostname = hostname
        self.patch_failed = patch_failed
        self.sw_version = sw_version
        self.state = state

        if out_of_date != self.out_of_date or requires_reboot != self.requires_reboot:
            self.out_of_date = out_of_date
            self.requires_reboot = requires_reboot
            LOG.info("Agent %s (%s) reporting out_of_date=%s, requires_reboot=%s" % (
                self.hostname,
                self.ip,
                self.out_of_date,
                self.requires_reboot))

        if self.last_query_id != query_id:
            self.last_query_id = query_id
            self.stale = True
            if self.ip not in stale_hosts and self.ip not in pending_queries:
                stale_hosts.append(self.ip)

    def get_age(self):
        return int(time.time() - self.last_ack)

    def handle_query_detailed_resp(self,
                                   installed,
                                   to_remove,
                                   missing_pkgs,
                                   nodetype,
                                   sw_version,
                                   subfunctions,
                                   state):
        self.installed = installed
        self.to_remove = to_remove
        self.missing_pkgs = missing_pkgs
        self.nodetype = nodetype
        self.stale = False
        self.pending_query = False
        self.sw_version = sw_version
        self.subfunctions = subfunctions
        self.state = state

        if self.ip in pending_queries:
            pending_queries.remove(self.ip)

        if self.ip in stale_hosts:
            stale_hosts.remove(self.ip)

    def get_dict(self):
        d = {"ip": self.ip,
             "hostname": self.hostname,
             "patch_current": not self.out_of_date,
             "secs_since_ack": self.get_age(),
             "patch_failed": self.patch_failed,
             "stale_details": self.stale,
             "installed": self.installed,
             "to_remove": self.to_remove,
             "missing_pkgs": self.missing_pkgs,
             "nodetype": self.nodetype,
             "subfunctions": self.subfunctions,
             "sw_version": self.sw_version,
             "state": self.state}

        global pc
        if self.out_of_date and not pc.allow_insvc_patching:
            d["requires_reboot"] = True
        else:
            d["requires_reboot"] = self.requires_reboot

        # Included for future enhancement, to allow per-node determination
        # of in-service patching
        d["allow_insvc_patching"] = pc.allow_insvc_patching

        return d


class PatchMessageHello(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_HELLO)
        self.patch_op_counter = 0

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        if 'patch_op_counter' in data:
            self.patch_op_counter = data['patch_op_counter']

    def encode(self):
        global pc
        messages.PatchMessage.encode(self)
        self.message['patch_op_counter'] = pc.patch_op_counter

    def handle(self, sock, addr):
        global pc
        host = addr[0]
        if host == cfg.get_mgmt_ip():
            # Ignore messages from self
            return

        # Send response
        if self.patch_op_counter > 0:
            pc.handle_nbr_patch_op_counter(host, self.patch_op_counter)

        resp = PatchMessageHelloAck()
        resp.send(sock)

    def send(self, sock):
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(message, (cfg.controller_mcast_group, cfg.controller_port))


class PatchMessageHelloAck(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_HELLO_ACK)

    def encode(self):
        # Nothing to add, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        global pc

        pc.controller_neighbours_lock.acquire()
        if not addr[0] in pc.controller_neighbours:
            pc.controller_neighbours[addr[0]] = ControllerNeighbour()

        pc.controller_neighbours[addr[0]].rx_ack()
        pc.controller_neighbours_lock.release()

    def send(self, sock):
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(message, (cfg.controller_mcast_group, cfg.controller_port))


class PatchMessageSyncReq(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_SYNC_REQ)

    def encode(self):
        # Nothing to add to the SYNC_REQ, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        global pc
        host = addr[0]
        if host == cfg.get_mgmt_ip():
            # Ignore messages from self
            return

        # We may need to do this in a separate thread, so that we continue to process hellos
        LOG.info("Handling sync req")

        pc.sync_from_nbr(host)

        resp = PatchMessageSyncComplete()
        resp.send(sock)

    def send(self, sock):
        LOG.info("sending sync req")
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(message, (cfg.controller_mcast_group, cfg.controller_port))


class PatchMessageSyncComplete(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_SYNC_COMPLETE)

    def encode(self):
        # Nothing to add to the SYNC_COMPLETE, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        global pc
        LOG.info("Handling sync complete")

        pc.controller_neighbours_lock.acquire()
        if not addr[0] in pc.controller_neighbours:
            pc.controller_neighbours[addr[0]] = ControllerNeighbour()

        pc.controller_neighbours[addr[0]].rx_synced()
        pc.controller_neighbours_lock.release()

    def send(self, sock):
        LOG.info("sending sync complete")
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(message, (cfg.controller_mcast_group, cfg.controller_port))


class PatchMessageHelloAgent(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_HELLO_AGENT)

    def encode(self):
        global pc
        messages.PatchMessage.encode(self)
        self.message['patch_op_counter'] = pc.patch_op_counter

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock):
        self.encode()
        message = json.dumps(self.message)
        local_hostname = utils.ip_to_versioned_localhost(cfg.agent_mcast_group)
        sock.sendto(message, (cfg.agent_mcast_group, cfg.agent_port))
        sock.sendto(message, (local_hostname, cfg.agent_port))


class PatchMessageHelloAgentAck(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_HELLO_AGENT_ACK)
        self.query_id = 0
        self.agent_out_of_date = False
        self.agent_hostname = "n/a"
        self.agent_requires_reboot = False
        self.agent_patch_failed = False
        self.agent_sw_version = "unknown"
        self.agent_state = "unknown"

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        if 'query_id' in data:
            self.query_id = data['query_id']
        if 'out_of_date' in data:
            self.agent_out_of_date = data['out_of_date']
        if 'hostname' in data:
            self.agent_hostname = data['hostname']
        if 'requires_reboot' in data:
            self.agent_requires_reboot = data['requires_reboot']
        if 'patch_failed' in data:
            self.agent_patch_failed = data['patch_failed']
        if 'sw_version' in data:
            self.agent_sw_version = data['sw_version']
        if 'state' in data:
            self.agent_state = data['state']

    def encode(self):
        # Nothing to add, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        global pc

        pc.hosts_lock.acquire()
        if not addr[0] in pc.hosts:
            pc.hosts[addr[0]] = AgentNeighbour(addr[0])

        pc.hosts[addr[0]].rx_ack(self.agent_hostname,
                                 self.agent_out_of_date,
                                 self.agent_requires_reboot,
                                 self.query_id,
                                 self.agent_patch_failed,
                                 self.agent_sw_version,
                                 self.agent_state)
        pc.hosts_lock.release()

    def send(self, sock):
        LOG.error("Should not get here")


class PatchMessageQueryDetailed(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_QUERY_DETAILED)

    def encode(self):
        # Nothing to add to the message, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock):
        self.encode()
        message = json.dumps(self.message)
        sock.sendall(message)


class PatchMessageQueryDetailedResp(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_QUERY_DETAILED_RESP)
        self.agent_sw_version = "unknown"
        self.installed = {}
        self.to_install = {}
        self.to_remove = []
        self.missing_pkgs = []
        self.subfunctions = []
        self.nodetype = "unknown"
        self.agent_sw_version = "unknown"
        self.agent_state = "unknown"

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        if 'installed' in data:
            self.installed = data['installed']
        if 'to_remove' in data:
            self.to_remove = data['to_remove']
        if 'missing_pkgs' in data:
            self.missing_pkgs = data['missing_pkgs']
        if 'nodetype' in data:
            self.nodetype = data['nodetype']
        if 'sw_version' in data:
            self.agent_sw_version = data['sw_version']
        if 'subfunctions' in data:
            self.subfunctions = data['subfunctions']
        if 'state' in data:
            self.agent_state = data['state']

    def encode(self):
        LOG.error("Should not get here")

    def handle(self, sock, addr):
        global pc

        ip = addr[0]
        pc.hosts_lock.acquire()
        if ip in pc.hosts:
            pc.hosts[ip].handle_query_detailed_resp(self.installed,
                                                    self.to_remove,
                                                    self.missing_pkgs,
                                                    self.nodetype,
                                                    self.agent_sw_version,
                                                    self.subfunctions,
                                                    self.agent_state)
            for patch_id in pc.interim_state.keys():
                if ip in pc.interim_state[patch_id]:
                    pc.interim_state[patch_id].remove(ip)
                    if len(pc.interim_state[patch_id]) == 0:
                        del pc.interim_state[patch_id]
            pc.hosts_lock.release()
            pc.check_patch_states()
        else:
            pc.hosts_lock.release()

    def send(self, sock):
        LOG.error("Should not get here")


class PatchMessageAgentInstallReq(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_AGENT_INSTALL_REQ)
        self.ip = None
        self.force = False

    def encode(self):
        global pc
        messages.PatchMessage.encode(self)
        self.message['force'] = self.force

    def handle(self, sock, addr):
        LOG.error("Should not get here")

    def send(self, sock):
        LOG.info("sending install request to node: %s" % self.ip)
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(message, (self.ip, cfg.agent_port))


class PatchMessageAgentInstallResp(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_AGENT_INSTALL_RESP)
        self.status = False
        self.reject_reason = None

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        if 'status' in data:
            self.status = data['status']
        if 'reject_reason' in data:
            self.reject_reason = data['reject_reason']

    def encode(self):
        # Nothing to add, so just call the super class
        messages.PatchMessage.encode(self)

    def handle(self, sock, addr):
        LOG.info("Handling install resp from %s" % addr[0])
        global pc
        # LOG.info("Handling hello ack")

        pc.hosts_lock.acquire()
        if not addr[0] in pc.hosts:
            pc.hosts[addr[0]] = AgentNeighbour(addr[0])

        pc.hosts[addr[0]].install_status = self.status
        pc.hosts[addr[0]].install_pending = False
        pc.hosts[addr[0]].install_reject_reason = self.reject_reason
        pc.hosts_lock.release()

    def send(self, sock):
        LOG.error("Should not get here")


class PatchMessageDropHostReq(messages.PatchMessage):
    def __init__(self):
        messages.PatchMessage.__init__(self, messages.PATCHMSG_DROP_HOST_REQ)
        self.ip = None

    def encode(self):
        messages.PatchMessage.encode(self)
        self.message['ip'] = self.ip

    def decode(self, data):
        messages.PatchMessage.decode(self, data)
        if 'ip' in data:
            self.ip = data['ip']

    def handle(self, sock, addr):
        global pc
        host = addr[0]
        if host == cfg.get_mgmt_ip():
            # Ignore messages from self
            return

        if self.ip is None:
            LOG.error("Received PATCHMSG_DROP_HOST_REQ with no ip: %s" % json.dumps(self.data))
            return

        pc.drop_host(self.ip, sync_nbr=False)
        return

    def send(self, sock):
        self.encode()
        message = json.dumps(self.message)
        sock.sendto(message, (cfg.controller_mcast_group, cfg.controller_port))



class PatchController(PatchService):
    def __init__(self):
        PatchService.__init__(self)

        # Locks
        self.socket_lock = threading.RLock()
        self.controller_neighbours_lock = threading.RLock()
        self.hosts_lock = threading.RLock()
        self.patch_data_lock = threading.RLock()

        self.hosts = {}
        self.controller_neighbours = {}

        # interim_state is used to track hosts that have not responded
        # with fresh queries since a patch was applied or removed, on
        # a per-patch basis. This allows the patch controller to move
        # patches immediately into a "Partial" state until all nodes
        # have responded.
        #
        self.interim_state = {}

        self.sock_out = None
        self.sock_in = None
        self.patch_op_counter = 1
        self.patch_data = PatchData()
        self.patch_data.load_all()
        self.check_patch_states()
        self.base_pkgdata = BasePackageData()

        self.allow_insvc_patching = True

        if os.path.isfile(state_file):
            self.read_state_file()
        else:
            self.write_state_file()

    def update_config(self):
        cfg.read_config()

        if self.port != cfg.controller_port:
            self.port = cfg.controller_port

        if self.mcast_addr != cfg.controller_mcast_group:
            self.mcast_addr = cfg.controller_mcast_group

    def socket_lock_acquire(self):
        self.socket_lock.acquire()

    def socket_lock_release(self):
        try:
            self.socket_lock.release()
        except:
            pass

    def write_state_file(self):
        config = ConfigParser.ConfigParser()

        cfgfile = open(state_file, 'w')

        config.add_section('runtime')
        config.set('runtime', 'patch_op_counter', self.patch_op_counter)
        config.write(cfgfile)
        cfgfile.close()

    def read_state_file(self):
        config = ConfigParser.ConfigParser()

        config.read(state_file)

        try:
            counter = config.getint('runtime', 'patch_op_counter')
            self.patch_op_counter = counter

            LOG.info("patch_op_counter is: %d" % self.patch_op_counter)
        except ConfigParser.Error:
            LOG.exception("Failed to read state info")

    def handle_nbr_patch_op_counter(self, host, nbr_patch_op_counter):
        if self.patch_op_counter >= nbr_patch_op_counter:
            return

        self.sync_from_nbr(host)

    def sync_from_nbr(self, host):
        # Sync the patching repo
        host_url = utils.ip_to_url(host)
        try:
            output = subprocess.check_output(["rsync",
                                              "-acv",
                                              "--delete",
                                              "--exclude", "tmp",
                                              "rsync://%s/patching/" % host_url,
                                              "%s/" % patch_dir],
                                             stderr=subprocess.STDOUT)
            LOG.info("Synced to mate patching via rsync: %s" % output)
        except subprocess.CalledProcessError as e:
            LOG.error("Failed to rsync: %s" % e.output)
            return False

        try:
            output = subprocess.check_output(["rsync",
                                              "-acv",
                                              "--delete",
                                              "rsync://%s/repo/" % host_url,
                                              "%s/" % repo_root_dir],
                                             stderr=subprocess.STDOUT)
            LOG.info("Synced to mate repo via rsync: %s" % output)
        except subprocess.CalledProcessError:
            LOG.error("Failed to rsync: %s" % output)
            return False

        self.read_state_file()

        self.patch_data_lock.acquire()
        self.hosts_lock.acquire()
        self.interim_state = {}
        self.patch_data.load_all()
        self.check_patch_states()
        self.hosts_lock.release()
        self.patch_data_lock.release()

        return True

    def inc_patch_op_counter(self):
        self.patch_op_counter += 1
        self.write_state_file()

    def check_patch_states(self):
        # If we have no hosts, we can't be sure of the current patch state
        if len(self.hosts) == 0:
            for patch_id in self.patch_data.metadata:
                self.patch_data.metadata[patch_id]["patchstate"] = constants.UNKNOWN
                return

        # Default to allowing in-service patching
        self.allow_insvc_patching = True

        # Take the detailed query results from the hosts and merge with the patch data

        self.hosts_lock.acquire()

        # Initialize patch state data based on repo state and interim_state presence
        for patch_id in self.patch_data.metadata:
            if patch_id in self.interim_state:
                if self.patch_data.metadata[patch_id]["repostate"] == constants.AVAILABLE:
                    self.patch_data.metadata[patch_id]["patchstate"] = constants.PARTIAL_REMOVE
                elif self.patch_data.metadata[patch_id]["repostate"] == constants.APPLIED:
                    self.patch_data.metadata[patch_id]["patchstate"] = constants.PARTIAL_APPLY
            else:
                self.patch_data.metadata[patch_id]["patchstate"] = \
                    self.patch_data.metadata[patch_id]["repostate"]

        any_out_of_date = False
        for ip in self.hosts.keys():
            if not self.hosts[ip].out_of_date:
                continue

            any_out_of_date = True

            for pkg in self.hosts[ip].installed.keys():
                for patch_id in self.patch_data.content_versions.keys():
                    if pkg not in self.patch_data.content_versions[patch_id]:
                        continue

                    if patch_id not in self.patch_data.metadata:
                        LOG.error("Patch data missing for %s" % patch_id)
                        continue

                    # If the patch is on a different release than the host, skip it.
                    if self.patch_data.metadata[patch_id]["sw_version"] != self.hosts[ip].sw_version:
                        continue

                    # Is the installed pkg higher or lower version?
                    # The rpm.labelCompare takes version broken into 3 components
                    installed_ver = self.hosts[ip].installed[pkg].split('@')[0]
                    if ":" in installed_ver:
                        # Ignore epoch
                        installed_ver = installed_ver.split(':')[1]

                    patch_ver = self.patch_data.content_versions[patch_id][pkg]
                    if ":" in patch_ver:
                        # Ignore epoch
                        patch_ver = patch_ver.split(':')[1]

                    rc = rpm.labelCompare(stringToVersion(installed_ver),
                                          stringToVersion(patch_ver))

                    if self.patch_data.metadata[patch_id]["repostate"] == constants.AVAILABLE:
                        # The RPM is not expected to be installed.
                        # If the installed version is the same or higher,
                        # this patch is in a Partial-Remove state
                        if rc >= 0 or patch_id in self.interim_state:
                            self.patch_data.metadata[patch_id]["patchstate"] = constants.PARTIAL_REMOVE
                            if self.patch_data.metadata[patch_id].get("reboot_required") != "N":
                                self.allow_insvc_patching = False
                            continue
                    elif self.patch_data.metadata[patch_id]["repostate"] == constants.APPLIED:
                        # The RPM is expected to be installed.
                        # If the installed version is the lower,
                        # this patch is in a Partial-Apply state
                        if rc == -1 or patch_id in self.interim_state:
                            self.patch_data.metadata[patch_id]["patchstate"] = constants.PARTIAL_APPLY
                            if self.patch_data.metadata[patch_id].get("reboot_required") != "N":
                                self.allow_insvc_patching = False
                            continue

            if self.hosts[ip].sw_version == "14.10":
                # For Release 1
                personality = "personality-%s" % self.hosts[ip].nodetype
            else:
                personality = "personality-%s" % "-".join(self.hosts[ip].subfunctions)

            # Check the to_remove list
            for pkg in self.hosts[ip].to_remove:
                for patch_id in self.patch_data.content_versions.keys():
                    if pkg not in self.patch_data.content_versions[patch_id]:
                        continue

                    if patch_id not in self.patch_data.metadata:
                        LOG.error("Patch data missing for %s" % patch_id)
                        continue

                    if personality not in self.patch_data.metadata[patch_id]:
                        continue

                    if pkg not in self.patch_data.metadata[patch_id][personality]:
                        continue

                    if self.patch_data.metadata[patch_id]["repostate"] == constants.AVAILABLE:
                        # The RPM is not expected to be installed.
                        # This patch is in a Partial-Remove state
                        self.patch_data.metadata[patch_id]["patchstate"] = constants.PARTIAL_REMOVE
                        if self.patch_data.metadata[patch_id].get("reboot_required") != "N":
                            self.allow_insvc_patching = False
                        continue

            # Check the missing_pkgs list
            for pkg in self.hosts[ip].missing_pkgs:
                for patch_id in self.patch_data.content_versions.keys():
                    if pkg not in self.patch_data.content_versions[patch_id]:
                        continue

                    if patch_id not in self.patch_data.metadata:
                        LOG.error("Patch data missing for %s" % patch_id)
                        continue

                    if personality not in self.patch_data.metadata[patch_id]:
                        continue

                    if pkg not in self.patch_data.metadata[patch_id][personality]:
                        continue

                    if self.patch_data.metadata[patch_id]["repostate"] == constants.APPLIED:
                        # The RPM is expected to be installed.
                        # This patch is in a Partial-Apply state
                        self.patch_data.metadata[patch_id]["patchstate"] = constants.PARTIAL_APPLY
                        if self.patch_data.metadata[patch_id].get("reboot_required") != "N":
                            self.allow_insvc_patching = False
                        continue

        self.hosts_lock.release()

    def get_store_filename(self, patch_sw_version, rpmname):
        rpm_dir = package_dir[patch_sw_version]
        rpmfile = "%s/%s" % (rpm_dir, rpmname)
        return rpmfile

    def get_repo_filename(self, patch_sw_version, rpmname):
        rpmfile = self.get_store_filename(patch_sw_version, rpmname)
        if not os.path.isfile(rpmfile):
            msg = "Could not find rpm: %s" % rpmfile
            LOG.error(msg)
            return None

        repo_filename = None

        try:
            # Get the architecture from the RPM
            pkgarch = subprocess.check_output(["rpm",
                                               "-qp",
                                               "--queryformat",
                                               "%{ARCH}",
                                               "--nosignature",
                                               rpmfile])

            repo_filename = "%s/Packages/%s/%s" % (repo_dir[patch_sw_version], pkgarch, rpmname)
        except subprocess.CalledProcessError:
            msg = "RPM query failed for %s" % rpmfile
            LOG.exception(msg)
            return None

        return repo_filename

    def patch_import_api(self, patches):
        """
        Import patches
        :return:
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        # Refresh data, if needed
        self.base_pkgdata.loaddirs()

        # Protect against duplications
        patch_list = sorted(list(set(patches)))

        # First, make sure the specified files exist
        for patch in patch_list:
            if not os.path.isfile(patch):
                raise PatchFail("File does not exist: %s" % patch)

        try:
            if not os.path.exists(avail_dir):
                os.makedirs(avail_dir)
            if not os.path.exists(applied_dir):
                os.makedirs(applied_dir)
            if not os.path.exists(committed_dir):
                os.makedirs(committed_dir)
        except os.error:
            msg = "Failed to create directories"
            LOG.exception(msg)
            raise PatchFail(msg)

        msg = "Importing patches: %s" % ",".join(patch_list)
        LOG.info(msg)
        audit_log_info(msg)

        repo_changed = False

        for patch in patch_list:
            msg = "Importing patch: %s" % patch
            LOG.info(msg)
            audit_log_info(msg)

            # Get the patch_id from the filename
            # and check to see if it's already imported
            (patch_id, ext) = os.path.splitext(os.path.basename(patch))
            if patch_id in self.patch_data.metadata:
                if self.patch_data.metadata[patch_id]["repostate"] == constants.APPLIED:
                    mdir = applied_dir
                elif self.patch_data.metadata[patch_id]["repostate"] == constants.COMMITTED:
                    msg = "%s is committed. Metadata not updated" % patch_id
                    LOG.info(msg)
                    msg_info += msg + "\n"
                    continue
                else:
                    mdir = avail_dir

                try:
                    thispatch = PatchFile.extract_patch(patch,
                                                        metadata_dir=mdir,
                                                        metadata_only=True,
                                                        existing_content=self.patch_data.contents[patch_id],
                                                        allpatches=self.patch_data,
                                                        base_pkgdata=self.base_pkgdata)
                    self.patch_data.update_patch(thispatch)
                    msg = "%s is already imported. Updated metadata only" % patch_id
                    LOG.info(msg)
                    msg_info += msg + "\n"
                except PatchMismatchFailure:
                    msg = "Contents of %s do not match re-imported patch" % patch_id
                    LOG.exception(msg)
                    msg_error += msg + "\n"
                    continue
                except PatchValidationFailure as e:
                    msg = "Patch validation failed for %s" % patch_id
                    if e.message is not None and e.message != '':
                        msg += ":\n%s" % e.message
                    LOG.exception(msg)
                    msg_error += msg + "\n"
                    continue
                except PatchFail:
                    msg = "Failed to import patch %s" % patch_id
                    LOG.exception(msg)
                    msg_error += msg + "\n"

                continue

            if ext != ".patch":
                msg = "File must end in .patch extension: %s" \
                      % os.path.basename(patch)
                LOG.exception(msg)
                msg_error += msg + "\n"
                continue

            repo_changed = True

            try:
                thispatch = PatchFile.extract_patch(patch,
                                                    metadata_dir=avail_dir,
                                                    allpatches=self.patch_data,
                                                    base_pkgdata=self.base_pkgdata)

                msg_info += "%s is now available\n" % patch_id
                self.patch_data.add_patch(patch_id, thispatch)

                self.patch_data.metadata[patch_id]["repostate"] = constants.AVAILABLE
                if len(self.hosts) > 0:
                    self.patch_data.metadata[patch_id]["patchstate"] = constants.AVAILABLE
                else:
                    self.patch_data.metadata[patch_id]["patchstate"] = constants.UNKNOWN
            except PatchValidationFailure as e:
                msg = "Patch validation failed for %s" % patch_id
                if e.message is not None and e.message != '':
                    msg += ":\n%s" % e.message
                LOG.exception(msg)
                msg_error += msg + "\n"
                continue
            except PatchFail:
                msg = "Failed to import patch %s" % patch_id
                LOG.exception(msg)
                msg_error += msg + "\n"
                continue

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def patch_apply_api(self, patch_ids):
        """
        Apply patches, moving patches from available to applied and updating repo
        :return:
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        # Protect against duplications
        patch_list = sorted(list(set(patch_ids)))

        msg = "Applying patches: %s" % ",".join(patch_list)
        LOG.info(msg)
        audit_log_info(msg)

        if "--all" in patch_list:
            # Set patch_ids to list of all available patches
            # We're getting this list now, before we load the applied patches
            patch_list = []
            for patch_id in sorted(self.patch_data.metadata.keys()):
                if self.patch_data.metadata[patch_id]["repostate"] == constants.AVAILABLE:
                    patch_list.append(patch_id)

            if len(patch_list) == 0:
                msg_info += "There are no available patches to be applied.\n"
                return dict(info=msg_info, warning=msg_warning, error=msg_error)

        repo_changed = False

        # First, verify that all specified patches exist
        id_verification = True
        for patch_id in patch_list:
            if patch_id not in self.patch_data.metadata:
                msg = "Patch %s does not exist" % patch_id
                LOG.error(msg)
                msg_error += msg + "\n"
                id_verification = False

        if not id_verification:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Next, check the patch dependencies
        # required_patches will map the required patch to the patches that need it
        required_patches = {}
        for patch_id in patch_list:
            for req_patch in self.patch_data.metadata[patch_id]["requires"]:
                # Ignore patches in the op set
                if req_patch in patch_list:
                    continue

                if req_patch not in required_patches:
                    required_patches[req_patch] = []

                required_patches[req_patch].append(patch_id)

        # Now verify the state of the required patches
        req_verification = True
        for req_patch, iter_patch_list in required_patches.iteritems():
            if req_patch not in self.patch_data.metadata \
                    or self.patch_data.metadata[req_patch]["repostate"] == constants.AVAILABLE:
                msg = "%s is required by: %s" % (req_patch, ", ".join(sorted(iter_patch_list)))
                msg_error += msg + "\n"
                LOG.info(msg)
                req_verification = False

        if not req_verification:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Start applying the patches
        for patch_id in patch_list:
            msg = "Applying patch: %s" % patch_id
            LOG.info(msg)
            audit_log_info(msg)

            if self.patch_data.metadata[patch_id]["repostate"] == constants.APPLIED \
               or self.patch_data.metadata[patch_id]["repostate"] == constants.COMMITTED:
                msg = "%s is already in the repo" % patch_id
                LOG.info(msg)
                msg_info += msg + "\n"
                continue

            # To allow for easy cleanup, we're going to first iterate
            # through the rpm list to determine where to copy the file.
            # As a second step, we'll go through the list and copy each file.
            # If there are problems querying any RPMs, none will be copied.
            rpmlist = {}
            for rpmname in self.patch_data.contents[patch_id]:
                patch_sw_version = self.patch_data.metadata[patch_id]["sw_version"]

                rpmfile = self.get_store_filename(patch_sw_version, rpmname)
                if not os.path.isfile(rpmfile):
                    msg = "Could not find rpm: %s" % rpmfile
                    LOG.error(msg)
                    raise RpmFail(msg)

                repo_filename = self.get_repo_filename(patch_sw_version, rpmname)
                if repo_filename is None:
                    msg = "Failed to determine repo path for %s" % rpmfile
                    LOG.exception(msg)
                    raise RpmFail(msg)

                repo_pkg_dir = os.path.dirname(repo_filename)
                if not os.path.exists(repo_pkg_dir):
                    os.makedirs(repo_pkg_dir)
                rpmlist[rpmfile] = repo_filename

            # Copy the RPMs. If a failure occurs, clean up copied files.
            copied = []
            for rpmfile in rpmlist:
                LOG.info("Copy %s to %s" % (rpmfile, rpmlist[rpmfile]))
                try:
                    shutil.copy(rpmfile, rpmlist[rpmfile])
                    copied.append(rpmlist[rpmfile])
                except IOError:
                    msg = "Failed to copy %s" % rpmfile
                    LOG.exception(msg)
                    # Clean up files
                    for filename in copied:
                        LOG.info("Cleaning up %s" % filename)
                        os.remove(filename)

                    raise RpmFail(msg)

            try:
                # Move the metadata to the applied dir
                shutil.move("%s/%s-metadata.xml" % (avail_dir, patch_id),
                            "%s/%s-metadata.xml" % (applied_dir, patch_id))

                msg_info += "%s is now in the repo\n" % patch_id
            except shutil.Error:
                msg = "Failed to move the metadata for %s" % patch_id
                LOG.exception(msg)
                raise MetadataFail(msg)

            self.patch_data.metadata[patch_id]["repostate"] = constants.APPLIED
            if len(self.hosts) > 0:
                self.patch_data.metadata[patch_id]["patchstate"] = constants.PARTIAL_APPLY
            else:
                self.patch_data.metadata[patch_id]["patchstate"] = constants.UNKNOWN

            self.hosts_lock.acquire()
            self.interim_state[patch_id] = self.hosts.keys()
            self.hosts_lock.release()

            repo_changed = True

        if repo_changed:
            # Update the repo
            self.patch_data.gen_groups_xml()
            for ver, rdir in repo_dir.iteritems():
                try:
                    output = subprocess.check_output(["createrepo",
                                                      "--update",
                                                      "-g",
                                                      "comps.xml",
                                                      rdir],
                                                     stderr=subprocess.STDOUT)
                    LOG.info("Repo[%s] updated:\n%s" % (ver, output))
                except subprocess.CalledProcessError:
                    msg = "Failed to update the repo for %s" % ver
                    LOG.exception(msg)
                    raise PatchFail(msg)
        else:
            LOG.info("Repository is unchanged")

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def patch_remove_api(self, patch_ids, **kwargs):
        """
        Remove patches, moving patches from applied to available and updating repo
        :return:
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""
        remove_unremovable = False

        repo_changed = False

        # Protect against duplications
        patch_list = sorted(list(set(patch_ids)))

        msg = "Removing patches: %s" % ",".join(patch_list)
        LOG.info(msg)
        audit_log_info(msg)

        if kwargs.get("removeunremovable") == "yes":
            remove_unremovable = True

        # First, verify that all specified patches exist
        id_verification = True
        for patch_id in patch_list:
            if patch_id not in self.patch_data.metadata:
                msg = "Patch %s does not exist" % patch_id
                LOG.error(msg)
                msg_error += msg + "\n"
                id_verification = False

        if not id_verification:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # See if any of the patches are marked as unremovable
        unremovable_verification = True
        for patch_id in patch_list:
            if self.patch_data.metadata[patch_id].get("unremovable") == "Y":
                if remove_unremovable:
                    msg = "Unremovable patch %s being removed" % patch_id
                    LOG.warning(msg)
                    msg_warning += msg + "\n"
                else:
                    msg = "Patch %s is not removable" % patch_id
                    LOG.error(msg)
                    msg_error += msg + "\n"
                    unremovable_verification = False
            elif self.patch_data.metadata[patch_id]['repostate'] == constants.COMMITTED:
                msg = "Patch %s is committed and cannot be removed" % patch_id
                LOG.error(msg)
                msg_error += msg + "\n"
                unremovable_verification = False

        if not unremovable_verification:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Next, see if any of the patches are required by applied patches
        # required_patches will map the required patch to the patches that need it
        required_patches = {}
        for patch_iter in self.patch_data.metadata.keys():
            # Ignore patches in the op set
            if patch_iter in patch_list:
                continue

            # Only check applied patches
            if self.patch_data.metadata[patch_iter]["repostate"] == constants.AVAILABLE:
                continue

            for req_patch in self.patch_data.metadata[patch_iter]["requires"]:
                if req_patch not in patch_list:
                    continue

                if req_patch not in required_patches:
                    required_patches[req_patch] = []

                required_patches[req_patch].append(patch_iter)

        if len(required_patches) > 0:
            for req_patch, iter_patch_list in required_patches.iteritems():
                msg = "%s is required by: %s" % (req_patch, ", ".join(sorted(iter_patch_list)))
                msg_error += msg + "\n"
                LOG.info(msg)

            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        for patch_id in patch_list:
            msg = "Removing patch: %s" % patch_id
            LOG.info(msg)
            audit_log_info(msg)

            if self.patch_data.metadata[patch_id]["repostate"] == constants.AVAILABLE:
                msg = "%s is not in the repo" % patch_id
                LOG.info(msg)
                msg_info += msg + "\n"
                continue

            repo_changed = True

            for rpmname in self.patch_data.contents[patch_id]:
                patch_sw_version = self.patch_data.metadata[patch_id]["sw_version"]
                rpmfile = self.get_store_filename(patch_sw_version, rpmname)
                if not os.path.isfile(rpmfile):
                    msg = "Could not find rpm: %s" % rpmfile
                    LOG.error(msg)
                    raise RpmFail(msg)

                repo_filename = self.get_repo_filename(patch_sw_version, rpmname)
                if repo_filename is None:
                    msg = "Failed to determine repo path for %s" % rpmfile
                    LOG.exception(msg)
                    raise RpmFail(msg)

                try:
                    os.remove(repo_filename)
                except OSError:
                    msg = "Failed to remove RPM"
                    LOG.exception(msg)
                    raise RpmFail(msg)

            try:
                # Move the metadata to the available dir
                shutil.move("%s/%s-metadata.xml" % (applied_dir, patch_id),
                            "%s/%s-metadata.xml" % (avail_dir, patch_id))
                msg_info += "%s has been removed from the repo\n" % patch_id
            except shutil.Error:
                msg = "Failed to move the metadata for %s" % patch_id
                LOG.exception(msg)
                raise MetadataFail(msg)

            self.patch_data.metadata[patch_id]["repostate"] = constants.AVAILABLE
            if len(self.hosts) > 0:
                self.patch_data.metadata[patch_id]["patchstate"] = constants.PARTIAL_REMOVE
            else:
                self.patch_data.metadata[patch_id]["patchstate"] = constants.UNKNOWN

            self.hosts_lock.acquire()
            self.interim_state[patch_id] = self.hosts.keys()
            self.hosts_lock.release()

        if repo_changed:
            # Update the repo
            self.patch_data.gen_groups_xml()
            for ver, rdir in repo_dir.iteritems():
                try:
                    output = subprocess.check_output(["createrepo",
                                                      "--update",
                                                      "-g",
                                                      "comps.xml",
                                                      rdir],
                                                     stderr=subprocess.STDOUT)
                    LOG.info("Repo[%s] updated:\n%s" % (ver, output))
                except subprocess.CalledProcessError:
                    msg = "Failed to update the repo for %s" % ver
                    LOG.exception(msg)
                    raise PatchFail(msg)
        else:
            LOG.info("Repository is unchanged")

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def patch_delete_api(self, patch_ids):
        """
        Delete patches
        :return:
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        # Protect against duplications
        patch_list = sorted(list(set(patch_ids)))

        msg = "Deleting patches: %s" % ",".join(patch_list)
        LOG.info(msg)
        audit_log_info(msg)

        # Verify patches exist and are in proper state first
        id_verification = True
        for patch_id in patch_list:
            if patch_id not in self.patch_data.metadata:
                msg = "Patch %s does not exist" % patch_id
                LOG.error(msg)
                msg_error += msg + "\n"
                id_verification = False
                continue

            # Get the aggregated patch state, if possible
            patchstate = constants.UNKNOWN
            if patch_id in self.patch_data.metadata:
                patchstate = self.patch_data.metadata[patch_id]["patchstate"]

            if self.patch_data.metadata[patch_id]["repostate"] != constants.AVAILABLE or \
                    (patchstate != constants.AVAILABLE and patchstate != constants.UNKNOWN):
                msg = "Patch %s not in Available state" % patch_id
                LOG.error(msg)
                msg_error += msg + "\n"
                id_verification = False
                continue

        if not id_verification:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Handle operation
        for patch_id in patch_list:
            for rpmname in self.patch_data.contents[patch_id]:
                patch_sw_version = self.patch_data.metadata[patch_id]["sw_version"]
                rpmfile = self.get_store_filename(patch_sw_version, rpmname)
                if not os.path.isfile(rpmfile):
                    # We're deleting the patch anyway, so the missing file
                    # doesn't really matter
                    continue

                try:
                    os.remove(rpmfile)
                except OSError:
                    msg = "Failed to remove RPM %s" % rpmfile
                    LOG.exception(msg)
                    raise RpmFail(msg)

            try:
                # Delete the metadata
                os.remove("%s/%s-metadata.xml" % (avail_dir, patch_id))
            except OSError:
                msg = "Failed to remove metadata for %s" % patch_id
                LOG.exception(msg)
                raise MetadataFail(msg)

            self.patch_data.delete_patch(patch_id)
            msg = "%s has been deleted" % patch_id
            LOG.info(msg)
            msg_info += msg + "\n"

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def patch_init_release_api(self, release):
        """
        Create an empty repo for a new release
        :return:
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        msg = "Initializing repo for: %s" % release
        LOG.info(msg)
        audit_log_info(msg)

        if release == SW_VERSION:
            msg = "Rejected: Requested release %s is running release" % release
            msg_error += msg + "\n"
            LOG.info(msg)
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Refresh data
        self.base_pkgdata.loaddirs()

        self.patch_data.load_all_metadata(avail_dir, repostate=constants.AVAILABLE)
        self.patch_data.load_all_metadata(applied_dir, repostate=constants.APPLIED)
        self.patch_data.load_all_metadata(committed_dir, repostate=constants.COMMITTED)

        repo_dir[release] = "%s/rel-%s" % (repo_root_dir, release)

        # Verify the release doesn't already exist
        if os.path.exists(repo_dir[release]):
            msg = "Patch repository for %s already exists" % release
            msg_info += msg + "\n"
            LOG.info(msg)
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Generate the groups xml
        self.patch_data.gen_release_groups_xml(release)

        # Create the repo
        try:
            output = subprocess.check_output(["createrepo",
                                              "--update",
                                              "-g",
                                              "comps.xml",
                                              repo_dir[release]],
                                             stderr=subprocess.STDOUT)
            LOG.info("Repo[%s] updated:\n%s" % (release, output))
        except subprocess.CalledProcessError:
            msg = "Failed to update the repo for %s" % release
            LOG.exception(msg)

            # Wipe out what was created
            shutil.rmtree(repo_dir[release])
            del repo_dir[release]

            raise PatchFail(msg)

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def patch_del_release_api(self, release):
        """
        Delete the repo and patches for second release
        :return:
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        msg = "Deleting repo and patches for: %s" % release
        LOG.info(msg)
        audit_log_info(msg)

        if release == SW_VERSION:
            msg = "Rejected: Requested release %s is running release" % release
            msg_error += msg + "\n"
            LOG.info(msg)
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Delete patch XML files
        for patch_id in self.patch_data.metadata.keys():
            if self.patch_data.metadata[patch_id]["sw_version"] != release:
                continue

            if self.patch_data.metadata[patch_id]["repostate"] == constants.APPLIED:
                mdir = applied_dir
            elif self.patch_data.metadata[patch_id]["repostate"] == constants.COMMITTED:
                mdir = committed_dir
            else:
                mdir = avail_dir

            try:
                # Delete the metadata
                os.remove("%s/%s-metadata.xml" % (mdir, patch_id))
            except OSError:
                msg = "Failed to remove metadata for %s" % patch_id
                LOG.exception(msg)

                # Refresh patch data
                self.patch_data = PatchData()
                self.patch_data.load_all_metadata(avail_dir, repostate=constants.AVAILABLE)
                self.patch_data.load_all_metadata(applied_dir, repostate=constants.APPLIED)
                self.patch_data.load_all_metadata(committed_dir, repostate=constants.COMMITTED)

                raise MetadataFail(msg)

        # Delete the packages dir
        package_dir[release] = "%s/%s" % (root_package_dir, release)
        if os.path.exists(package_dir[release]):
            try:
                shutil.rmtree(package_dir[release])
            except shutil.Error:
                msg = "Failed to delete package dir for %s" % release
                LOG.exception(msg)

        del package_dir[release]

        # Verify the release exists
        repo_dir[release] = "%s/rel-%s" % (repo_root_dir, release)
        if not os.path.exists(repo_dir[release]):
            # Nothing to do
            msg = "Patch repository for %s does not exist" % release
            msg_info += msg + "\n"
            LOG.info(msg)
            del repo_dir[release]

            # Refresh patch data
            self.patch_data = PatchData()
            self.patch_data.load_all_metadata(avail_dir, repostate=constants.AVAILABLE)
            self.patch_data.load_all_metadata(applied_dir, repostate=constants.APPLIED)
            self.patch_data.load_all_metadata(committed_dir, repostate=constants.COMMITTED)

            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Delete the repo
        try:
            shutil.rmtree(repo_dir[release])
        except shutil.Error:
            msg = "Failed to delete repo for %s" % release
            LOG.exception(msg)

        del repo_dir[release]

        if self.base_pkgdata is not None:
            del self.base_pkgdata.pkgs[release]

        # Refresh patch data
        self.patch_data = PatchData()
        self.patch_data.load_all_metadata(avail_dir, repostate=constants.AVAILABLE)
        self.patch_data.load_all_metadata(applied_dir, repostate=constants.APPLIED)
        self.patch_data.load_all_metadata(committed_dir, repostate=constants.COMMITTED)

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def patch_query_what_requires(self, patch_ids):
        """
        Query the known patches to see which have dependencies on the specified patches
        :return:
        """
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        msg = "Querying what requires patches: %s" % ",".join(patch_ids)
        LOG.info(msg)
        audit_log_info(msg)

        # First, verify that all specified patches exist
        id_verification = True
        for patch_id in patch_ids:
            if patch_id not in self.patch_data.metadata:
                msg = "Patch %s does not exist" % patch_id
                LOG.error(msg)
                msg_error += msg + "\n"
                id_verification = False

        if not id_verification:
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        required_patches = {}
        for patch_iter in self.patch_data.metadata.keys():
            for req_patch in self.patch_data.metadata[patch_iter]["requires"]:
                if req_patch not in patch_ids:
                    continue

                if req_patch not in required_patches:
                    required_patches[req_patch] = []

                required_patches[req_patch].append(patch_iter)

        for patch_id in patch_ids:
            if patch_id in required_patches:
                iter_patch_list = required_patches[patch_id]
                msg_info += "%s is required by: %s\n" % (patch_id, ", ".join(sorted(iter_patch_list)))
            else:
                msg_info += "%s is not required by any patches.\n" % patch_id

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def patch_sync(self):
        # Increment the patch_op_counter here
        self.inc_patch_op_counter()

        self.patch_data_lock.acquire()
        #self.patch_data.load_all()
        self.check_patch_states()
        self.patch_data_lock.release()

        if self.sock_out is None:
            return True

        # Send the sync requests

        self.controller_neighbours_lock.acquire()
        for n in self.controller_neighbours:
            self.controller_neighbours[n].clear_synced()
        self.controller_neighbours_lock.release()

        msg = PatchMessageSyncReq()
        self.socket_lock.acquire()
        msg.send(self.sock_out)
        self.socket_lock.release()

        # Now we wait, up to two mins... TODO: Wait on a condition
        my_ip = cfg.get_mgmt_ip()
        sync_rc = False
        max_time = time.time() + 120
        while time.time() < max_time:
            all_done = True
            self.controller_neighbours_lock.acquire()
            for n in self.controller_neighbours:
                if n != my_ip and not self.controller_neighbours[n].get_synced():
                    all_done = False
            self.controller_neighbours_lock.release()

            if all_done:
                LOG.info("Sync complete")
                sync_rc = True
                break

            time.sleep(0.5)

        # Send hellos to the hosts now, to get queries performed
        hello_agent = PatchMessageHelloAgent()
        self.socket_lock.acquire()
        hello_agent.send(self.sock_out)
        self.socket_lock.release()

        if not sync_rc:
            LOG.info("Timed out waiting for sync completion")
        return sync_rc

    def patch_query_cached(self, **kwargs):
        query_state = None
        if "show" in kwargs:
            if kwargs["show"] == "available":
                query_state = constants.AVAILABLE
            elif kwargs["show"] == "applied":
                query_state = constants.APPLIED
            elif kwargs["show"] == "committed":
                query_state = constants.COMMITTED

        query_release = None
        if "release" in kwargs:
            query_release = kwargs["release"]

        results = {}
        self.patch_data_lock.acquire()
        if query_state is None and query_release is None:
            # Return everything
            results = self.patch_data.metadata
        else:
            # Filter results
            for patch_id, data in self.patch_data.metadata.iteritems():
                if query_state is not None and data["repostate"] != query_state:
                    continue
                if query_release is not None and data["sw_version"] != query_release:
                    continue
                results[patch_id] = data
        self.patch_data_lock.release()

        return results

    def patch_query_specific_cached(self, patch_ids):
        audit_log_info("Patch show")

        results = {"metadata": {},
                   "contents": {},
                   "error": ""}

        self.patch_data_lock.acquire()

        for patch_id in patch_ids:
            if patch_id not in self.patch_data.metadata.keys():
                results["error"] += "%s is unrecognized\n" % patch_id

        for patch_id, data in self.patch_data.metadata.iteritems():
            if patch_id in patch_ids:
                results["metadata"][patch_id] = data
        for patch_id, data in self.patch_data.contents.iteritems():
            if patch_id in patch_ids:
                results["contents"][patch_id] = data

        self.patch_data_lock.release()

        return results

    def get_dependencies(self, patch_ids, recursive):
        dependencies = set()
        patch_added = False

        self.patch_data_lock.acquire()

        # Add patches to workset
        for patch_id in sorted(patch_ids):
            dependencies.add(patch_id)
            patch_added = True

        while patch_added:
            patch_added = False
            for patch_id in sorted(dependencies):
                for req in self.patch_data.metadata[patch_id]["requires"]:
                    if req not in dependencies:
                        dependencies.add(req)
                        patch_added = recursive

        self.patch_data_lock.release()

        return sorted(dependencies)

    def patch_query_dependencies(self, patch_ids, **kwargs):
        msg = "Patch query-dependencies %s" % patch_ids
        LOG.info(msg)
        audit_log_info(msg)

        failure = False

        results = {"patches": [],
                   "error": ""}

        recursive = False
        if kwargs.get("recursive") == "yes":
            recursive = True

        self.patch_data_lock.acquire()

        # Verify patch IDs
        for patch_id in sorted(patch_ids):
            if patch_id not in self.patch_data.metadata.keys():
                errormsg = "%s is unrecognized\n" % patch_id
                LOG.info("patch_query_dependencies: %s" % errormsg)
                results["error"] += errormsg
                failure = True
        self.patch_data_lock.release()

        if failure:
            LOG.info("patch_query_dependencies failed")
            return results

        results["patches"] = self.get_dependencies(patch_ids, recursive)

        return results

    def patch_commit(self, patch_ids, dry_run=False):
        msg = "Patch commit %s" % patch_ids
        LOG.info(msg)
        audit_log_info(msg)

        try:
            if not os.path.exists(committed_dir):
                os.makedirs(committed_dir)
        except os.error:
            msg = "Failed to create %s" % committed_dir
            LOG.exception(msg)
            raise PatchFail(msg)

        release = None
        all = False
        patch_added = False
        failure = False
        recursive = True

        keep = {}
        cleanup = {}
        cleanup_files = set()

        results = {"info": "",
                   "error": ""}

        # Ensure there are only REL patches
        non_rel_list = []
        self.patch_data_lock.acquire()
        for patch_id in self.patch_data.metadata:
            if self.patch_data.metadata[patch_id]['status'] != constants.STATUS_RELEASED:
                non_rel_list.append(patch_id)
        self.patch_data_lock.release()

        if len(non_rel_list) > 0:
            errormsg = "A commit cannot be performed with non-REL status patches in the system:\n"
            for patch_id in non_rel_list:
                errormsg += "    %s\n" % patch_id
            LOG.info("patch_commit rejected: %s" % errormsg)
            results["error"] += errormsg
            return results

        # Verify patch IDs
        self.patch_data_lock.acquire()
        for patch_id in sorted(patch_ids):
            if patch_id not in self.patch_data.metadata.keys():
                errormsg = "%s is unrecognized\n" % patch_id
                LOG.info("patch_commit: %s" % errormsg)
                results["error"] += errormsg
                failure = True
        self.patch_data_lock.release()

        if failure:
            LOG.info("patch_commit: Failed patch ID check")
            return results

        commit_list = self.get_dependencies(patch_ids, recursive)

        # Check patch states
        avail_list = []
        self.patch_data_lock.acquire()
        for patch_id in commit_list:
            if self.patch_data.metadata[patch_id]['patchstate'] != constants.APPLIED \
                    and self.patch_data.metadata[patch_id]['patchstate'] != constants.COMMITTED:
                avail_list.append(patch_id)
        self.patch_data_lock.release()

        if len(avail_list) > 0:
            errormsg = "The following patches are not applied and cannot be committed:\n"
            for patch_id in avail_list:
                errormsg += "    %s\n" % patch_id
            LOG.info("patch_commit rejected: %s" % errormsg)
            results["error"] += errormsg
            return results

        # Get list of packages
        self.patch_data_lock.acquire()
        for patch_id in commit_list:
            patch_sw_version = self.patch_data.metadata[patch_id]["sw_version"]

            if patch_sw_version not in keep:
                keep[patch_sw_version] = {}
            if patch_sw_version not in cleanup:
                cleanup[patch_sw_version] = {}

            for rpmname in self.patch_data.contents[patch_id]:
                try:
                    pkgname, arch, pkgver = parse_rpm_filename(rpmname)
                except ValueError as e:
                    self.patch_data_lock.release()
                    raise e

                if pkgname not in keep[patch_sw_version]:
                    keep[patch_sw_version][pkgname] = { arch: pkgver }
                    continue
                elif arch not in keep[patch_sw_version][pkgname]:
                    keep[patch_sw_version][pkgname][arch] = pkgver
                    continue

                # Compare versions
                keep_pkgver = keep[patch_sw_version][pkgname][arch]
                if pkgver > keep_pkgver:
                    if pkgname not in cleanup[patch_sw_version]:
                        cleanup[patch_sw_version][pkgname] = { arch: [ keep_pkgver ] }
                    elif arch not in cleanup[patch_sw_version][pkgname]:
                        cleanup[patch_sw_version][pkgname][arch] = [ keep_pkgver ]
                    else:
                        cleanup[patch_sw_version][pkgname][arch].append(keep_pkgver)

                    # Find the rpmname
                    keep_rpmname = keep_pkgver.generate_rpm_filename(pkgname, arch)

                    store_filename = self.get_store_filename(patch_sw_version, keep_rpmname)
                    if store_filename is not None and os.path.exists(store_filename):
                        cleanup_files.add(store_filename)

                    repo_filename = self.get_repo_filename(patch_sw_version, keep_rpmname)
                    if repo_filename is not None and os.path.exists(repo_filename):
                        cleanup_files.add(repo_filename)

                    # Keep the new pkgver
                    keep[patch_sw_version][pkgname][arch] = pkgver
                else:
                    # Put this pkg in the cleanup list
                    if pkgname not in cleanup[patch_sw_version]:
                        cleanup[patch_sw_version][pkgname] = { arch: [ pkgver ] }
                    elif arch not in cleanup[patch_sw_version][pkgname]:
                        cleanup[patch_sw_version][pkgname][arch] = [ pkgver ]
                    else:
                        cleanup[patch_sw_version][pkgname][arch].append(pkgver)

                    store_filename = self.get_store_filename(patch_sw_version, rpmname)
                    if store_filename is not None and os.path.exists(store_filename):
                        cleanup_files.add(store_filename)

                    repo_filename = self.get_repo_filename(patch_sw_version, rpmname)
                    if repo_filename is not None and os.path.exists(repo_filename):
                        cleanup_files.add(repo_filename)

        self.patch_data_lock.release()

        # Calculate disk space
        disk_space = 0
        for rpmfile in cleanup_files:
            statinfo = os.stat(rpmfile)
            disk_space += statinfo.st_size

        if dry_run:
            results["info"] = "This commit operation would free %0.2f MiB" % (disk_space/(1024.0*1024.0))
            return results

        # Do the commit

        # Move the metadata to the committed dir
        for patch_id in commit_list:
            metadata_fname = "%s-metadata.xml" % patch_id
            applied_fname = os.path.join(applied_dir, metadata_fname)
            committed_fname = os.path.join(committed_dir, metadata_fname)
            if os.path.exists(applied_fname):
                try:
                    shutil.move(applied_fname, committed_fname)
                except shutil.Error:
                    msg = "Failed to move the metadata for %s" % patch_id
                    LOG.exception(msg)
                    raise MetadataFail(msg)

        # Delete the files
        for rpmfile in cleanup_files:
            try:
                os.remove(rpmfile)
            except OSError:
                msg = "Failed to remove: %s" % rpmfile
                LOG.exception(msg)
                raise MetadataFail(msg)

        # Update the repo
        self.patch_data.gen_groups_xml()
        for ver, rdir in repo_dir.iteritems():
            try:
                output = subprocess.check_output(["createrepo",
                                                  "--update",
                                                  "-g",
                                                  "comps.xml",
                                                  rdir],
                                                 stderr=subprocess.STDOUT)
                LOG.info("Repo[%s] updated:\n%s" % (ver, output))
            except subprocess.CalledProcessError:
                msg = "Failed to update the repo for %s" % ver
                LOG.exception(msg)
                raise PatchFail(msg)

        self.patch_data.load_all()

        results["info"] = "The patches have been committed."
        return results

    def query_host_cache(self):
        output = []

        self.hosts_lock.acquire()
        for nbr in self.hosts.keys():
            host = self.hosts[nbr].get_dict()
            host["interim_state"] = False
            for patch_id in pc.interim_state.keys():
                if nbr in pc.interim_state[patch_id]:
                    host["interim_state"] = True

            output.append(host)

        self.hosts_lock.release()

        return output

    def any_patch_host_installing(self):
        rc = False

        self.hosts_lock.acquire()
        for ip, host in self.hosts.iteritems():
            if host.state == constants.PATCH_AGENT_STATE_INSTALLING:
                rc = True
                break

        self.hosts_lock.release()

        return rc

    def patch_host_install(self, host_ip, force, async=False):
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        ip = host_ip

        self.hosts_lock.acquire()
        # If not in hosts table, maybe a hostname was used instead
        if host_ip not in self.hosts:
            try:
                ip = utils.gethostbyname(host_ip)
                if ip not in self.hosts:
                    # Translated successfully, but IP isn't in the table.
                    # Raise an exception to drop out to the failure handling
                    raise
            except:
                self.hosts_lock.release()
                msg = "Unknown host specified: %s" % host_ip
                msg_error += msg + "\n"
                LOG.error("Error in host-install: " + msg)
                return dict(info=msg_info, warning=msg_warning, error=msg_error)

        msg = "Running host-install for %s (%s), force=%s, async=%s" % (host_ip, ip, force, async)
        LOG.info(msg)
        audit_log_info(msg)

        if self.allow_insvc_patching:
            LOG.info("Allowing in-service patching")
            force = True

        self.hosts[ip].install_pending = True
        self.hosts[ip].install_status = False
        self.hosts[ip].install_reject_reason = None
        self.hosts_lock.release()

        installreq = PatchMessageAgentInstallReq()
        installreq.ip = ip
        installreq.force = force
        installreq.encode()
        self.socket_lock.acquire()
        installreq.send(self.sock_out)
        self.socket_lock.release()

        if async:
            # async install requested, so return now
            msg = "Patch installation request sent to %s." % self.hosts[ip].hostname
            msg_info += msg + "\n"
            LOG.info("host-install async: " + msg)
            return dict(info=msg_info, warning=msg_warning, error=msg_error)

        # Now we wait, up to ten mins... TODO: Wait on a condition
        resp_rx = False
        max_time = time.time() + 600
        while time.time() < max_time:
            self.hosts_lock.acquire()
            if ip not in self.hosts:
                # The host aged out while we were waiting
                self.hosts_lock.release()
                msg = "Agent expired while waiting: %s" % ip
                msg_error += msg + "\n"
                LOG.error("Error in host-install: " + msg)
                break

            if not self.hosts[ip].install_pending:
                # We got a response
                resp_rx = True
                if self.hosts[ip].install_status:
                    msg = "Patch installation was successful on %s." % self.hosts[ip].hostname
                    msg_info += msg + "\n"
                    LOG.info("host-install: " + msg)
                elif self.hosts[ip].install_reject_reason:
                    msg = "Patch installation rejected by %s. %s" % (
                        self.hosts[ip].hostname,
                        self.hosts[ip].install_reject_reason)
                    msg_error += msg + "\n"
                    LOG.error("Error in host-install: " + msg)
                else:
                    msg = "Patch installation failed on %s." % self.hosts[ip].hostname
                    msg_error += msg + "\n"
                    LOG.error("Error in host-install: " + msg)

                self.hosts_lock.release()
                break

            self.hosts_lock.release()

            time.sleep(0.5)

        if not resp_rx:
            msg = "Timeout occurred while waiting response from %s." % ip
            msg_error += msg + "\n"
            LOG.error("Error in host-install: " + msg)

        return dict(info=msg_info, warning=msg_warning, error=msg_error)

    def drop_host(self, host_ip, sync_nbr=True):
        msg_info = ""
        msg_warning = ""
        msg_error = ""

        ip = host_ip

        self.hosts_lock.acquire()
        # If not in hosts table, maybe a hostname was used instead
        if host_ip not in self.hosts:
            try:
                # Because the host may be getting dropped due to deletion,
                # we may be unable to do a hostname lookup. Instead, we'll
                # iterate through the table here.
                for host in self.hosts.keys():
                    if host_ip == self.hosts[host].hostname:
                        ip = host
                        break

                if ip not in self.hosts:
                    # Translated successfully, but IP isn't in the table.
                    # Raise an exception to drop out to the failure handling
                    raise
            except:
                self.hosts_lock.release()
                msg = "Unknown host specified: %s" % host_ip
                msg_error += msg + "\n"
                LOG.error("Error in drop-host: " + msg)
                return dict(info=msg_info, warning=msg_warning, error=msg_error)

        msg = "Running drop-host for %s (%s)" % (host_ip, ip)
        LOG.info(msg)
        audit_log_info(msg)

        del self.hosts[ip]
        for patch_id in self.interim_state.keys():
            if ip in self.interim_state[patch_id]:
                self.interim_state[patch_id].remove(ip)

        self.hosts_lock.release()

        if sync_nbr:
            sync_msg = PatchMessageDropHostReq()
            sync_msg.ip = ip
            self.socket_lock.acquire()
            sync_msg.send(self.sock_out)
            self.socket_lock.release()

        return dict(info=msg_info, warning=msg_warning, error=msg_error)


# The wsgiref.simple_server module has an error handler that catches
# and prints any exceptions that occur during the API handling to stderr.
# This means the patching sys.excepthook handler that logs uncaught
# exceptions is never called, and those exceptions are lost.
#
# To get around this, we're subclassing the simple_server.ServerHandler
# in order to replace the handle_error method with a custom one that
# logs the exception instead, and will set a global flag to shutdown
# the server and reset.
#
class MyServerHandler(simple_server.ServerHandler):
    def handle_error(self):
        LOG.exception('An uncaught exception has occurred:')
        if not self.headers_sent:
            self.result = self.error_output(self.environ, self.start_response)
            self.finish_response()
        global keep_running
        keep_running = False


def get_handler_cls():
    cls = simple_server.WSGIRequestHandler

    # old-style class doesn't support super
    class MyHandler(cls, object):
        def address_string(self):
            # In the future, we could provide a config option to allow reverse DNS lookup
            return self.client_address[0]

        # Overload the handle function to use our own MyServerHandler
        def handle(self):
            """Handle a single HTTP request"""

            self.raw_requestline = self.rfile.readline()
            if not self.parse_request():  # An error code has been sent, just exit
                return

            handler = MyServerHandler(
                self.rfile, self.wfile, self.get_stderr(), self.get_environ()
            )
            handler.request_handler = self  # backpointer for logging
            handler.run(self.server.get_app())

    return MyHandler


class PatchControllerApiThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.wsgi = None

    def run(self):
        host = "127.0.0.1"
        port = cfg.api_port

        try:
            # In order to support IPv6, server_class.address_family must be
            # set to the correct address family.  Because the unauthenticated
            # API always uses IPv4 for the loopback address, the address_family
            # variable cannot be set directly in the WSGIServer class, so a
            # local subclass needs to be created for the call to make_server,
            # where the correct address_family can be specified.
            class server_class(simple_server.WSGIServer):
                pass

            server_class.address_family = socket.AF_INET
            self.wsgi = simple_server.make_server(
                host, port,
                app.VersionSelectorApplication(),
                server_class=server_class,
                handler_class=get_handler_cls())

            self.wsgi.socket.settimeout(api_socket_timeout)
            global keep_running
            while keep_running:
                self.wsgi.handle_request()
        except:
            # Log all exceptions
            LOG.exception("Error occurred during request processing")

        global thread_death
        thread_death.set()

    def kill(self):
        # Must run from other thread
        if self.wsgi is not None:
            self.wsgi.shutdown()


class PatchControllerAuthApiThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        # LOG.info ("Initializing Authenticated API thread")
        self.wsgi = None

    def run(self):
        host = CONF.auth_api_bind_ip
        port = CONF.auth_api_port
        if host is None:
            host = utils.get_versioned_address_all()
        try:
            # Can only launch authenticated server post-config
            while not os.path.exists('/etc/platform/.initial_config_complete'):
                time.sleep(5)

            # In order to support IPv6, server_class.address_family must be
            # set to the correct address family.  Because the unauthenticated
            # API always uses IPv4 for the loopback address, the address_family
            # variable cannot be set directly in the WSGIServer class, so a
            # local subclass needs to be created for the call to make_server,
            # where the correct address_family can be specified.
            class server_class(simple_server.WSGIServer):
                pass

            server_class.address_family = utils.get_management_family()
            self.wsgi = simple_server.make_server(
                host, port,
                auth_app.VersionSelectorApplication(),
                server_class=server_class,
                handler_class=get_handler_cls())

            # self.wsgi.serve_forever()
            self.wsgi.socket.settimeout(api_socket_timeout)

            global keep_running
            while keep_running:
                self.wsgi.handle_request()
        except:
            # Log all exceptions
            LOG.exception("Authorized API failure: Error occurred during request processing")

    def kill(self):
        # Must run from other thread
        if self.wsgi is not None:
            self.wsgi.shutdown()


class PatchControllerMainThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        # LOG.info ("Initializing Main thread")

    def run(self):
        global pc
        global thread_death

        # LOG.info ("In Main thread")

        try:
            sock_in = pc.setup_socket()

            while sock_in is None:
                # Check every thirty seconds?
                # Once we've got a conf file, tied into packstack,
                # we'll get restarted when the file is updated,
                # and this should be unnecessary.
                time.sleep(30)
                sock_in = pc.setup_socket()

            # Ok, now we've got our socket. Let's start with a hello!
            pc.socket_lock.acquire()

            hello = PatchMessageHello()
            hello.send(pc.sock_out)

            hello_agent = PatchMessageHelloAgent()
            hello_agent.send(pc.sock_out)

            pc.socket_lock.release()

            # Send hello every thirty seconds
            hello_timeout = time.time() + 30.0
            remaining = 30

            agent_query_conns = []

            while True:
                # Check to see if any other thread has died
                if thread_death.is_set():
                    LOG.info("Detected thread death. Terminating")
                    return

                # Check for in-service patch restart flag
                if os.path.exists(insvc_patch_restart_controller):
                    LOG.info("In-service patch restart flag detected. Exiting.")
                    global keep_running
                    keep_running = False
                    os.remove(insvc_patch_restart_controller)
                    return

                inputs = [pc.sock_in] + agent_query_conns
                outputs = []

                # LOG.info("Running select, remaining=%d" % remaining)
                rlist, wlist, xlist = select.select(inputs, outputs, inputs, remaining)

                if (len(rlist) == 0 and
                        len(wlist) == 0 and
                        len(xlist) == 0):
                    # Timeout hit
                    pc.audit_socket()

                # LOG.info("Checking sockets")
                for s in rlist:
                    data = ''
                    addr = None
                    msg = None

                    if s == pc.sock_in:
                        # Receive from UDP
                        pc.socket_lock.acquire()
                        data, addr = s.recvfrom(1024)
                        pc.socket_lock.release()
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
                                LOG.info('End of TCP message received')
                                break

                        if data == '':
                            # Connection dropped
                            agent_query_conns.remove(s)
                            s.close()
                            continue

                        # Get the TCP endpoint address
                        addr = s.getpeername()

                    msgdata = json.loads(data)

                    # For now, discard any messages that are not msgversion==1
                    if 'msgversion' in msgdata and msgdata['msgversion'] != 1:
                        continue

                    if 'msgtype' in msgdata:
                        if msgdata['msgtype'] == messages.PATCHMSG_HELLO:
                            msg = PatchMessageHello()
                        elif msgdata['msgtype'] == messages.PATCHMSG_HELLO_ACK:
                            msg = PatchMessageHelloAck()
                        elif msgdata['msgtype'] == messages.PATCHMSG_SYNC_REQ:
                            msg = PatchMessageSyncReq()
                        elif msgdata['msgtype'] == messages.PATCHMSG_SYNC_COMPLETE:
                            msg = PatchMessageSyncComplete()
                        elif msgdata['msgtype'] == messages.PATCHMSG_HELLO_AGENT_ACK:
                            msg = PatchMessageHelloAgentAck()
                        elif msgdata['msgtype'] == messages.PATCHMSG_QUERY_DETAILED_RESP:
                            msg = PatchMessageQueryDetailedResp()
                        elif msgdata['msgtype'] == messages.PATCHMSG_AGENT_INSTALL_RESP:
                            msg = PatchMessageAgentInstallResp()
                        elif msgdata['msgtype'] == messages.PATCHMSG_DROP_HOST_REQ:
                            msg = PatchMessageDropHostReq()

                    if msg is None:
                        msg = messages.PatchMessage()

                    msg.decode(msgdata)
                    if s == pc.sock_in:
                        msg.handle(pc.sock_out, addr)
                    else:
                        msg.handle(s, addr)

                    # We can drop the connection after a query response
                    if msg.msgtype == messages.PATCHMSG_QUERY_DETAILED_RESP and s != pc.sock_in:
                        agent_query_conns.remove(s)
                        s.shutdown(socket.SHUT_RDWR)
                        s.close()

                while len(stale_hosts) > 0 and len(agent_query_conns) <= 5:
                    ip = stale_hosts.pop()
                    try:
                        agent_sock = socket.create_connection((ip, cfg.agent_port))
                        query = PatchMessageQueryDetailed()
                        query.send(agent_sock)
                        agent_query_conns.append(agent_sock)
                    except:
                        # Put it back on the list
                        stale_hosts.append(ip)

                remaining = int(hello_timeout - time.time())
                if remaining <= 0 or remaining > 30:
                    hello_timeout = time.time() + 30.0
                    remaining = 30

                    pc.socket_lock.acquire()

                    hello = PatchMessageHello()
                    hello.send(pc.sock_out)

                    hello_agent = PatchMessageHelloAgent()
                    hello_agent.send(pc.sock_out)

                    pc.socket_lock.release()

                    # Age out neighbours
                    pc.controller_neighbours_lock.acquire()
                    nbrs = pc.controller_neighbours.keys()
                    for n in nbrs:
                        # Age out controllers after 2 minutes
                        if pc.controller_neighbours[n].get_age() >= 120:
                            LOG.info("Aging out controller %s from table" % n)
                            del pc.controller_neighbours[n]
                    pc.controller_neighbours_lock.release()

                    pc.hosts_lock.acquire()
                    nbrs = pc.hosts.keys()
                    for n in nbrs:
                        # Age out hosts after 1 hour
                        if pc.hosts[n].get_age() >= 3600:
                            LOG.info("Aging out host %s from table" % n)
                            del pc.hosts[n]
                            for patch_id in pc.interim_state.keys():
                                if n in pc.interim_state[patch_id]:
                                    pc.interim_state[patch_id].remove(n)

                    pc.hosts_lock.release()
        except:
            # Log all exceptions
            LOG.exception("Error occurred during request processing")
            thread_death.set()


def main():
    configure_logging()

    cfg.read_config()

    # daemon.pidlockfile.write_pid_to_pidfile(pidfile_path)

    global thread_death
    thread_death = threading.Event()

    # Set the TMPDIR environment variable to /scratch so that any modules
    # that create directories with tempfile will not use /tmp
    os.environ['TMPDIR'] = '/scratch'

    global pc
    pc = PatchController()

    LOG.info("launching")
    api_thread = PatchControllerApiThread()
    auth_api_thread = PatchControllerAuthApiThread()
    main_thread = PatchControllerMainThread()

    api_thread.start()
    auth_api_thread.start()
    main_thread.start()

    thread_death.wait()
    global keep_running
    keep_running = False

    api_thread.join()
    auth_api_thread.join()
    main_thread.join()
