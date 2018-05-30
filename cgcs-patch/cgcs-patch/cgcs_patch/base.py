"""
Copyright (c) 2017-2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import socket
import struct
import subprocess
import time

import cgcs_patch.utils as utils
import cgcs_patch.config as cfg
import cgcs_patch.constants as constants
from cgcs_patch.patch_functions import LOG


class PatchService:
    def __init__(self):
        self.sock_out = None
        self.sock_in = None
        self.service_type = None
        self.port = None
        self.mcast_addr = None
        self.socket_lock = None

    def update_config(self):
        # Implemented in subclass
        pass

    def socket_lock_acquire(self):
        pass

    def socket_lock_release(self):
        pass

    def setup_socket_ipv4(self):
        mgmt_ip = cfg.get_mgmt_ip()
        if mgmt_ip is None:
            # Don't setup socket unless we have a mgmt ip
            return None

        self.update_config()

        interface_addr = socket.inet_pton(socket.AF_INET, mgmt_ip)

        # Close sockets, if necessary
        for s in [self.sock_out, self.sock_in]:
            if s is not None:
                s.close()

        self.sock_out = socket.socket(socket.AF_INET,
                                      socket.SOCK_DGRAM)
        self.sock_in = socket.socket(socket.AF_INET,
                                     socket.SOCK_DGRAM)

        self.sock_out.setblocking(0)
        self.sock_in.setblocking(0)

        self.sock_out.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock_in.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.sock_out.bind((mgmt_ip, 0))
        self.sock_in.bind(('', self.port))

        # These options are for outgoing multicast messages
        self.sock_out.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, interface_addr)
        self.sock_out.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        # Since only the controllers are sending to this address,
        # we want the loopback so the local agent can receive it
        self.sock_out.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

        # Register the multicast group
        group = socket.inet_pton(socket.AF_INET, self.mcast_addr)
        mreq = struct.pack('=4s4s', group, interface_addr)

        self.sock_in.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        return self.sock_in

    def setup_socket_ipv6(self):
        mgmt_ip = cfg.get_mgmt_ip()
        if mgmt_ip is None:
            # Don't setup socket unless we have a mgmt ip
            return None

        self.update_config()

        # Close sockets, if necessary
        for s in [self.sock_out, self.sock_in]:
            if s is not None:
                s.close()

        self.sock_out = socket.socket(socket.AF_INET6,
                                      socket.SOCK_DGRAM)
        self.sock_in = socket.socket(socket.AF_INET6,
                                     socket.SOCK_DGRAM)

        self.sock_out.setblocking(0)
        self.sock_in.setblocking(0)

        self.sock_out.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock_in.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.sock_out.bind((mgmt_ip, 0))
        self.sock_in.bind(('', self.port))

        # These options are for outgoing multicast messages
        mgmt_ifindex = utils.if_nametoindex(cfg.get_mgmt_iface())
        self.sock_out.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, mgmt_ifindex)
        self.sock_out.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
        # Since only the controllers are sending to this address,
        # we want the loopback so the local agent can receive it
        self.sock_out.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 1)

        # Register the multicast group
        if_index_packed = struct.pack('I', mgmt_ifindex)
        group = socket.inet_pton(socket.AF_INET6, self.mcast_addr) + if_index_packed
        self.sock_in.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, group)

        return self.sock_in

    def setup_socket(self):
        self.socket_lock_acquire()

        try:
            sock_in = None
            if utils.get_management_version() == constants.ADDRESS_VERSION_IPV6:
                sock_in = self.setup_socket_ipv6()
            else:
                sock_in = self.setup_socket_ipv4()
            self.socket_lock_release()
            return sock_in
        except:
            LOG.exception("Failed to setup socket")

        # Close sockets, if necessary
        for s in [self.sock_out, self.sock_in]:
            if s is not None:
                s.close()

        self.socket_lock_release()

        return None

    def audit_socket(self):
        # Ensure multicast address is still allocated
        cmd = "ip maddr show %s | awk 'BEGIN { ORS=\"\" }; {if ($2 == \"%s\") print $2}'" % \
              (cfg.get_mgmt_iface(), self.mcast_addr)
        try:
            result = subprocess.check_output(cmd, shell=True)

            if result == self.mcast_addr:
                return
        except subprocess.CalledProcessError as e:
            LOG.error("Command output: %s" % e.output)
            return

        # Close the socket and set it up again
        LOG.info("Detected missing multicast addr (%s). Reconfiguring" % self.mcast_addr)
        while self.setup_socket() is None:
            LOG.info("Unable to setup sockets. Waiting to retry")
            time.sleep(5)
        LOG.info("Multicast address reconfigured")

