"""
Copyright (c) 2014 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

###################
# IMPORTS
###################
import logging
import time
import requests
import json

from daemon import runner # pylint: disable=no-name-in-module
from fm_api import fm_api
from fm_api import constants as fm_constants

import cgcs_patch.config as cfg
from cgcs_patch.patch_functions import configure_logging
from cgcs_patch.constants import ENABLE_DEV_CERTIFICATE_PATCH_IDENTIFIER

###################
# CONSTANTS
###################
LOG_FILE = '/var/log/patch-alarms.log'
PID_FILE = '/var/run/patch-alarm-manager.pid'


###################
# METHODS
###################
def start_polling():
    cfg.read_config()
    patch_alarm_daemon = PatchAlarmDaemon()
    alarm_runner = runner.DaemonRunner(patch_alarm_daemon)
    alarm_runner.daemon_context.umask = 0o022
    alarm_runner.do_action()


###################
# CLASSES
###################
class PatchAlarmDaemon():
    """ Daemon process representation of
        the patch monitoring program
    """
    def __init__(self):
        # Daemon-specific init
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/null'
        self.stderr_path = '/dev/null'
        self.pidfile_path = PID_FILE
        self.pidfile_timeout = 5

        self.api_addr = "127.0.0.1:%d" % cfg.api_port

        self.fm_api = fm_api.FaultAPIs()

    def run(self):
        configure_logging()

        requests_logger = logging.getLogger('requests')
        requests_logger.setLevel(logging.CRITICAL)

        while True:
            # start monitoring patch status
            self.check_patch_alarms()

            # run/poll every 1 min
            time.sleep(60)

    def check_patch_alarms(self):
        self._handle_patch_alarms()
        self._get_handle_failed_hosts()

    def _handle_patch_alarms(self):
        url = "http://%s/patch/query" % self.api_addr

        try:
            req = requests.get(url)
        except:
            return

        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST, "controller")

        raise_pip_alarm = False
        raise_obs_alarm = False
        raise_cert_alarm = False
        if req.status_code == 200:
            data = json.loads(req.text)

            if 'pd' in data:
                for patch_id, metadata in data['pd'].iteritems():
                    if 'patchstate' in metadata and \
                            (metadata['patchstate'] == 'Partial-Apply' or metadata['patchstate'] == 'Partial-Remove'):
                        raise_pip_alarm = True
                    if 'status' in metadata and \
                            (metadata['status'] == 'OBS' or metadata['status'] == 'Obsolete'):
                        raise_obs_alarm = True
                    # If there is a patch in the system (in any state) that is
                    # named some variation of "enable-dev-certificate", raise
                    # the 'developer certificate could allow for untrusted
                    # patches' alarm
                    if ENABLE_DEV_CERTIFICATE_PATCH_IDENTIFIER in patch_id:
                        raise_cert_alarm = True

        pip_alarm = self.fm_api.get_fault(fm_constants.FM_ALARM_ID_PATCH_IN_PROGRESS,
                                          entity_instance_id)
        if raise_pip_alarm and pip_alarm is None:
            logging.info("Raising patch-in-progress alarm")
            fault = fm_api.Fault(alarm_id=fm_constants.FM_ALARM_ID_PATCH_IN_PROGRESS,
                                 alarm_type=fm_constants.FM_ALARM_TYPE_5,
                                 alarm_state=fm_constants.FM_ALARM_STATE_SET,
                                 entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                                 entity_instance_id=entity_instance_id,
                                 severity=fm_constants.FM_ALARM_SEVERITY_MINOR,
                                 reason_text='Patching operation in progress',
                                 probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_65,
                                 proposed_repair_action='Complete reboots of affected hosts',
                                 service_affecting=False)

            self.fm_api.set_fault(fault)
        elif not raise_pip_alarm and pip_alarm is not None:
            logging.info("Clearing patch-in-progress alarm")
            self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_PATCH_IN_PROGRESS,
                                    entity_instance_id)

        obs_alarm = self.fm_api.get_fault(fm_constants.FM_ALARM_ID_PATCH_OBS_IN_SYSTEM,
                                          entity_instance_id)
        if raise_obs_alarm and obs_alarm is None:
            logging.info("Raising obsolete-patch-in-system alarm")
            fault = fm_api.Fault(alarm_id=fm_constants.FM_ALARM_ID_PATCH_OBS_IN_SYSTEM,
                                 alarm_type=fm_constants.FM_ALARM_TYPE_5,
                                 alarm_state=fm_constants.FM_ALARM_STATE_SET,
                                 entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                                 entity_instance_id=entity_instance_id,
                                 severity=fm_constants.FM_ALARM_SEVERITY_WARNING,
                                 reason_text='Obsolete patch in system',
                                 probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_65,
                                 proposed_repair_action='Remove and delete obsolete patches',
                                 service_affecting=False)

            self.fm_api.set_fault(fault)
        elif not raise_obs_alarm and obs_alarm is not None:
            logging.info("Clearing obsolete-patch-in-system alarm")
            self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_PATCH_OBS_IN_SYSTEM,
                                    entity_instance_id)

        cert_alarm = self.fm_api.get_fault(fm_constants.FM_ALARM_ID_NONSTANDARD_CERT_PATCH,
                                           entity_instance_id)
        if raise_cert_alarm and cert_alarm is None:
            logging.info("Raising developer-certificate-enabled alarm")
            fault = fm_api.Fault(alarm_id=fm_constants.FM_ALARM_ID_NONSTANDARD_CERT_PATCH,
                                 alarm_type=fm_constants.FM_ALARM_TYPE_9,
                                 alarm_state=fm_constants.FM_ALARM_STATE_SET,
                                 entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                                 entity_instance_id=entity_instance_id,
                                 severity=fm_constants.FM_ALARM_SEVERITY_CRITICAL,
                                 reason_text='Developer patch certificate is enabled',
                                 probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_65,
                                 proposed_repair_action='Reinstall system to disable certificate and remove untrusted patches',
                                 suppression=False,
                                 service_affecting=False)

            self.fm_api.set_fault(fault)

    def _get_handle_failed_hosts(self):
        url = "http://%s/patch/query_hosts" % self.api_addr

        try:
            req = requests.get(url)
        except:
            return

        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST, "controller")

        failed_hosts = []
        if req.status_code == 200:
            data = json.loads(req.text)

            if 'data' in data:
                for host in data['data']:
                    if 'hostname' in host and 'patch_failed' in host and host['patch_failed']:
                        failed_hosts.append(host['hostname'])

        # Query existing alarms
        patch_failed_alarm = self.fm_api.get_fault(fm_constants.FM_ALARM_ID_PATCH_HOST_INSTALL_FAILED,
                                                   entity_instance_id)

        if len(failed_hosts) > 0:
            reason_text = "Patch installation failed on the following hosts: %s" % ", ".join(sorted(failed_hosts))

            if patch_failed_alarm is None or reason_text != patch_failed_alarm.reason_text:
                if patch_failed_alarm is None:
                    logging.info("Raising patch-host-install-failure alarm")
                else:
                    logging.info("Updating patch-host-install-failure alarm")

                fault = fm_api.Fault(alarm_id=fm_constants.FM_ALARM_ID_PATCH_HOST_INSTALL_FAILED,
                                     alarm_type=fm_constants.FM_ALARM_TYPE_5,
                                     alarm_state=fm_constants.FM_ALARM_STATE_SET,
                                     entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                                     entity_instance_id=entity_instance_id,
                                     severity=fm_constants.FM_ALARM_SEVERITY_MAJOR,
                                     reason_text=reason_text,
                                     probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_65,
                                     proposed_repair_action='Undo patching operation',
                                     service_affecting=False)
                self.fm_api.set_fault(fault)

        elif patch_failed_alarm is not None:
            logging.info("Clearing patch-host-install-failure alarm")
            self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_PATCH_HOST_INSTALL_FAILED,
                                    entity_instance_id)

        return False
