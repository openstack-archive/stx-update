#!/bin/bash
#
# Copyright (c) 2014-2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# CGCS Patching
# chkconfig: 345 20 23
# description: CGCS Patching init script

NAME=$(basename $0)

. /usr/bin/tsconfig
. /etc/platform/platform.conf

logfile=/var/log/patching.log

function LOG_TO_FILE()
{
    echo "`date "+%FT%T.%3N"`: $NAME: $*" >> $logfile
}

function check_for_rr_patch()
{
    if [ -f /var/run/node_is_patched_rr ]
    then
        echo
        echo "Node has been patched and requires an immediate reboot."
        echo
        LOG_TO_FILE "Node has been patched, with reboot-required flag set. Rebooting"
        /sbin/reboot
    fi
}

function check_install_uuid()
{
    # Check whether our installed load matches the active controller
    CONTROLLER_UUID=`curl -sf http://controller/feed/rel-${SW_VERSION}/install_uuid`
    if [ $? -ne 0 ]
    then
        if [ "$HOSTNAME" = "controller-1" ]
        then
            # If we're on controller-1, controller-0 may not have the install_uuid
            # matching this release, if we're in an upgrade. If the file doesn't exist,
            # bypass this check
            return 0
        fi

        LOG_TO_FILE "Unable to retrieve installation uuid from active controller"
        echo "Unable to retrieve installation uuid from active controller"
        return 1
    fi

    if [ "$INSTALL_UUID" != "$CONTROLLER_UUID" ]
    then
        LOG_TO_FILE "This node is running a different load than the active controller and must be reinstalled"
        echo "This node is running a different load than the active controller and must be reinstalled"
        return 1
    fi

    return 0
}

# Check for installation failure
if [ -f /etc/platform/installation_failed ] ; then
    LOG_TO_FILE "/etc/platform/installation_failed flag is set. Aborting."
    echo "$(basename $0): Detected installation failure. Aborting."
    exit 1
fi

# Clean up the RPM DB
if [ ! -f /var/run/.rpmdb_cleaned ]
then
    LOG_TO_FILE "Cleaning RPM DB"
    rm -f /var/lib/rpm/__db*
    touch /var/run/.rpmdb_cleaned
fi

# If the management interface is bonded, it may take some time
# before communications can be properly setup.
# Allow up to $DELAY_SEC seconds to reach controller.
DELAY_SEC=120
START=`date +%s`
FOUND=0
while [ $(date +%s) -lt $(( ${START} + ${DELAY_SEC} )) ]
do
    ping -c 1 controller > /dev/null 2>&1 || ping6 -c 1 controller > /dev/null 2>&1
    if [ $? -eq 0 ]
    then
        FOUND=1
        break
    fi
    sleep 1
done

if [ ${FOUND} -eq 0 ]
then
     # 'controller' is not available, just exit
     LOG_TO_FILE "Unable to contact active controller (controller). Boot will continue."
     exit 1
fi

case "$1" in
    start)
        if [ "${system_mode}" = "simplex" ]
        then
            # On a simplex CPE, we need to launch the http server first,
            # before we can do the patch installation
            LOG_TO_FILE "***** Launching lighttpd *****"
            /etc/init.d/lighttpd start

            LOG_TO_FILE "***** Starting patch operation *****"
            /usr/sbin/sw-patch-agent --install 2>>$logfile
            LOG_TO_FILE "***** Finished patch operation *****"

            LOG_TO_FILE "***** Shutting down lighttpd *****"
            /etc/init.d/lighttpd stop
        else
            check_install_uuid
            if [ $? -ne 0 ]
            then
                # The INSTALL_UUID doesn't match the active controller, so exit
                exit 1
            fi

            LOG_TO_FILE "***** Starting patch operation *****"
            /usr/sbin/sw-patch-agent --install 2>>$logfile
            LOG_TO_FILE "***** Finished patch operation *****"
        fi

        check_for_rr_patch
        ;;
    stop)
        # Nothing to do here
        ;;
    restart)
        LOG_TO_FILE "***** Starting patch operation *****"
        /usr/sbin/sw-patch-agent --install 2>>$logfile
        LOG_TO_FILE "***** Finished patch operation *****"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart}"
        exit 1
esac

exit 0

