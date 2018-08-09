#!/bin/sh
#
# Copyright (c) 2014-2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# chkconfig: 345 26 30

### BEGIN INIT INFO
# Provides:          sw-patch-agent
# Required-Start:    $syslog
# Required-Stop:     $syslog
# Default-Start:     2 3 5
# Default-Stop:      0 1 6
# Short-Description: sw-patch-agent
# Description:       Provides the CGCS Patch Agent Daemon
### END INIT INFO

DESC="sw-patch-agent"
DAEMON="/usr/sbin/sw-patch-agent"
PIDFILE="/var/run/sw-patch-agent.pid"
PATCH_INSTALLING_FILE="/var/run/patch_installing"

start()
{
    if [ -e $PIDFILE ]; then
        PIDDIR=/proc/$(cat $PIDFILE)
        if [ -d ${PIDDIR} ]; then
            echo "$DESC already running."
            exit 1
        else
            echo "Removing stale PID file $PIDFILE"
            rm -f $PIDFILE
        fi
    fi

    echo -n "Starting $DESC..."

    start-stop-daemon --start --quiet --background \
        --pidfile ${PIDFILE} --make-pidfile --exec ${DAEMON}

    if [ $? -eq 0 ]; then
        echo "done."
    else
        echo "failed."
    fi
}

stop()
{
    if [ -f $PATCH_INSTALLING_FILE ]; then
        echo "Patches are installing. Waiting for install to complete."
        while [ -f $PATCH_INSTALLING_FILE ]; do
            # Verify the agent is still running
            pid=$(cat $PATCH_INSTALLING_FILE)
            cat /proc/$pid/cmdline 2>/dev/null | grep -q $DAEMON
            if [ $? -ne 0 ]; then
                echo "Patch agent not running."
                break
            fi
            sleep 1
        done
        echo "Continuing with shutdown."
    fi

    echo -n "Stopping $DESC..."
    start-stop-daemon --stop --quiet --pidfile $PIDFILE
    if [ $? -eq 0 ]; then
        echo "done."
    else
        echo "failed."
    fi
    rm -f $PIDFILE
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart|force-reload)
        stop
        start
        ;;
    *)
        echo "Usage: $0 {start|stop|force-reload|restart}"
        exit 1
        ;;
esac

exit 0
