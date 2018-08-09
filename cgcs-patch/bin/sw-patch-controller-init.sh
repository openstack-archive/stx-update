#!/bin/bash
#
# Copyright (c) 2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# CGCS Patching Controller setup
# chkconfig: 345 20 24
# description: CGCS Patching Controller init script

. /usr/bin/tsconfig

NAME=$(basename $0)

REPO_ID=updates
REPO_ROOT=/www/pages/${REPO_ID}
REPO_DIR=${REPO_ROOT}/rel-${SW_VERSION}
GROUPS_FILE=$REPO_DIR/comps.xml
PATCHING_DIR=/opt/patching

logfile=/var/log/patching.log

function LOG {
    logger "$NAME: $*"
    echo "`date "+%FT%T.%3N"`: $NAME: $*" >> $logfile
}

function LOG_TO_FILE {
    echo "`date "+%FT%T.%3N"`: $NAME: $*" >> $logfile
}

function create_groups {
    if [ -f $GROUPS_FILE ]; then
        return 0
    fi

    cat >$GROUPS_FILE <<EOF
<comps>
</comps>

EOF
}

function do_setup {
    # Does the repo exist?
    if [ ! -d $REPO_DIR ]; then
        LOG "Creating repo"
        mkdir -p $REPO_DIR

        # Setup the groups file
        create_groups

        createrepo -g $GROUPS_FILE $REPO_DIR >> $logfile 2>&1
    fi

    if [ ! -d $PATCHING_DIR ]; then
        LOG "Creating $PATCHING_DIR"
        mkdir -p $PATCHING_DIR
    fi

    # If we can ping the active controller, sync the repos
    LOG_TO_FILE "ping -c 1 -w 1 controller"
    ping -c 1 -w 1 controller >> $logfile 2>&1 || ping6 -c 1 -w 1 controller >> $logfile 2>&1
    if [ $? -ne 0 ]; then
        LOG "Cannot ping controller. Nothing to do"
        return 0
    fi

    # Sync the patching dir
    LOG_TO_FILE "rsync -acv --delete rsync://controller/patching/ ${PATCHING_DIR}/"
    rsync -acv --delete rsync://controller/patching/ ${PATCHING_DIR}/ >> $logfile 2>&1

    # Sync the patching dir
    LOG_TO_FILE "rsync -acv --delete rsync://controller/repo/ ${REPO_ROOT}/"
    rsync -acv --delete rsync://controller/repo/ ${REPO_ROOT}/ >> $logfile 2>&1
}

case "$1" in
    start)
        do_setup
        ;;
    status)
        ;;
    stop)
        # Nothing to do here
        ;;
    restart)
        do_setup
        ;;
    *)
        echo "Usage: $0 {status|start|stop|restart}"
        exit 1
esac

exit 0

