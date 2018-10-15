#!/bin/bash

# devstack/plugin.sh
# Triggers stx_update specific functions to install and configure stx_update

# Dependencies:
#
# - ``functions`` file
# - ``DATA_DIR`` must be defined

# ``stack.sh`` calls the entry points in this order:
#
echo_summary "update devstack plugin.sh called: $1/$2"
source $DEST/stx-update/devstack/lib/stx-update

# check for service enabled
if is_service_enabled tsconfig; then
    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        # Perform installation of source
        echo_summary "Installing tsconfig"
        install_tsconfig

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # Configure after the other layer 1 and 2 services have been configured
        echo_summary "Configuring update"
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        # Initialize and start the service
        echo_summary "Initializing and start update"
        # init_update
        # start_update
    elif [[ "$1" == "stack" && "$2" == "test-config" ]]; then
        # do sanity test
        echo_summary "do test-config"
    fi

    if [[ "$1" == "unstack" ]]; then
        # Shut down services
        echo_summary "Stop service"
        # stop_update
        :
    fi

    if [[ "$1" == "clean" ]]; then
        echo_summary "Clean stx-update"
        # cleanup_update
        :
    fi
fi
