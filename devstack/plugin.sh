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
        # Perform installation of sysinv source
        echo_summary "Installing tsconfig"
        install_tsconfig

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # Configure after the other layer 1 and 2 services have been configured
        echo_summary "Configuring update"
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        # Initialize and start the sysinv service
        echo_summary "Initializing and start update"
        # init_sysinv
        # start_sysinv
    elif [[ "$1" == "stack" && "$2" == "test-config" ]]; then
        # do sanity test for sysinv
        echo_summary "do test-config"
    fi

    if [[ "$1" == "unstack" ]]; then
        # Shut down sysinv services
        echo_summary "Stop service"
        # stop_sysinv
        :
    fi

    if [[ "$1" == "clean" ]]; then
        cleanup_sysinv
        :
    fi
fi
