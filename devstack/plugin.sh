#!/bin/bash

# devstack/plugin.sh
# Triggers stx_update specific functions to install and configure stx_update

echo_summary "stx-update devstack plugin.sh called: $1/$2"

# check for service enabled
if is_service_enabled stx-update; then
    if [[ "$1" == "stack" && "$2" == "install" ]]; then
        # Perform installation of source
        echo_summary "Install stx-update"
        install_tsconfig
        install_patch
    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # Configure after the other layer 1 and 2 services have been configured
        echo_summary "Configure stx-update"
    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        # Initialize and start the service
        echo_summary "Initialize and start stx-update"
        # init_update
        # start_update
    elif [[ "$1" == "stack" && "$2" == "test-config" ]]; then
        # do sanity test
        echo_summary "do test-config"
    fi

    if [[ "$1" == "unstack" ]]; then
        # Shut down services
        echo_summary "Stop stx-update services"
        # stop_update
    fi

    if [[ "$1" == "clean" ]]; then
        echo_summary "Clean stx-update"
        # cleanup_update
    fi
fi
