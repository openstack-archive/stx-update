#!/bin/bash

pushd `dirname $0` > /dev/null
SCRIPTPATH=`pwd`
popd > /dev/null

CGCSPATCH_DIR=$SCRIPTPATH/../../stx-update/cgcs-patch

# Set environment variables for python
export PYTHONPATH=$CGCSPATCH_DIR/cgcs-patch
export PYTHONDONTWRITEBYTECODE=true

# Run the patch_build tool 
exec $CGCSPATCH_DIR/bin/modify_patch "$@"

