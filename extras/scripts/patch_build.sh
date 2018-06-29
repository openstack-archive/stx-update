#!/bin/bash

pushd `dirname $0` > /dev/null
SCRIPTPATH=`pwd`
popd > /dev/null

CGCSPATCH_DIR=$SCRIPTPATH/../../stx-update/cgcs-patch

# Source release-info
. $SCRIPTPATH/../../middleware/recipes-common/build-info/release-info.inc
export PLATFORM_RELEASE

# Set environment variables for python
export PYTHONPATH=$CGCSPATCH_DIR/cgcs-patch
export PYTHONDONTWRITEBYTECODE=true

# Run the patch_build tool 
exec $CGCSPATCH_DIR/bin/patch_build "$@"

