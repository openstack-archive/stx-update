#!/bin/bash

CGCSPATCH_DIR=$MY_REPO/addons/wr-cgcs/layers/cgcs/middleware/patching/recipes-common/cgcs-patch

# Source release-info
. $MY_REPO/addons/wr-cgcs/layers/cgcs/middleware/recipes-common/build-info/release-info.inc
export PLATFORM_RELEASE

# Set environment variables for python
export PYTHONPATH=$CGCSPATCH_DIR/cgcs-patch
export PYTHONDONTWRITEBYTECODE=true

# Run the patch_build tool 
exec $CGCSPATCH_DIR/bin/patch_build "$@"

