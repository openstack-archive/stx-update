#!/bin/bash

pushd `dirname $0` > /dev/null
SCRIPTPATH=`pwd`
popd > /dev/null

# CGCSPATCH_DIR=$MY_REPO/addons/wr-cgcs/layers/cgcs/middleware/patching/recipes-common/cgcs-patch
CGCSPATCH_DIR=$SCRIPTPATH/../../middleware/patching/recipes-common/cgcs-patch

# Set environment variables for python
export PYTHONPATH=$CGCSPATCH_DIR/cgcs-patch
export PYTHONDONTWRITEBYTECODE=true

# Run the patch_build tool 
exec $CGCSPATCH_DIR/bin/make_patch "$@"

