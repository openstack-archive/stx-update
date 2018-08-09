"""
Copyright (c) 2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""


class PatchError(Exception):
    """Base class for patching exceptions."""

    def __init__(self, message=None):
        self.message = message

    def __str__(self):
        return self.message or ""


class MetadataFail(PatchError):
    """Metadata error."""
    pass


class RpmFail(PatchError):
    """RPM error."""
    pass


class RepoFail(PatchError):
    """Repo error."""
    pass


class PatchFail(PatchError):
    """General patching error."""
    pass


class PatchValidationFailure(PatchError):
    """Patch validation error."""
    pass


class PatchMismatchFailure(PatchError):
    """Patch validation error."""
    pass
