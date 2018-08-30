"""
Copyright (c) 2014-2017 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
from __future__ import print_function
from six.moves import input
import requests
import json
import os
import sys
import shutil
import re
import time
import signal

import subprocess
import textwrap

# noinspection PyUnresolvedReferences
from requests_toolbelt import MultipartEncoder

import cgcs_patch.constants as constants
import cgcs_patch.utils as utils

from tsconfig.tsconfig import SW_VERSION as RUNNING_SW_VERSION

api_addr = "127.0.0.1:5487"
auth_token = None

TERM_WIDTH = 72
VIRTUAL_REGION = 'SystemController'
IPV6_FAMILY = 6


help_upload = "Upload one or more patches to the patching system."
help_upload_dir = "Upload patches from one or more directories to the patching system."
help_apply = "Apply one or more patches. This adds the specified patches " + \
    "to the repository, making the update(s) available to the " + \
    "hosts in the system. Use --all to apply all available patches."
help_remove = "Remove one or more patches. This removes the specified " + \
    "patches from the repository."
help_delete = "Delete one or more patches from the patching system."
help_query = "Query system patches. Optionally, specify 'query applied' " + \
    "to query only those patches that are applied, or 'query available' " + \
    "to query those that are not."
help_show = "Show details for specified patches."
help_what_requires = "List patches that require the specified patches."
help_query_hosts = "Query patch states for hosts in the system."
help_host_install = "Trigger patch install/remove on specified host. " + \
    "To force install on unlocked node, use the --force option."
help_host_install_async = "Trigger patch install/remove on specified host. " + \
    "To force install on unlocked node, use the --force option." + \
    " Note: This command returns immediately upon dispatching installation request."
help_patch_args = "Patches are specified as a space-separated list of patch IDs."
help_install_local = "Trigger patch install/remove on the local host. " + \
    "This command can only be used for patch installation prior to initial " + \
    "configuration."
help_drop_host = "Drop specified host from table."
help_query_dependencies = "List dependencies for specified patch. Use " + \
    constants.CLI_OPT_RECURSIVE + " for recursive query."
help_commit = "Commit patches to free disk space. WARNING: This action " + \
    "is irreversible!"
help_region_name = "Send the request to a specified region"


def set_term_width():
    global TERM_WIDTH

    try:
        with open(os.devnull, 'w') as NULL:
            output = subprocess.check_output(["tput", "cols"], stderr=NULL)
            width = int(output)
            if width > 60:
                TERM_WIDTH = width - 4
    except:
        pass


def print_help():
    print("usage: sw-patch [--debug]")
    print("                  <subcommand> ...")
    print("")
    print("Subcomands:")
    print("")
    print(textwrap.fill("    {0:<15} ".format("upload:") + help_upload,
                        width=TERM_WIDTH, subsequent_indent=' ' * 20))
    print("")
    print(textwrap.fill("    {0:<15} ".format("upload-dir:") + help_upload_dir,
                        width=TERM_WIDTH, subsequent_indent=' ' * 20))
    print("")
    print(textwrap.fill("    {0:<15} ".format("apply:") + help_apply,
                        width=TERM_WIDTH, subsequent_indent=' ' * 20))
    print(textwrap.fill(help_patch_args,
                        width=TERM_WIDTH, initial_indent=' ' * 20, subsequent_indent=' ' * 20))
    print("")
    print(textwrap.fill("    {0:<15} ".format("remove:") + help_remove,
                        width=TERM_WIDTH, subsequent_indent=' ' * 20))
    print(textwrap.fill(help_patch_args,
                        width=TERM_WIDTH, initial_indent=' ' * 20, subsequent_indent=' ' * 20))
    print("")
    print(textwrap.fill("    {0:<15} ".format("delete:") + help_delete,
                        width=TERM_WIDTH, subsequent_indent=' ' * 20))
    print(textwrap.fill(help_patch_args,
                        width=TERM_WIDTH, initial_indent=' ' * 20, subsequent_indent=' ' * 20))
    print("")
    print(textwrap.fill("    {0:<15} ".format("query:") + help_query,
                        width=TERM_WIDTH, subsequent_indent=' ' * 20))
    print("")
    print(textwrap.fill("    {0:<15} ".format("show:") + help_show,
                        width=TERM_WIDTH, subsequent_indent=' ' * 20))
    print("")
    print(textwrap.fill("    {0:<15} ".format("what-requires:") + help_what_requires,
                        width=TERM_WIDTH, subsequent_indent=' ' * 20))
    print("")
    print(textwrap.fill("    {0:<15} ".format("query-hosts:") + help_query_hosts,
                        width=TERM_WIDTH, subsequent_indent=' ' * 20))
    print("")
    print(textwrap.fill("    {0:<15} ".format("host-install:") + help_host_install,
                        width=TERM_WIDTH, subsequent_indent=' ' * 20))
    print("")
    print(textwrap.fill("    {0:<15} ".format("host-install-async:") + help_host_install_async,
                        width=TERM_WIDTH, subsequent_indent=' ' * 20))
    print("")
    print(textwrap.fill("    {0:<15} ".format("install-local:") + help_install_local,
                        width=TERM_WIDTH, subsequent_indent=' ' * 20))
    print("")
    print(textwrap.fill("    {0:<15} ".format("drop-host:") + help_drop_host,
                        width=TERM_WIDTH, subsequent_indent=' ' * 20))
    print("")
    print(textwrap.fill("    {0:<15} ".format("query-dependencies:") + help_query_dependencies,
                        width=TERM_WIDTH, subsequent_indent=' ' * 20))
    print("")
    print(textwrap.fill("    {0:<15} ".format("commit:") + help_commit,
                        width=TERM_WIDTH, subsequent_indent=' ' * 20))
    print("")
    print(textwrap.fill("    {0:<15} ".format("--os-region-name:") + help_region_name,
                        width=TERM_WIDTH, subsequent_indent=' ' * 20))
    print("")

    exit(1)


def check_rc(req):
    rc = 0
    if req.status_code == 200:
        data = json.loads(req.text)
        if 'error' in data and data["error"] != "":
            rc = 1
    else:
        rc = 1

    return rc


def print_result_debug(req):
    if req.status_code == 200:
        data = json.loads(req.text)
        if 'pd' in data:
            print(json.dumps(data['pd'],
                             sort_keys=True,
                             indent=4,
                             separators=(',', ': ')))
        elif 'data' in data:
            print(json.dumps(data['data'],
                             sort_keys=True,
                             indent=4,
                             separators=(',', ': ')))
        else:
            print(json.dumps(data,
                             sort_keys=True,
                             indent=4,
                             separators=(',', ': ')))
    elif req.status_code == 500:
        print("An internal error has occurred. Please check /var/log/patching.log for details")
    else:
        m = re.search("(Error message:.*)", req.text, re.MULTILINE)
        print(m.group(0))


def print_patch_op_result(req):
    if req.status_code == 200:
        data = json.loads(req.text)

        if 'pd' in data:
            pd = data['pd']

            # Calculate column widths
            hdr_id = "Patch ID"
            hdr_rr = "RR"
            hdr_rel = "Release"
            hdr_repo = "Repo State"
            hdr_state = "Patch State"

            width_id = len(hdr_id)
            width_rr = len(hdr_rr)
            width_rel = len(hdr_rel)
            width_repo = len(hdr_repo)
            width_state = len(hdr_state)

            show_repo = False

            for patch_id in pd.keys():
                if len(patch_id) > width_id:
                    width_id = len(patch_id)
                if len(pd[patch_id]["sw_version"]) > width_rel:
                    width_rel = len(pd[patch_id]["sw_version"])
                if len(pd[patch_id]["repostate"]) > width_repo:
                    width_repo = len(pd[patch_id]["repostate"])
                if len(pd[patch_id]["patchstate"]) > width_state:
                    width_state = len(pd[patch_id]["patchstate"])
                if pd[patch_id]["patchstate"] == "n/a":
                    show_repo = True

            if show_repo:
                print("{0:^{width_id}}  {1:^{width_rr}}  {2:^{width_rel}}  {3:^{width_repo}}  {4:^{width_state}}".format(
                    hdr_id, hdr_rr, hdr_rel, hdr_repo, hdr_state,
                    width_id=width_id, width_rr=width_rr,
                    width_rel=width_rel, width_repo=width_repo, width_state=width_state))

                print("{0}  {1}  {2}  {3}  {4}".format(
                    '=' * width_id, '=' * width_rr, '=' * width_rel, '=' * width_repo, '=' * width_state))

                for patch_id in sorted(pd.keys()):
                    if "reboot_required" in pd[patch_id]:
                        rr = pd[patch_id]["reboot_required"]
                    else:
                        rr = "Y"

                    print("{0:<{width_id}}  {1:^{width_rr}}  {2:^{width_rel}}  {3:^{width_repo}}  {4:^{width_state}}".format(
                        patch_id,
                        rr,
                        pd[patch_id]["sw_version"],
                        pd[patch_id]["repostate"],
                        pd[patch_id]["patchstate"],
                        width_id=width_id, width_rr=width_rr,
                        width_rel=width_rel, width_repo=width_repo, width_state=width_state))
            else:
                print("{0:^{width_id}}  {1:^{width_rr}}  {2:^{width_rel}}  {3:^{width_state}}".format(
                    hdr_id, hdr_rr, hdr_rel, hdr_state,
                    width_id=width_id, width_rr=width_rr, width_rel=width_rel, width_state=width_state))

                print("{0}  {1}  {2}  {3}".format(
                    '=' * width_id, '=' * width_rr, '=' * width_rel, '=' * width_state))

                for patch_id in sorted(pd.keys()):
                    if "reboot_required" in pd[patch_id]:
                        rr = pd[patch_id]["reboot_required"]
                    else:
                        rr = "Y"

                    print("{0:<{width_id}}  {1:^{width_rr}}  {2:^{width_rel}}  {3:^{width_state}}".format(
                        patch_id,
                        rr,
                        pd[patch_id]["sw_version"],
                        pd[patch_id]["patchstate"],
                        width_id=width_id, width_rr=width_rr, width_rel=width_rel, width_state=width_state))

            print("")

        if 'info' in data and data["info"] != "":
            print(data["info"])

        if 'warning' in data and data["warning"] != "":
            print("Warning:")
            print(data["warning"])

        if 'error' in data and data["error"] != "":
            print("Error:")
            print(data["error"])

    elif req.status_code == 500:
        print("An internal error has occurred. Please check /var/log/patching.log for details")


def print_patch_show_result(req):
    if req.status_code == 200:
        data = json.loads(req.text)

        if 'metadata' in data:
            pd = data['metadata']
            for patch_id in sorted(pd.keys()):
                print("%s:" % patch_id)

                if "sw_version" in pd[patch_id] and pd[patch_id]["sw_version"] != "":
                    print(textwrap.fill("    {0:<15} ".format("Release:") + pd[patch_id]["sw_version"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "patchstate" in pd[patch_id] and pd[patch_id]["patchstate"] != "":
                    print(textwrap.fill("    {0:<15} ".format("Patch State:") + pd[patch_id]["patchstate"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                    if pd[patch_id]["patchstate"] == "n/a":
                        if "repostate" in pd[patch_id] and pd[patch_id]["repostate"] != "":
                            print(textwrap.fill("    {0:<15} ".format("Repo State:") + pd[patch_id]["repostate"],
                                                width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "status" in pd[patch_id] and pd[patch_id]["status"] != "":
                    print(textwrap.fill("    {0:<15} ".format("Status:") + pd[patch_id]["status"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "unremovable" in pd[patch_id] and pd[patch_id]["unremovable"] != "":
                    print(textwrap.fill("    {0:<15} ".format("Unremovable:") + pd[patch_id]["unremovable"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "reboot_required" in pd[patch_id] and pd[patch_id]["reboot_required"] != "":
                    print(textwrap.fill("    {0:<15} ".format("RR:") + pd[patch_id]["reboot_required"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "summary" in pd[patch_id] and pd[patch_id]["summary"] != "":
                    print(textwrap.fill("    {0:<15} ".format("Summary:") + pd[patch_id]["summary"],
                                        width=TERM_WIDTH, subsequent_indent=' ' * 20))

                if "description" in pd[patch_id] and pd[patch_id]["description"] != "":
                    first_line = True
                    for line in pd[patch_id]["description"].split('\n'):
                        if first_line:
                            print(textwrap.fill("    {0:<15} ".format("Description:") + line,
                                                width=TERM_WIDTH, subsequent_indent=' ' * 20))
                            first_line = False
                        else:
                            print(textwrap.fill(line,
                                                width=TERM_WIDTH, subsequent_indent=' ' * 20,
                                                initial_indent=' ' * 20))

                if "install_instructions" in pd[patch_id] and pd[patch_id]["install_instructions"] != "":
                    print("    Install Instructions:")
                    for line in pd[patch_id]["install_instructions"].split('\n'):
                        print(textwrap.fill(line,
                                            width=TERM_WIDTH, subsequent_indent=' ' * 20,
                                            initial_indent=' ' * 20))

                if "warnings" in pd[patch_id] and pd[patch_id]["warnings"] != "":
                    first_line = True
                    for line in pd[patch_id]["warnings"].split('\n'):
                        if first_line:
                            print(textwrap.fill("    {0:<15} ".format("Warnings:") + line,
                                                width=TERM_WIDTH, subsequent_indent=' ' * 20))
                            first_line = False
                        else:
                            print(textwrap.fill(line,
                                                width=TERM_WIDTH, subsequent_indent=' ' * 20,
                                                initial_indent=' ' * 20))

                if "requires" in pd[patch_id] and len(pd[patch_id]["requires"]) > 0:
                    print("    Requires:")
                    for req_patch in sorted(pd[patch_id]["requires"]):
                        print(' ' * 20 + req_patch)

                if "contents" in data and patch_id in data["contents"]:
                    print("    Contents:")
                    for pkg in sorted(data["contents"][patch_id]):
                        print(' ' * 20 + pkg)

                print("\n")

        if 'info' in data and data["info"] != "":
            print(data["info"])

        if 'warning' in data and data["warning"] != "":
            print("Warning:")
            print(data["warning"])

        if 'error' in data and data["error"] != "":
            print("Error:")
            print(data["error"])

    elif req.status_code == 500:
        print("An internal error has occurred. Please check /var/log/patching.log for details")


def patch_upload_req(debug, args):
    rc = 0

    if len(args) == 0:
        print_help()

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    for patchfile in sorted(list(set(args))):
        if os.path.isdir(patchfile):
            print("Error: %s is a directory. Please use upload-dir" % patchfile)
            continue

        if not os.path.isfile(patchfile):
            print("Error: File does not exist: %s" % patchfile)
            continue

        enc = MultipartEncoder(fields={'file': (patchfile,
                                                open(patchfile, 'rb'),
                                                )})
        url = "http://%s/patch/upload" % api_addr
        headers = {'Content-Type': enc.content_type}
        append_auth_token_if_required(headers)
        req = requests.post(url,
                            data=enc,
                            headers=headers)

        if debug:
            print_result_debug(req)
        else:
            print_patch_op_result(req)

        if check_rc(req) != 0:
            rc = 1

    return rc


def patch_apply_req(debug, args):
    if len(args) == 0:
        print_help()

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    patches = "/".join(args)

    url = "http://%s/patch/apply/%s" % (api_addr, patches)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, headers=headers)

    if debug:
        print_result_debug(req)
    else:
        print_patch_op_result(req)

    return check_rc(req)


def patch_remove_req(debug, args):
    extra_opts = ""

    if len(args) == 0:
        print_help()

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    # The removeunremovable option is hidden and should not be added to help
    # text or customer documentation. It is for emergency use only - under
    # supervision of the design team.
    if "--removeunremovable" in args:
        idx = args.index("--removeunremovable")

        # Get rid of the --removeunremovable
        args.pop(idx)

        # Format the extra opts
        extra_opts = "?removeunremovable=yes"

    patches = "/".join(args)

    url = "http://%s/patch/remove/%s%s" % (api_addr, patches, extra_opts)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, headers=headers)

    if debug:
        print_result_debug(req)
    else:
        print_patch_op_result(req)

    return check_rc(req)


def patch_delete_req(debug, args):
    if len(args) == 0:
        print_help()

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    patches = "/".join(args)

    url = "http://%s/patch/delete/%s" % (api_addr, patches)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, headers=headers)

    if debug:
        print_result_debug(req)
    else:
        print_patch_op_result(req)

    return check_rc(req)


def patch_commit_req(debug, args):
    if len(args) == 0:
        print_help()

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    dry_run = False
    if constants.CLI_OPT_DRY_RUN in args:
        dry_run = True
        args.remove(constants.CLI_OPT_DRY_RUN)

    all_patches = False
    if constants.CLI_OPT_ALL in args:
        all_patches = True
        args.remove(constants.CLI_OPT_ALL)

    # Default to running release
    relopt = RUNNING_SW_VERSION

    release = False
    if constants.CLI_OPT_RELEASE in args:
        release = True
        idx = args.index(constants.CLI_OPT_RELEASE)
        # There must be at least one more arg
        if len(args) < (idx + 1):
            print_help()

        # Get rid of the --release
        args.pop(idx)
        # Pop off the release arg
        relopt = args.pop(idx)

    headers = {}
    append_auth_token_if_required(headers)
    if release and not all_patches:
        # Disallow
        print("Use of --release option requires --all")
        return 1
    elif all_patches:
        # Get a list of all patches
        extra_opts = "&release=%s" % relopt
        url = "http://%s/patch/query?show=all%s" % (api_addr, extra_opts)

        req = requests.get(url, headers=headers)

        patch_list = []
        if req.status_code == 200:
            data = json.loads(req.text)

            if 'pd' in data:
                patch_list = sorted(data['pd'].keys())
        elif req.status_code == 500:
            print("Failed to get patch list. Aborting...")
            return 1

        if len(patch_list) == 0:
            print("There are no %s patches to commit." % relopt)
            return 0

        print("The following patches will be committed:")
        for patch_id in patch_list:
            print("    %s" % patch_id)
        print()

        patches = "/".join(patch_list)
    else:
        patches = "/".join(args)

        # First, get a list of dependencies and ask for confirmation
        url = "http://%s/patch/query_dependencies/%s?recursive=yes" % (api_addr, patches)

        req = requests.get(url, headers=headers)

        if req.status_code == 200:
            data = json.loads(req.text)

            if 'patches' in data:
                print("The following patches will be committed:")
                for patch_id in sorted(data['patches']):
                    print("    %s" % patch_id)
                print()
            else:
                print("No patches found to commit")
                return 1

        elif req.status_code == 500:
            print("An internal error has occurred. Please check /var/log/patching.log for details")
            return 1

    # Run dry-run
    url = "http://%s/patch/commit_dry_run/%s" % (api_addr, patches)

    req = requests.post(url, headers=headers)
    print_patch_op_result(req)

    if check_rc(req) != 0:
        print("Aborting...")
        return 1

    if dry_run:
        return 0

    print()
    commit_warning = "WARNING: Committing a patch is an irreversible operation. " + \
                     "Committed patches cannot be removed."
    print(textwrap.fill(commit_warning, width=TERM_WIDTH, subsequent_indent=' ' * 9))
    print()

    user_input = input("Would you like to continue? [y/N]: ")
    if user_input.lower() != 'y':
        print("Aborting...")
        return 1

    url = "http://%s/patch/commit/%s" % (api_addr, patches)
    req = requests.post(url, headers=headers)

    if debug:
        print_result_debug(req)
    else:
        print_patch_op_result(req)

    return check_rc(req)


def patch_query_req(debug, args):
    state = "all"
    extra_opts = ""

    if "--release" in args:
        idx = args.index("--release")
        # There must be at least one more arg
        if len(args) < (idx + 1):
            print_help()

        # Get rid of the --release
        args.pop(idx)
        # Pop off the release arg
        relopt = args.pop(idx)

        # Format the query string
        extra_opts = "&release=%s" % relopt

    if len(args) > 1:
        # Support 1 additional arg at most, currently
        print_help()

    if len(args) > 0:
        state = args[0]

    url = "http://%s/patch/query?show=%s%s" % (api_addr, state, extra_opts)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.get(url, headers=headers)

    if debug:
        print_result_debug(req)
    else:
        print_patch_op_result(req)

    return check_rc(req)


def print_query_hosts_result(req):
    if req.status_code == 200:
        data = json.loads(req.text)
        if 'data' not in data:
            print("Invalid data returned:")
            print_result_debug(req)
            return

        agents = data['data']

        # Calculate column widths
        hdr_hn = "Hostname"
        hdr_ip = "IP Address"
        hdr_pc = "Patch Current"
        hdr_rr = "Reboot Required"
        hdr_rel = "Release"
        hdr_state = "State"

        width_hn = len(hdr_hn)
        width_ip = len(hdr_ip)
        width_pc = len(hdr_pc)
        width_rr = len(hdr_rr)
        width_rel = len(hdr_rel)
        width_state = len(hdr_state)

        for agent in sorted(agents, key=lambda a: a["hostname"]):
            if len(agent["hostname"]) > width_hn:
                width_hn = len(agent["hostname"])
            if len(agent["ip"]) > width_ip:
                width_ip = len(agent["ip"])
            if len(agent["sw_version"]) > width_rel:
                width_rel = len(agent["sw_version"])
            if len(agent["state"]) > width_state:
                width_state = len(agent["state"])

        print("{0:^{width_hn}}  {1:^{width_ip}}  {2:^{width_pc}}  {3:^{width_rr}}  {4:^{width_rel}}  {5:^{width_state}}".format(
            hdr_hn, hdr_ip, hdr_pc, hdr_rr, hdr_rel, hdr_state,
            width_hn=width_hn, width_ip=width_ip, width_pc=width_pc, width_rr=width_rr, width_rel=width_rel, width_state=width_state))

        print("{0}  {1}  {2}  {3}  {4}  {5}".format(
            '=' * width_hn, '=' * width_ip, '=' * width_pc, '=' * width_rr, '=' * width_rel, '=' * width_state))

        for agent in sorted(agents, key=lambda a: a["hostname"]):
            patch_current_field = "Yes" if agent["patch_current"] else "No"
            if agent.get("interim_state") is True:
                patch_current_field = "Pending"

            if agent["patch_failed"]:
                patch_current_field = "Failed"

            print("{0:<{width_hn}}  {1:<{width_ip}}  {2:^{width_pc}}  {3:^{width_rr}}  {4:^{width_rel}}  {5:^{width_state}}".format(
                agent["hostname"],
                agent["ip"],
                patch_current_field,
                "Yes" if agent["requires_reboot"] else "No",
                agent["sw_version"],
                agent["state"],
                width_hn=width_hn, width_ip=width_ip, width_pc=width_pc, width_rr=width_rr, width_rel=width_rel, width_state=width_state))

    elif req.status_code == 500:
        print("An internal error has occurred. Please check /var/log/patching.log for details")


def patch_query_hosts_req(debug, args):
    if len(args) > 0:
        # Support 0 arg at most, currently
        print_help()

    url = "http://%s/patch/query_hosts" % api_addr

    req = requests.get(url)

    if debug:
        print_result_debug(req)
    else:
        print_query_hosts_result(req)

    return check_rc(req)


def patch_show_req(debug, args):
    if len(args) == 0:
        print_help()

    patches = "/".join(args)

    url = "http://%s/patch/show/%s" % (api_addr, patches)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, headers=headers)

    if debug:
        print_result_debug(req)
    else:
        print_patch_show_result(req)

    return check_rc(req)


def what_requires(debug, args):
    if len(args) == 0:
        print_help()

    patches = "/".join(args)

    url = "http://%s/patch/what_requires/%s" % (api_addr, patches)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.get(url, headers=headers)

    if debug:
        print_result_debug(req)
    else:
        print_patch_op_result(req)

    return check_rc(req)


def query_dependencies(debug, args):
    if len(args) == 0:
        print_help()

    extra_opts = ""
    if constants.CLI_OPT_RECURSIVE in args:
        args.remove(constants.CLI_OPT_RECURSIVE)
        extra_opts = "?recursive=yes"

    patches = "/".join(args)

    url = "http://%s/patch/query_dependencies/%s%s" % (api_addr, patches, extra_opts)

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.get(url, headers=headers)

    if debug:
        print_result_debug(req)
    else:
        if req.status_code == 200:
            data = json.loads(req.text)

            if 'patches' in data:
                for patch_id in sorted(data['patches']):
                    print(patch_id)

        elif req.status_code == 500:
            print("An internal error has occurred. Please check /var/log/patching.log for details")

    return check_rc(req)


def wait_for_install_complete(agent_ip):
    url = "http://%s/patch/query_hosts" % api_addr
    rc = 0

    max_retries = 4
    retriable_count = 0

    while True:
        # Sleep on the first pass as well, to allow time for the
        # agent to respond
        time.sleep(5)

        try:
            req = requests.get(url)
        except requests.exceptions.ConnectionError:
            # The local patch-controller may have restarted.
            retriable_count += 1
            if retriable_count <= max_retries:
                continue
            else:
                print("Lost communications with the patch controller")
                rc = 1
                break

        if req.status_code == 200:
            data = json.loads(req.text)
            if 'data' not in data:
                print("Invalid query-hosts data returned:")
                print_result_debug(req)
                rc = 1
                break

            state = None
            agents = data['data']
            interim_state = None
            for agent in agents:
                if agent['hostname'] == agent_ip \
                   or agent['ip'] == agent_ip:
                    state = agent.get('state')
                    interim_state = agent.get('interim_state')

            if state is None:
                # If the patching daemons have restarted, there's a
                # window after the patch-controller restart that the
                # hosts table will be empty.
                retriable_count += 1
                if retriable_count <= max_retries:
                    continue
                else:
                    print("%s agent has timed out." % agent_ip)
                    rc = 1
                    break

            if state == constants.PATCH_AGENT_STATE_INSTALLING or \
                    interim_state is True:
                # Still installing
                sys.stdout.write(".")
                sys.stdout.flush()
            elif state == constants.PATCH_AGENT_STATE_INSTALL_REJECTED:
                print("\nInstallation rejected. Node must be locked")
                rc = 1
                break
            elif state == constants.PATCH_AGENT_STATE_INSTALL_FAILED:
                print("\nInstallation failed. Please check logs for details.")
                rc = 1
                break
            elif state == constants.PATCH_AGENT_STATE_IDLE:
                print("\nInstallation was successful.")
                rc = 0
                break
            else:
                print("\nPatch agent is reporting unknown state: %s" % state)
                rc = 1
                break

        elif req.status_code == 500:
            print("An internal error has occurred. Please check /var/log/patching.log for details")
            rc = 1
            break
        else:
            m = re.search("(Error message:.*)", req.text, re.MULTILINE)
            print(m.group(0))
            rc = 1
            break

    return rc


def host_install(debug, args):
    force = False
    rc = 0

    if "--force" in args:
        force = True
        args.remove("--force")

    if len(args) != 1:
        print_help()

    agent_ip = args[0]

    # Issue host_install_async request and poll for results
    url = "http://%s/patch/host_install_async/%s" % (api_addr, agent_ip)

    if force:
        url += "/force"

    req = requests.post(url)

    if req.status_code == 200:
        data = json.loads(req.text)
        if 'error' in data and data["error"] != "":
            print("Error:")
            print(data["error"])
            rc = 1
        else:
            rc = wait_for_install_complete(agent_ip)
    elif req.status_code == 500:
        print("An internal error has occurred. Please check /var/log/patching.log for details")
        rc = 1
    else:
        m = re.search("(Error message:.*)", req.text, re.MULTILINE)
        print(m.group(0))
        rc = 1

    return rc


def host_install_async(debug, args):
    force = False

    if "--force" in args:
        force = True
        args.remove("--force")

    if len(args) != 1:
        print_help()

    agent_ip = args[0]

    url = "http://%s/patch/host_install_async/%s" % (api_addr, agent_ip)

    if force:
        url += "/force"

    req = requests.post(url)

    if debug:
        print_result_debug(req)
    else:
        print_patch_op_result(req)

    return check_rc(req)


def drop_host(debug, args):
    force = False

    if len(args) != 1:
        print_help()

    host_ip = args[0]

    url = "http://%s/patch/drop_host/%s" % (api_addr, host_ip)

    req = requests.post(url)

    if debug:
        print_result_debug(req)
    else:
        print_patch_op_result(req)

    return check_rc(req)


def patch_upload_dir_req(debug, args):
    if len(args) == 0:
        print_help()

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    dirlist = {}
    i = 0
    for d in sorted(list(set(args))):
        dirlist["dir%d" % i] = os.path.abspath(d)
        i += 1

    url = "http://%s/patch/upload_dir" % api_addr

    headers = {}
    append_auth_token_if_required(headers)
    req = requests.post(url, params=dirlist, headers=headers)

    if debug:
        print_result_debug(req)
    else:
        print_patch_op_result(req)

    return check_rc(req)


def patch_install_local(debug, args):
    """ This function is used to trigger patch installation prior to configuration """
    # First, check to see if the controller hostname is already known.
    if utils.gethostbyname(constants.CONTROLLER_FLOATING_HOSTNAME):
        # If this is successful, disallow the install
        print("Error: This function can only be used before initial system configuration.", file=sys.stderr)
        return 1

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    # To allow patch installation to occur before configuration, we need
    # to alias controller to localhost so that the smartpm channels work.
    # There is a HOSTALIASES feature that would be preferred here, but it
    # unfortunately requires dnsmasq to be running, which it is not at this point.

    rc = 0

    # Make a backup of /etc/hosts
    shutil.copy2('/etc/hosts', '/etc/hosts.patchbak')

    # Update /etc/hosts
    with open('/etc/hosts', 'a') as f:
        f.write("127.0.0.1 controller\n")

    # Run the patch install
    try:
        # Use the restart option of the sw-patch init script, which will
        # install patches but won't automatically reboot if the RR flag is set
        subprocess.check_output(['/etc/init.d/sw-patch', 'restart'])
    except subprocess.CalledProcessError:
        print("Error: Failed to install patches. Please check /var/log/patching.log for details", file=sys.stderr)
        rc = 1

    # Restore /etc/hosts
    os.rename('/etc/hosts.patchbak', '/etc/hosts')

    if rc == 0:
        print("Patch installation is complete.")
        print("Please reboot before continuing with configuration.")

    return rc


def patch_init_release(debug, args):
    if len(args) != 1:
        print_help()

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    release = args[0]

    url = "http://%s/patch/init_release/%s" % (api_addr, release)

    req = requests.post(url)

    if debug:
        print_result_debug(req)
    else:
        print_patch_op_result(req)

    return check_rc(req)


def patch_del_release(debug, args):
    if len(args) != 1:
        print_help()

    # Ignore interrupts during this function
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    release = args[0]

    url = "http://%s/patch/del_release/%s" % (api_addr, release)

    req = requests.post(url)

    if debug:
        print_result_debug(req)
    else:
        print_patch_op_result(req)

    return check_rc(req)


def completion_opts(args):
    if len(args) != 1:
        return 1

    if args[0] == "patches":
        url = "http://%s/patch/query" % api_addr
        req = requests.get(url)
        # Just list patch IDs
        if req.status_code == 200:
            data = json.loads(req.text)

            if 'pd' in data:
                print(" ".join(data['pd'].keys()))
        return 0

    elif args[0] == "hosts":
        url = "http://%s/patch/query_hosts" % api_addr
        req = requests.get(url)

        # Just list hostnames
        if req.status_code == 200:
            data = json.loads(req.text)

            if 'data' in data:
                for agent in data['data']:
                    print(agent["hostname"])
        return 0

    return 1


def check_env(env, var):
    if env not in os.environ:
        print("You must provide a %s via env[%s]" % (var, env))
        exit(-1)


def get_auth_token_and_endpoint(region_name):
    from keystoneauth1 import identity
    from keystoneauth1 import session
    from keystoneauth1 import exceptions

    user_env_map = {'OS_USERNAME': 'username',
                    'OS_PASSWORD': 'password',
                    'OS_PROJECT_NAME': 'project_name',
                    'OS_AUTH_URL': 'auth_url',
                    'OS_USER_DOMAIN_NAME': 'user_domain_name',
                    'OS_PROJECT_DOMAIN_NAME': 'project_domain_name'}

    for k, v in user_env_map.items():
        check_env(k, v)

    user = dict()
    for k, v in user_env_map.items():
        user[v] = os.environ.get(k)

    auth = identity.V3Password(**user)
    sess = session.Session(auth=auth)
    try:
        token = auth.get_token(sess)
        endpoint = auth.get_endpoint(sess, service_type='patching',
                                     interface='internal',
                                     region_name=region_name)
    except (exceptions.http.Unauthorized, exceptions.EndpointNotFound) as e:
        print(e.message)
        exit(-1)

    return token, endpoint


def append_auth_token_if_required(headers):
    global auth_token
    if auth_token is not None:
        headers['X-Auth-Token'] = auth_token


def format_url_address(address):
    import netaddr
    try:
        ip_addr = netaddr.IPAddress(address)
        if ip_addr.version == IPV6_FAMILY:
            return "[%s]" % address
        else:
            return address
    except netaddr.AddrFormatError:
        return address


def check_for_os_region_name():
    region_option = "--os-region-name"
    if region_option not in sys.argv:
        return False

    for c, value in enumerate(sys.argv, 1):
        if value == region_option:
            if c == len(sys.argv):
                print("Please specify a region name")
                print_help()

            region = sys.argv[c]
            global VIRTUAL_REGION
            if region != VIRTUAL_REGION:
                print("Unsupported region name: %s" % region)
                exit(1)

            # check it is running on the active controller
            # not able to use sm-query due to it requires sudo
            try:
                subprocess.check_output("pgrep -f dcorch-api-proxy", shell=True)
            except subprocess.CalledProcessError:
                print("Command must be run from the active controller.")
                exit(1)

            # get a token and fetch the internal endpoint in SystemController
            global auth_token
            auth_token, endpoint = get_auth_token_and_endpoint(region)
            if endpoint is not None:
                global api_addr
                try:
                    # python 2
                    from urlparse import urlparse
                except ImportError:
                    # python 3
                    from urllib.parse import urlparse
                url = urlparse(endpoint)
                address = format_url_address(url.hostname)
                api_addr = '{}:{}'.format(address, url.port)

    sys.argv.remove("--os-region-name")
    sys.argv.remove(region)
    return True


def main():
    set_term_width()

    if len(sys.argv) <= 1:
        print_help()

    debug = False
    if "--debug" in sys.argv:
        debug = True
        sys.argv.remove("--debug")

    dc_request = check_for_os_region_name()

    rc = 0

    action = sys.argv[1]

    # Reject the commands that are not supported in the virtual region
    if (dc_request and action in ["query-hosts", "host-install",
                                  "host-install-async",
                                  "install-local", "drop-host"]):
        global VIRTUAL_REGION
        print("\n%s command is not allowed in %s region" % (action,
                                                            VIRTUAL_REGION))
        exit(1)

    if auth_token is None and os.geteuid() != 0:
        # Restrict non-root/sudo users to these commands
        if action == "query":
            rc = patch_query_req(debug, sys.argv[2:])
        elif action == "query-hosts":
            rc = patch_query_hosts_req(debug, sys.argv[2:])
        elif action == "what-requires":
            rc = what_requires(debug, sys.argv[2:])
        elif action == "completion":
            rc = completion_opts(sys.argv[2:])
        elif action == "--help" or action == "-h":
            print_help()
        else:
            print("Error: Command must be run as sudo or root", file=sys.stderr)
            rc = 1
    else:
        if action == "upload":
            rc = patch_upload_req(debug, sys.argv[2:])
        elif action == "apply":
            rc = patch_apply_req(debug, sys.argv[2:])
        elif action == "remove":
            rc = patch_remove_req(debug, sys.argv[2:])
        elif action == "delete":
            rc = patch_delete_req(debug, sys.argv[2:])
        elif action == "commit":
            rc = patch_commit_req(debug, sys.argv[2:])
        elif action == "query":
            rc = patch_query_req(debug, sys.argv[2:])
        elif action == "query-hosts":
            rc = patch_query_hosts_req(debug, sys.argv[2:])
        elif action == "show":
            rc = patch_show_req(debug, sys.argv[2:])
        elif action == "what-requires":
            what_requires(debug, sys.argv[2:])
        elif action == "query-dependencies":
            query_dependencies(debug, sys.argv[2:])
        elif action == "host-install":
            rc = host_install(debug, sys.argv[2:])
        elif action == "host-install-async":
            rc = host_install_async(debug, sys.argv[2:])
        elif action == "drop-host":
            rc = drop_host(debug, sys.argv[2:])
        elif action == "upload-dir":
            rc = patch_upload_dir_req(debug, sys.argv[2:])
        elif action == "install-local":
            rc = patch_install_local(debug, sys.argv[2:])
        elif action == "init-release":
            rc = patch_init_release(debug, sys.argv[2:])
        elif action == "del-release":
            rc = patch_del_release(debug, sys.argv[2:])
        elif action == "completion":
            rc = completion_opts(sys.argv[2:])
        else:
            print_help()

    exit(rc)
