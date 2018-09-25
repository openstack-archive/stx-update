====================================================
Patching API v1
====================================================

Manage the patching of hosts with the Titanium Cloud Patching API. This
includes upload, application, installation, removal, deletion, and
querying.

The typical port used for the Patching REST API is 15491. However,
proper technique would be to look up the patching service endpoint in
Keystone.

-------------
API versions
-------------

******************************************************************
Lists information about all Titanium Cloud Patching API versions
******************************************************************

.. rest_method:: GET /

**Normal response codes**

200, 300

**Error response codes**

serviceUnavailable (503), badRequest (400), unauthorized (401),
forbidden (403), badMethod (405), overLimit (413), itemNotFound (404)

::

   "Titanium Cloud Patching API, Available versions: /v1"

This operation does not accept a request body.

--------
Patches
--------

The patches used by the patching service to update individual hosts in
the cloud.

******************************************
Lists all patches in the patching system
******************************************

.. rest_method:: GET /v1/query

Supported query values are ``all``, ``available``, or ``applied``.

**Normal response codes**

200

**Error response codes**

serviceUnavailable (503), badRequest (400), unauthorized (401),
forbidden (403), badMethod (405), overLimit (413), itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "pd (Optional)", "plain", "xsd:list", "The list of patches present in the patching system."
   "patch (Optional)", "plain", "xsd:list", "A patch present in the patching system."
   "status (Optional)", "plain", "xsd:string", "The status of the patch."
   "sw_version (Optional)", "plain", "xsd:string", "The software version for which the patch is intended."
   "install_instructions (Optional)", "plain", "xsd:string", "Instructions on how to install the patch."
   "description (Optional)", "plain", "xsd:string", "The description of any updates present in this patch."
   "warnings (Optional)", "plain", "xsd:string", "Any warnings associated with the usage of the patch."
   "summary (Optional)", "plain", "xsd:string", "A brief summary of the patch."
   "repostate (Optional)", "plain", "xsd:string", "Whether this patch`s content`s have been added to the patching repository; ``Applied`` or ``Available``."
   "patchstate (Optional)", "plain", "xsd:string", "The state of this patch`s application to hosts; ``Available``, ``Partial-Apply``, ``Applied``, or ``Partial-Removed``."
   "requires (Optional)", "plain", "xsd:list", "A list of patch ids required for this patch to be installed."

::

   {
       'pd':{
           'TS_15.12_PATCH_0002':{
                'status': 'REL',
                'sw_version': '15.12',
                'patchstate': 'Partial-Remove',
                'description': 'Fixes the following Issues:\n   compute-4 and storage-0 multiple resets after DOR\n  Alarms bogged down for 1 hour after DOR\n   Guest Heartbeat cannot be enabled from horizon',
                'warnings': '',
                'summary': 'TS_15.12 Patch 0002',
                'repostate': 'Available',
                'install_instructions': '',
                'requires': []
           },
           'TS_15.12_PATCH_0001':{
                'status': 'REL',
                'sw_version': '15.12',
                'patchstate': 'Applied',
                'description': 'Fixes the following Issues:\n   hbsClient instrumentation can cause server reset or hang after long soaks',
                'warnings': '',
                'summary': 'TS_15.12 Patch 0001',
                'repostate': 'Applied',
                'install_instructions': 'No special install instructions.',
                'requires': []
           }
       }
   }

This operation does not accept a request body.

***************************************************
Shows detailed information about a specific patch
***************************************************

.. rest_method:: GET /v1/show/{patch_id}

**Normal response codes**

200

**Error response codes**

serviceUnavailable (503), badRequest (400), unauthorized (401),
forbidden (403), badMethod (405), overLimit (413), itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "contents (Optional)", "plain", "xsd:list", "The RPMs contained within the patch."
   "patch (Optional)", "plain", "xsd:list", "A patch present in the patching system."
   "pkg (Optional)", "plain", "xsd:string", "A package included in a patch."
   "error (Optional)", "plain", "xsd:string", "Any errors associated with the patch."
   "metadata (Optional)", "plain", "xsd:list", "Metadata associated with the patch."
   "status (Optional)", "plain", "xsd:string", "The status of the patch."
   "sw_version (Optional)", "plain", "xsd:string", "The software version for which the patch is intended."
   "install_instructions (Optional)", "plain", "xsd:string", "Instructions on how to install the patch."
   "description (Optional)", "plain", "xsd:string", "The description of any updates present in this patch."
   "warnings (Optional)", "plain", "xsd:string", "Any warnings associated with the usage of the patch."
   "summary (Optional)", "plain", "xsd:string", "A brief summary of the patch."
   "repostate (Optional)", "plain", "xsd:string", "Whether the patch content has been added to the patching repository; ``Applied`` or ``Available``."
   "patchstate (Optional)", "plain", "xsd:string", "The state of the patch regarding application to hosts; ``Available``, ``Partial-Apply``, ``Applied``, or ``Partial-Removed``."
   "requires (Optional)", "plain", "xsd:list", "A list of patch ids required for this patch to be installed."

::

   {
       "contents": {
           "TS_15.12_PATCH_0002": [
               "python-horizon-2013.2.3-r118.x86_64.rpm",
               "sysinv-1.0-r81.x86_64.rpm"
           ]
       },
       "error": "",
       "metadata": {
           "TS_15.12_PATCH_0002": {
               "description": "Fixes the following Issues:\n   compute-4 and storage-0 multiple resets after DOR",
               "install_instructions": "",
               "patchstate": "Partial-Remove",
               "repostate": "Available",
               "requires": [],
               "status": "DEV",
               "summary": "TS_15.12 Patch 0002",
               "sw_version": "15.12",
               "warnings": ""
           }
       }
   }

This operation does not accept a request body.

****************************************
Uplaods a patch to the patching system
****************************************

.. rest_method:: POST /v1/upload

Note that only one patch may be added per request

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "info (Optional)", "plain", "xsd:string", "Any information regarding the request processing."
   "warning (Optional)", "plain", "xsd:string", "Any warnings generated during the request processing."
   "error (Optional)", "plain", "xsd:string", "Any errors generated during the request processing."

::

   {
       "info": "TS_15.12_PATCH_0001 is now available\n",
       "warning": "",
       "error": ""
   }

*************************************************
Applies a patch which is in the Available state
*************************************************

.. rest_method:: POST /v1/apply/{patch_id}

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "info (Optional)", "plain", "xsd:string", "Any information regarding the request processing."
   "warning (Optional)", "plain", "xsd:string", "Any warnings generated during the request processing."
   "error (Optional)", "plain", "xsd:string", "Any errors generated during the request processing."

::

   {
       "info": "TS_15.12_PATCH_0001 has been applied\n",
       "warning": "",
       "error": ""
   }

This operation does not accept a request body.

***********************************************
Removes a patch which is in the Applied state
***********************************************

.. rest_method:: POST /v1/remove/{patch_id}

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "info (Optional)", "plain", "xsd:string", "Any information regarding the request processing."
   "warning (Optional)", "plain", "xsd:string", "Any warnings generated during the request processing."
   "error (Optional)", "plain", "xsd:string", "Any errors generated during the request processing."

::

   {
       "info": "TS_15.12_PATCH_0001 has been removed from the repo\n",
       "warning": "",
       "error": ""
   }

This operation does not accept a request body.

*************************************************
Deletes a patch which is in the Available state
*************************************************

.. rest_method:: POST /v1/delete/{patch_id}

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "info (Optional)", "plain", "xsd:string", "Any information regarding the request processing."
   "warning (Optional)", "plain", "xsd:string", "Any warnings generated during the request processing."
   "error (Optional)", "plain", "xsd:string", "Any errors generated during the request processing."

::

   {
       "info": "TS_15.12_PATCH_0001 has been deleted\n",
       "warning": "",
       "error": ""
   }

This operation does not accept a request body.

------
Hosts
------

Hosts are the physical hosts or servers for the system as viewed by the
patching service.

********************************************************
Lists all host entities and their patching information
********************************************************

.. rest_method:: GET /v1/query_hosts

**Normal response codes**

200

**Error response codes**

serviceUnavailable (503), badRequest (400), unauthorized (401),
forbidden (403), badMethod (405), overLimit (413), itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "data (Optional)", "plain", "xsd:list", "The list of host entities."
   "requires_reboot (Optional)", "plain", "xsd:boolean", "Indicates whether the host requires a reboot."
   "nodetype (Optional)", "plain", "xsd:string", "The type of the host; ``controller``, ``compute`` or ``storage``."
   "missing_pkgs (Optional)", "plain", "xsd:list", "The list of packages missing from this host."
   "ip (Optional)", "plain", "xsd:string", "The ip address of the host."
   "hostname (Optional)", "plain", "xsd:string", "The name of the host."
   "installed (Optional)", "plain", "xsd:list", "The packages installed on this host by the patching system."
   "secs_since_ack (Optional)", "plain", "xsd:integer", "The number of seconds since the host last reported its status."
   "patch_failed (Optional)", "plain", "xsd:boolean", "Indicates whether a patch installation has failed on the host."
   "stale_details (Optional)", "plain", "xsd:boolean", "Indicates whether the details of this host are out of date."
   "patch_current (Optional)", "plain", "xsd:boolean", "Indicates whether the host is up to date regarding patches."
   "to_remove (Optional)", "plain", "xsd:list", "The list of packages that are to be removed from the host."
   "sw_version (Optional)", "plain", "xsd:string", "The software version running on the host."
   "state (Optional)", "plain", "xsd:string", "The state of the patch agent: <ul><li>``idle``: The patch agent is in an idle state, ready for installation requests. </li><li>``installing``: The patch agent is installing or removing patches as needed. </li><li>``install-failed``: The installation failed on the host. </li><li>``install-rejected``: The host is unlocked. Lock the node, and run the command again. </li></ul>"
   "subfunctions (Optional)", "plain", "xsd:list", "The list of host subfunctions."

::

   {
       'data': [
           {
                'hostname': 'controller-0',
                'nodetype': 'controller',
                'patch_failed': False,
                'ip': u'192.168.204.3',
                'requires_reboot': False,
                'installed': {},
                'secs_since_ack': 18,
                'missing_pkgs': [],
                'patch_current': True,
                'stale_details': False,
                'to_remove': [],
                'state': 'idle',
                'subfunctions': [
                   'controller'
                ],
                'sw_version': '15.12'
           },
           {    'hostname': 'compute-0',
                'nodetype': 'compute',
                'patch_failed': False,
                'ip': u'192.168.204.27',
                'requires_reboot': False,
                'installed': {},
                'secs_since_ack': 18,
                'missing_pkgs': [],
                'patch_current': True,
                'stale_details': False,
                'to_remove': [],
                'state': 'idle',
                'subfunctions': [
                   'compute'
                ],
                'sw_version': '15.12'
           }
       ]
   }

This operation does not accept a request body.

************************************************************
Trigger an asynchronous host install on the specified host
************************************************************

.. rest_method:: POST /v1/host_install_async/{hostname}

The host must be in the Locked-Disabled-Online state.

**Normal response codes**

200

**Error response codes**

serviceUnavailable (503), badRequest (400), unauthorized (401),
forbidden (403), badMethod (405), overLimit (413), badMediaType (415)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "info (Optional)", "plain", "xsd:string", "Any information regarding the request processing."
   "warning (Optional)", "plain", "xsd:string", "Any warnings generated during the request processing."
   "error (Optional)", "plain", "xsd:string", "Any errors generated during the request processing."

::

   {
       "info": "Patch installation request sent to compute-0.\n",
       "warning": "",
       "error": ""
   }

This operation does not accept a request body.
