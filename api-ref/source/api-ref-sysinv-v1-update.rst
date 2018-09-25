====================================================
Update API v1
====================================================

Manage physical servers with the Titanium System Inventory API. This
includes inventory collection and configuration of nodes, ports,
interfaces, CPUs, disks, partitions, memory, and sensors. The API also
supports configuration of the cloud's SNMP interface.

The typical port used for the SysInv REST API is 6385. However, proper
technique would be to look up the sysinv service endpoint in Keystone.

-------------
API versions
-------------

**************************************************************************
Lists information about all Titanium Cloud System Inventory API versions
**************************************************************************

.. rest_method:: GET /

**Normal response codes**

200, 300

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

::

   {
      "default_version":{
         "id":"v1",
         "links":[
            {
               "href":"http://128.224.150.54:6385/v1/",
               "rel":"self"
            }
         ]
      },
      "versions":[
         {
            "id":"v1",
            "links":[
               {
                  "href":"http://128.224.150.54:6385/v1/",
                  "rel":"self"
               }
            ]
         }
      ],
      "description":"Titanium Cloud System API allows for the management of physical servers.  This includes inventory collection and configuration of hosts, ports, interfaces, CPUs, disk, memory, and system configuration.  The API also supports the configuration of the cloud's SNMP interface. ",
      "name":"Titanium SysInv API"
   }

This operation does not accept a request body.

*******************************************
Shows details for System Inventory API v1
*******************************************

.. rest_method:: GET /v1

**Normal response codes**

200, 203

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

::

   {
      "ihosts":[
         {
            "href":"http://128.224.150.54:6385/v1/ihosts/",
            "rel":"self"
         },
         {
            "href":"http://128.224.150.54:6385/ihosts/",
            "rel":"bookmark"
         }
      ],
      "media_types":[
         {
            "base":"application/json",
            "type":"application/vnd.openstack.sysinv.v1+json"
         }
      ],
      "links":[
         {
            "href":"http://128.224.150.54:6385/v1/",
            "rel":"self"
         },
         {
            "href":"http://www.windriver.com/developer/sysinv/dev/api-spec-v1.html",
            "type":"text/html",
            "rel":"describedby"
         }
      ],
      "inode":[
         {
            "href":"http://128.224.150.54:6385/v1/inode/",
            "rel":"self"
         },
         {
            "href":"http://128.224.150.54:6385/inode/",
            "rel":"bookmark"
         }
      ],
      "imemory":[
         {
            "href":"http://128.224.150.54:6385/v1/imemory/",
            "rel":"self"
         },
         {
            "href":"http://128.224.150.54:6385/imemory/",
            "rel":"bookmark"
         }
      ],
      "idns":[
         {
            "href":"http://128.224.150.54:6385/v1/idns/",
            "rel":"self"
         },
         {
            "href":"http://128.224.150.54:6385/idns/",
            "rel":"bookmark"
         }
      ],
      "iuser":[
         {
            "href":"http://128.224.150.54:6385/v1/iuser/",
            "rel":"self"
         },
         {
            "href":"http://128.224.150.54:6385/iuser/",
            "rel":"bookmark"
         }
      ],
      "itrapdest":[
         {
            "href":"http://128.224.150.54:6385/v1/itrapdest/",
            "rel":"self"
         },
         {
            "href":"http://128.224.150.54:6385/itrapdest/",
            "rel":"bookmark"
         }
      ],
      "istorconfig":[
         {
            "href":"http://128.224.150.54:6385/v1/istorconfig/",
            "rel":"self"
         },
         {
            "href":"http://128.224.150.54:6385/istorconfig/",
            "rel":"bookmark"
         }
      ],
      "iextoam":[
         {
            "href":"http://128.224.150.54:6385/v1/iextoam/",
            "rel":"self"
         },
         {
            "href":"http://128.224.150.54:6385/iextoam/",
            "rel":"bookmark"
         }
      ],
      "intp":[
         {
            "href":"http://128.224.150.54:6385/v1/intp/",
            "rel":"self"
         },
         {
            "href":"http://128.224.150.54:6385/intp/",
            "rel":"bookmark"
         }
      ],
      "isystems":[
         {
            "href":"http://128.224.150.54:6385/v1/isystems/",
            "rel":"self"
         },
         {
            "href":"http://128.224.150.54:6385/isystems/",
            "rel":"bookmark"
         }
      ],
      "iprofile":[
         {
            "href":"http://128.224.150.54:6385/v1/iprofile/",
            "rel":"self"
         },
         {
            "href":"http://128.224.150.54:6385/iprofile/",
            "rel":"bookmark"
         }
      ],
      "icpu":[
         {
            "href":"http://128.224.150.54:6385/v1/icpu/",
            "rel":"self"
         },
         {
            "href":"http://128.224.150.54:6385/icpu/",
            "rel":"bookmark"
         }
      ],
      "icommunity":[
         {
            "href":"http://128.224.150.54:6385/v1/icommunity/",
            "rel":"self"
         },
         {
            "href":"http://128.224.150.54:6385/icommunity/",
            "rel":"bookmark"
         }
      ],
      "iinfra":[
         {
            "href":"http://128.224.150.54:6385/v1/iinfra/",
            "rel":"self"
         },
         {
            "href":"http://128.224.150.54:6385/iinfra/",
            "rel":"bookmark"
         }
      ],
      "id":"v1",
   }

This operation does not accept a request body.

--------------
System Health
--------------

These APIs allow the display of the system health.

***************************************
Shows the health status of the system
***************************************

.. rest_method:: GET /v1/health

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

::

   "System Health:\nAll hosts are provisioned: [OK]\nAll hosts are unlocked/enabled: [OK]\nAll hosts have current configurations: [OK]\nAll hosts are patch current: [OK]\nNo alarms: [OK]\n"

This operation does not accept a request body.

************************************************************************
Shows the health status of the system with requirements for an upgrade
************************************************************************

.. rest_method:: GET /v1/health/upgrade

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

::

   "System Health:\nAll hosts are provisioned: [OK]\nAll hosts are unlocked/enabled: [OK]\nAll hosts have current configurations: [OK]\nAll hosts are patch current: [OK]\nNo alarms: [OK]\nRequired patches are applied: [OK]\nLicense valid for upgrade: [OK]\n"

This operation does not accept a request body.

---------------
Software Loads
---------------

These APIs allow the display and configuration of the software loads.

***************************************
List of loads installed on the system
***************************************

.. rest_method:: GET /v1/loads

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "uuid (Optional)", "plain", "csapi:UUID", "The UUID of this load."
   "state (Optional)", "plain", "xsd:string", "The state of the software load."
   "id (Optional)", "plain", "xsd:integer", "The id of the load."
   "required_patches (Optional)", "plain", "xsd:string", "A list of patches required before the system can upgrade to this load."
   "software_version (Optional)", "plain", "xsd:string", "The software version of this load."
   "compatible_version (Optional)", "plain", "xsd:string", "The software version this load can be upgraded from."

::

   {
     "loads": [
       {
         "required_patches": "N/A",
         "uuid": "924a83a1-3d86-4b67-80fe-decf4c60ac78",
         "software_version": "16.10",
         "id": 1,
         "state": "active",
         "compatible_version": "N/A"
       },
       {
         "required_patches": "",
         "uuid": "f57e2b86-9047-443f-be39-d3c8aa47222b",
         "software_version": "18.03",
         "id": 2,
         "state": "imported",
         "compatible_version": "16.10"
       }
     ]
   }

This operation does not accept a request body.

********************************
Shows the attributes of a load
********************************

.. rest_method:: GET /v1/loads/​{load_id}​

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "load_id", "URI", "csapi:UUID", "The unique identifier of the load."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "uuid (Optional)", "plain", "csapi:UUID", "The UUID of this load."
   "state (Optional)", "plain", "xsd:string", "The state of the software load."
   "id (Optional)", "plain", "xsd:integer", "The id of the load."
   "required_patches (Optional)", "plain", "xsd:string", "A list of patches required before the system can upgrade to this load."
   "software_version (Optional)", "plain", "xsd:string", "The software version of this load."
   "compatible_version (Optional)", "plain", "xsd:string", "The software version this load can be upgraded from."

::

   {
     "required_patches": "N/A",
     "uuid": "924a83a1-3d86-4b67-80fe-decf4c60ac78",
     "software_version": "16.10",
     "created_at": "2016-11-03T17:16:15.212760+00:00",
     "updated_at": null,
     "id": 1,
     "state": "active",
     "compatible_version": "N/A"
   }

This operation does not accept a request body.

****************
Deletes a load
****************

.. rest_method:: DELETE /v1/loads/​{load_id}​

**Normal response codes**

204

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "load_id", "URI", "csapi:UUID", "The unique identifier of the load."

This operation does not accept a request body.

***************
Import a load
***************

.. rest_method:: POST /v1/loads/import_load

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "path_to_iso (Optional)", "plain", "xsd:string", "The full system path of the iso."
   "path_to_signature (Optional)", "plain", "xsd:string", "The full system path of the detached signature for the iso."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "uuid (Optional)", "plain", "csapi:UUID", "The UUID of this load."
   "state (Optional)", "plain", "xsd:string", "The state of the software load."
   "id (Optional)", "plain", "xsd:integer", "The id of the load."
   "required_patches (Optional)", "plain", "xsd:string", "A list of patches required before the system can upgrade to this load."
   "software_version (Optional)", "plain", "xsd:string", "The software version of this load."
   "compatible_version (Optional)", "plain", "xsd:string", "The software version this load can be upgraded from."

::

   {
      "path_to_iso": "/home/wrsroot/bootimage.iso",
      "path_to_signature": "/home/wrsroot/bootimage.sig"
   }

::

   {
     "required_patches": "",
     "uuid": "f57e2b86-9047-443f-be39-d3c8aa47222b",
     "software_version": "18.03",
     "created_at": "2017-03-07T16:29:27+00:00",
     "updated_at": null,
     "id": 2,
     "state": "importing",
     "compatible_version": "16.10"
   }

-----------------
Software Upgrade
-----------------

These APIs allow the display and configuration of the software upgrade.

********************************
Shows the status of the upgrade
********************************

.. rest_method:: GET /v1/upgrade

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
itemNotFound (404)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "state (Optional)", "plain", "xsd:string", "The state of the software upgrade."
   "from_release (Optional)", "plain", "xsd:string", "The software version the system is upgrading from."
   "to_release (Optional)", "plain", "xsd:string", "The software version the system is upgrading to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."

::

   {
     "upgrades": [
       {
         "state": "activating",
         "to_release": "16.10",
         "uuid": "d0a6a564-0539-4f76-ab5f-2213e20193fe",
         "links": [
           {
             "href": "http://10.10.10.2:6385/v1/upgrades/d0a6a564-0539-4f76-ab5f-2213e20193fe",
             "rel": "self"
           },
           {
             "href": "http://10.10.10.2:6385/upgrades/d0a6a564-0539-4f76-ab5f-2213e20193fe",
             "rel": "bookmark"
           }
         ],
         "from_release": "15.12"
       }
     ]
   }

This operation does not accept a request body.

********************
Starts the upgrade
********************

.. rest_method:: POST /v1/upgrade

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413),
badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "force (Optional)", "plain", "xsd:boolean", "Set to true to ignore minor and warning alarms."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "state (Optional)", "plain", "xsd:string", "The state of the software upgrade."
   "from_load (Optional)", "plain", "xsd:string", "The id of the load the system is upgrading from."
   "from_release (Optional)", "plain", "xsd:string", "The software version the system is upgrading from."
   "to_load (Optional)", "plain", "xsd:string", "The id of the load the system is upgrading to."
   "to_release (Optional)", "plain", "xsd:string", "The software version the system is upgrading to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {"force": false}

::

   {
     "uuid": "452298f3-dfd2-495f-9a4e-f611a03b93e6",
     "links": [
       {
         "href": "http://10.10.10.2:6385/v1/upgrades/452298f3-dfd2-495f-9a4e-f611a03b93e6",
         "rel": "self"
       },
       {
         "href": "http://10.10.10.2:6385/upgrades/452298f3-dfd2-495f-9a4e-f611a03b93e6",
         "rel": "bookmark"
       }
     ],
     "created_at": "2017-03-07T16:35:36.662098+00:00",
     "from_load": 1,
     "from_release": "16.10",
     "updated_at": null,
     "state": "starting",
     "to_load": 2,
     "to_release": "18.03",
     "id": 1
   }

*******************************
Activate or abort the upgrade
*******************************

.. rest_method:: PATCH /v1/upgrade

**Normal response codes**

200

**Error response codes**

badMediaType (415)

**Request parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "state (Optional)", "plain", "xsd:string", "Change the state of the upgrade: Valid values are: ``aborting``, or ``activation-requested``."

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "state (Optional)", "plain", "xsd:string", "The state of the software upgrade."
   "from_load (Optional)", "plain", "xsd:string", "The id of the load the system is upgrading from."
   "from_release (Optional)", "plain", "xsd:string", "The software version the system is upgrading from."
   "to_load (Optional)", "plain", "xsd:string", "The id of the load the system is upgrading to."
   "to_release (Optional)", "plain", "xsd:string", "The software version the system is upgrading to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   [{"path": "/state", "value": "activation-requested", "op": "replace"}]

::

   {
     "uuid": "d0a6a564-0539-4f76-ab5f-2213e20193fe",
     "links": [
       {
         "href": "http://10.10.10.2:6385/v1/upgrades/d0a6a564-0539-4f76-ab5f-2213e20193fe",
         "rel": "self"
       },
       {
         "href": "http://10.10.10.2:6385/upgrades/d0a6a564-0539-4f76-ab5f-2213e20193fe",
         "rel": "bookmark"
       }
     ],
     "created_at": "2017-02-27T17:10:40.033745+00:00",
     "from_load": 1,
     "from_release": "15.12",
     "updated_at": "2017-03-06T16:36:23.294777+00:00",
     "state": "activation-requested",
     "to_load": 2,
     "to_release": "16.10",
     "id": 1
   }

***********************************************************************************
Completes the upgrade. This can be done after the upgrade is activated or aborted
***********************************************************************************

.. rest_method:: DELETE /v1/upgrade

**Normal response codes**

200

**Error response codes**

computeFault (400, 500, ...), serviceUnavailable (503), badRequest (400),
unauthorized (401), forbidden (403), badMethod (405), overLimit (413)

**Response parameters**

.. csv-table::
   :header: "Parameter", "Style", "Type", "Description"
   :widths: 20, 20, 20, 60

   "state (Optional)", "plain", "xsd:string", "The state of the software upgrade."
   "from_load (Optional)", "plain", "xsd:string", "The id of the load the system is upgrading from."
   "from_release (Optional)", "plain", "xsd:string", "The software version the system is upgrading from."
   "to_load (Optional)", "plain", "xsd:string", "The id of the load the system is upgrading to."
   "to_release (Optional)", "plain", "xsd:string", "The software version the system is upgrading to."
   "uuid (Optional)", "plain", "csapi:UUID", "The universally unique identifier for this object."
   "links (Optional)", "plain", "xsd:list", "For convenience, resources contain links to themselves. This allows a client to easily obtain rather than construct resource URIs. The following types of link relations are associated with resources: a self link containing a versioned link to the resource, and a bookmark link containing a permanent link to a resource that is appropriate for long term storage."
   "created_at (Optional)", "plain", "xsd:dateTime", "The time when the object was created."
   "updated_at (Optional)", "plain", "xsd:dateTime", "The time when the object was last updated."

::

   {
     "uuid": "d0a6a564-0539-4f76-ab5f-2213e20193fe",
     "links": [
       {
         "href": "http://10.10.10.2:6385/v1/upgrades/d0a6a564-0539-4f76-ab5f-2213e20193fe",
         "rel": "self"
       },
       {
         "href": "http://10.10.10.2:6385/upgrades/d0a6a564-0539-4f76-ab5f-2213e20193fe",
         "rel": "bookmark"
       }
     ],
     "created_at": "2017-02-27T17:10:40.033745+00:00",
     "from_load": 1,
     "from_release": "15.12",
     "updated_at": "2017-03-06T17:51:43.906711+00:00",
     "state": "completing",
     "to_load": 2,
     "to_release": "16.10",
     "id": 1
   }

This operation does not accept a request body.






