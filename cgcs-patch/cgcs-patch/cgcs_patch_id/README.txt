Intended to run on a single build server.  Currently yow-cgts2-lx

# On other build servers
   mkdir -p /localdisk/designer/jenkins/bin
   cp patch_id_allocator_client.py /localdisk/designer/jenkins/bin
   

# On the intended server: e.g. yow-cgts2-lx
   mkdir -p /localdisk/designer/jenkins/bin
   cp *py /localdisk/designer/jenkins/bin/
   mkdir -p /localdisk/designer/jenkins/patch_ids
   sudo cp patch_id_allocator_server.conf /etc/init
   sudo initctl reload-configuration
   sudo start script

# Change to a different server
   edit patch_id_allocator_client.py
   change the line ...
       server = 'yow-cgts2-lx.wrs.com'
   
# TODO: 
   Need to back up the /localdisk/designer/jenkins/patch_ids directory 

# Quick test
   Point your browser at this url:
       http://yow-cgts2-lx:8888/get_patch_id

   expected result is:
       CGCS_None_PATCH_0000

   on each reload of the page, the number increments:
       CGCS_None_PATCH_0001
       CGCS_None_PATCH_0002
       ....
