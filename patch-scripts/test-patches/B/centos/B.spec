Name: B
Summary: TIS Reboot-Required Patch RPM Example
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>

%description
%{summary}

%files

%post
touch /var/run/node_is_patched_rr
exit 0

%preun
touch /var/run/node_is_patched_rr
exit 0

