Name: post-update-scripts
Summary: In-Service Patch Scripts
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: StarlingX
Source0: update-config-file

%install
    install -Dp -m 700 %{S:0} %{buildroot}%{_patch_scripts}/%{name}
    install -d  -m 755 %{buildroot}%{_runtime_patch_scripts}

%description
%{summary}

%files
%defattr(-,root,root,-)
%{_patch_scripts}/*

%post
cp -f %{_patch_scripts}/%{name} %{_runtime_patch_scripts}/
exit 0

%preun
cp -f %{_patch_scripts}/%{name} %{_runtime_patch_scripts}/
exit 0

