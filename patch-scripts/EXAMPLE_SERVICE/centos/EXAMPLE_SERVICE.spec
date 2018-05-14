Name: EXAMPLE_SERVICE
Summary: TIS In-Service Patch Scripts Example that supports systemd reload
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: windriver
Group: base
Packager: Wind River <info@windriver.com>
Source0: service-process-restart

%install
    install -Dp -m 700 %{S:0} %{buildroot}%{_patch_scripts}/%{name}

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

