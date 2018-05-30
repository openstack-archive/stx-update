Summary: Patch alarm management
Name: patch-alarm
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown
Source0: %{name}-%{version}.tar.gz

%define debug_package %{nil}

BuildRequires: python-setuptools
Requires: python-devel
Requires: /bin/bash

%description
TIS Platform Patching

%define pythonroot           /usr/lib64/python2.7/site-packages

%prep
%setup

%build
%{__python} setup.py build

%install
%{__python} setup.py install --root=$RPM_BUILD_ROOT \
                             --install-lib=%{pythonroot} \
                             --prefix=/usr \
                             --install-data=/usr/share \
                             --single-version-externally-managed

    install -m 755 -d %{buildroot}%{_bindir}
    install -m 755 -d %{buildroot}%{_sysconfdir}/init.d

    install -m 700 ${RPM_BUILD_DIR}/scripts/bin/patch-alarm-manager \
        %{buildroot}%{_bindir}/patch-alarm-manager

    install -m 700 ${RPM_BUILD_DIR}/scripts/init.d/patch-alarm-manager \
        %{buildroot}%{_sysconfdir}/init.d/patch-alarm-manager

%clean
rm -rf $RPM_BUILD_ROOT 


%files
%defattr(-,root,root,-)
%doc LICENSE
%{pythonroot}/patch_alarm
%{pythonroot}/patch_alarm-*.egg-info
"%{_bindir}/patch-alarm-manager"
"%{_sysconfdir}/init.d/patch-alarm-manager"

