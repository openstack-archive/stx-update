Summary: TIS Platform Patching
Name: cgcs-patch
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown
Source0: %{name}-%{version}.tar.gz
Source1: LICENSE

BuildRequires: python-setuptools
BuildRequires: python2-pip
BuildRequires: python2-wheel
BuildRequires: systemd-units
BuildRequires: systemd-devel
Requires: python-devel
Requires: /bin/bash

%description
TIS Platform Patching

%define pythonroot           /usr/lib64/python2.7/site-packages

%define debug_package %{nil}

%prep
%setup

%build
%{__python} setup.py build
%py2_build_wheel

%install
%{__python} setup.py install --root=$RPM_BUILD_ROOT \
                             --install-lib=%{pythonroot} \
                             --prefix=/usr \
                             --install-data=/usr/share \
                             --single-version-externally-managed
mkdir -p $RPM_BUILD_ROOT/wheels
install -m 644 dist/*.whl $RPM_BUILD_ROOT/wheels/

    install -m 755 -d %{buildroot}%{_sbindir}
    install -m 755 -d %{buildroot}%{_sysconfdir}/bash_completion.d
    install -m 755 -d %{buildroot}%{_sysconfdir}/goenabled.d
    install -m 755 -d %{buildroot}%{_sysconfdir}/init.d
    install -m 755 -d %{buildroot}%{_sysconfdir}/logrotate.d
    install -m 755 -d %{buildroot}%{_sysconfdir}/patching
    install -m 700 -d %{buildroot}%{_sysconfdir}/patching/patch-scripts
    install -m 755 -d %{buildroot}%{_sysconfdir}/pmon.d
    install -m 755 -d %{buildroot}%{_unitdir}


    install -m 500 ${RPM_BUILD_DIR}/bin/sw-patch-agent \
        %{buildroot}%{_sbindir}/sw-patch-agent
    install -m 500 ${RPM_BUILD_DIR}/bin/sw-patch-controller-daemon \
        %{buildroot}%{_sbindir}/sw-patch-controller-daemon
    install -m 555 ${RPM_BUILD_DIR}/bin/sw-patch \
        %{buildroot}%{_sbindir}/sw-patch

    install -m 555 ${RPM_BUILD_DIR}/bin/rpm-audit \
        %{buildroot}%{_sbindir}/rpm-audit

    install -m 500 ${RPM_BUILD_DIR}/bin/sw-patch-controller-daemon-init.sh \
        %{buildroot}%{_sysconfdir}/init.d/sw-patch-controller-daemon
    install -m 500 ${RPM_BUILD_DIR}/bin/sw-patch-agent-init.sh \
        %{buildroot}%{_sysconfdir}/init.d/sw-patch-agent

    install -m 600 ${RPM_BUILD_DIR}/bin/patching.conf \
        %{buildroot}%{_sysconfdir}/patching/patching.conf
    install -m 644 ${RPM_BUILD_DIR}/bin/policy.json \
        %{buildroot}%{_sysconfdir}/patching/policy.json

    install -m 444 ${RPM_BUILD_DIR}/bin/pmon-sw-patch-controller-daemon.conf \
        %{buildroot}%{_sysconfdir}/pmon.d/sw-patch-controller-daemon.conf
    install -m 444 ${RPM_BUILD_DIR}/bin/pmon-sw-patch-agent.conf \
        %{buildroot}%{_sysconfdir}/pmon.d/sw-patch-agent.conf

    install -m 444 ${RPM_BUILD_DIR}/bin/*.service %{buildroot}%{_unitdir}

    install -m 444 ${RPM_BUILD_DIR}/bin/sw-patch.completion %{buildroot}%{_sysconfdir}/bash_completion.d/sw-patch

    install -m 400 ${RPM_BUILD_DIR}/bin/patch-functions \
        %{buildroot}%{_sysconfdir}/patching/patch-functions

    install -D -m 444 ${RPM_BUILD_DIR}/bin/patch-tmpdirs.conf \
        %{buildroot}%{_tmpfilesdir}/patch-tmpdirs.conf
    install -m 500 ${RPM_BUILD_DIR}/bin/run-patch-scripts \
        %{buildroot}%{_sbindir}/run-patch-scripts

    install -m 500 ${RPM_BUILD_DIR}/bin/sw-patch-controller-daemon-restart \
        %{buildroot}%{_sbindir}/sw-patch-controller-daemon-restart
    install -m 500 ${RPM_BUILD_DIR}/bin/sw-patch-agent-restart \
        %{buildroot}%{_sbindir}/sw-patch-agent-restart

    install -m 500 ${RPM_BUILD_DIR}/bin/sw-patch-init.sh \
        %{buildroot}%{_sysconfdir}/init.d/sw-patch
    install -m 500 ${RPM_BUILD_DIR}/bin/sw-patch-controller-init.sh \
        %{buildroot}%{_sysconfdir}/init.d/sw-patch-controller

    install -m 555 ${RPM_BUILD_DIR}/bin/patch_check_goenabled.sh \
        %{buildroot}%{_sysconfdir}/goenabled.d/patch_check_goenabled.sh

    install -m 444 ${RPM_BUILD_DIR}/bin/patching.logrotate \
        %{buildroot}%{_sysconfdir}/logrotate.d/patching

    install -m 500 ${RPM_BUILD_DIR}/bin/upgrade-start-pkg-extract \
        %{buildroot}%{_sbindir}/upgrade-start-pkg-extract

%clean
rm -rf $RPM_BUILD_ROOT 

%package -n cgcs-patch-controller
Summary: TIS Platform Patching
Group: base
Requires: /usr/bin/env
Requires: /bin/sh
Requires: requests-toolbelt
Requires: createrepo
Requires(post): /usr/bin/env
Requires(post): /bin/sh

%description -n cgcs-patch-controller
TIS Platform Patching

%post -n cgcs-patch-controller
/usr/bin/systemctl enable sw-patch-controller.service
/usr/bin/systemctl enable sw-patch-controller-daemon.service


%package -n cgcs-patch-agent
Summary: TIS Platform Patching
Group: base
Requires: /usr/bin/env
Requires: /bin/sh
Requires(post): /usr/bin/env
Requires(post): /bin/sh

%description -n cgcs-patch-agent
TIS Platform Patching

%post -n cgcs-patch-agent
/usr/bin/systemctl enable sw-patch-agent.service

%post
/usr/bin/systemctl enable sw-patch.service

%files
%license ../LICENSE
%defattr(-,root,root,-)
%{pythonroot}/cgcs_patch
%{pythonroot}/cgcs_patch-*.egg-info
%{_sbindir}/rpm-audit
%config(noreplace) %{_sysconfdir}/patching/policy.json
%config(noreplace) %{_sysconfdir}/patching/patching.conf
%dir %{_sysconfdir}/patching/patch-scripts
%{_sysconfdir}/patching/patch-functions
%{_tmpfilesdir}/patch-tmpdirs.conf
%{_sbindir}/run-patch-scripts
%{_sysconfdir}/init.d/sw-patch
%{_unitdir}/sw-patch.service
%{_sysconfdir}/goenabled.d/patch_check_goenabled.sh
%{_sysconfdir}/logrotate.d/patching

%files -n cgcs-patch-controller
%defattr(-,root,root,-)
%{_sbindir}/sw-patch
%{_sbindir}/sw-patch-controller-daemon
%{_sbindir}/sw-patch-controller-daemon-restart
%{_sbindir}/upgrade-start-pkg-extract
%{_sysconfdir}/pmon.d/sw-patch-controller-daemon.conf
%{_sysconfdir}/init.d/sw-patch-controller-daemon
%{_unitdir}/sw-patch-controller-daemon.service
%{_sysconfdir}/bash_completion.d/sw-patch
%{_sysconfdir}/init.d/sw-patch-controller
%{_unitdir}/sw-patch-controller.service

%files -n cgcs-patch-agent
%defattr(-,root,root,-)
%{_sbindir}/sw-patch-agent
%{_sbindir}/sw-patch-agent-restart
%{_sysconfdir}/pmon.d/sw-patch-agent.conf
%{_sysconfdir}/init.d/sw-patch-agent
%{_unitdir}/sw-patch-agent.service

%package wheels
Summary: %{module_name} wheels

%description wheels
Contains python wheels for %{module_name}

%files wheels
/wheels/*
