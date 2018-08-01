Summary: Enable installation of developer patches
Name: enable-dev-patch
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown
Source0: dev_certificate_enable.bin

%description
Enables the installation of Titanium patches signed by developers

%prep

%build

%install
    install -m 755 -d %{buildroot}%{_sysconfdir}/pki/wrs
    install -m 444 %{SOURCE0} %{buildroot}%{_sysconfdir}/pki/wrs/dev_certificate_enable.bin

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_sysconfdir}/pki/wrs/dev_certificate_enable.bin

