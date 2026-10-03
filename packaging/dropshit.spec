Name:           dropshit
Version:        0.1.4
Release:        1%{?dist}
Summary:        Rust terminal game region selector with HTTPS latency estimates
License:        GPL-3.0-only
URL:            https://github.com/DurkaEbanaya/dropshit
Source0:        dropshit-linux-%{version}.tar.gz
BuildArch:      x86_64
%global debug_package %{nil}
Requires:       curl
%if 0%{?fedora}
Requires:       iproute
%else
Requires:       iproute2
%endif
Requires:       polkit
Requires:       (nftables >= 1.0.9 or iptables)

%description
Independent Rust TUI for regional HTTPS latency estimates and per-user
Overwatch UDP game-region selection using nftables or iptables.

%prep
%setup -q -n dropshit-linux-%{version}

%build
# The binaries were built on Debian 12; the source bundle includes Cargo.lock.

%install
sh packaging/stage.sh %{buildroot} bin/dropshit bin/dropshit-helper

%post
systemctl daemon-reload >/dev/null 2>&1 || :
systemctl enable dropshit-restore.service >/dev/null 2>&1 || :

%preun
if [ "$1" = 0 ]; then
    /bin/sh /usr/share/dropshit/clear-installed-rules.sh
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || :

%files
/usr/share/licenses/dropshit/LICENSE
/usr/share/doc/dropshit/README.md
/usr/bin/dropshit
/usr/libexec/dropshit-helper
/usr/share/dropshit/clear-installed-rules.sh
/usr/share/polkit-1/actions/io.github.durkaebanaya.dropshit.policy
/usr/lib/systemd/system/dropshit-restore.service
%dir /etc/dropshit
%config(noreplace) /etc/dropshit/firewall.json
%dir /var/lib/dropshit
