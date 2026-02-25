%define name        raid-agent
%define version     1.0.4
%define release     1%{?dist}
%define install_dir /opt/raid-agent
%define config_dir  /etc/raid-agent
%define log_dir     /var/log/raid-agent
%define selinux_dir %{install_dir}/raid_agent/selinux

# Fallback for _unitdir if systemd-rpm-macros is not installed
%{!?_unitdir: %define _unitdir /usr/lib/systemd/system}

Name:           %{name}
Version:        %{version}
Release:        %{release}
Summary:        RAID Monitor Agent - collects RAID controller data via storcli64
License:        Proprietary
URL:            https://raid-monitor.example.com
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3 >= 3.9
BuildRequires:  python3-devel
# systemd macros replaced with explicit commands for cross-distro build compatibility

Requires:       python3 >= 3.9
Requires:       python3-pip
Requires:       systemd
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
RAID Monitor Agent is a daemon that collects RAID controller health data
using storcli64 (MegaRAID) and reports it to a central monitoring server.

Features:
- Automatic RAID controller detection and data collection
- Physical and virtual drive health monitoring
- BBU/CacheVault status tracking
- SMART attribute collection
- Event log forwarding
- Self-update capability
- SELinux policy included

%prep
%setup -q -n %{name}-%{version}

%build
# Nothing to build for a pure Python package

%install
rm -rf %{buildroot}

# Application directory
install -d -m 0755 %{buildroot}%{install_dir}
install -d -m 0755 %{buildroot}%{install_dir}/raid_agent
install -d -m 0755 %{buildroot}%{install_dir}/raid_agent/selinux

# Copy Python source files
cp -a raid_agent/__init__.py   %{buildroot}%{install_dir}/raid_agent/
cp -a raid_agent/main.py       %{buildroot}%{install_dir}/raid_agent/
cp -a raid_agent/config.py     %{buildroot}%{install_dir}/raid_agent/
cp -a raid_agent/collector.py  %{buildroot}%{install_dir}/raid_agent/
cp -a raid_agent/system_info.py %{buildroot}%{install_dir}/raid_agent/
cp -a raid_agent/reporter.py   %{buildroot}%{install_dir}/raid_agent/
cp -a raid_agent/installer.py  %{buildroot}%{install_dir}/raid_agent/
cp -a raid_agent/updater.py    %{buildroot}%{install_dir}/raid_agent/

# Copy SELinux policy source
cp -a raid_agent/selinux/*.te  %{buildroot}%{selinux_dir}/ 2>/dev/null || :
cp -a raid_agent/selinux/*.fc  %{buildroot}%{selinux_dir}/ 2>/dev/null || :
cp -a raid_agent/selinux/*.if  %{buildroot}%{selinux_dir}/ 2>/dev/null || :
cp -a raid_agent/selinux/Makefile %{buildroot}%{selinux_dir}/ 2>/dev/null || :

# Copy setup.py for virtualenv install
cp -a setup.py %{buildroot}%{install_dir}/

# Configuration directory
install -d -m 0750 %{buildroot}%{config_dir}
install -m 0600 config/config.yml.example %{buildroot}%{config_dir}/config.yml

# Log directory
install -d -m 0750 %{buildroot}%{log_dir}

# systemd service file
install -d -m 0755 %{buildroot}%{_unitdir}
install -m 0644 config/raid-agent.service %{buildroot}%{_unitdir}/raid-agent.service

# logrotate configuration
install -d -m 0755 %{buildroot}%{_sysconfdir}/logrotate.d
install -m 0644 config/raid-agent.logrotate %{buildroot}%{_sysconfdir}/logrotate.d/raid-agent

%pre
# Pre-install: nothing special needed since we run as root

%post
# Post-install: create virtualenv, install dependencies, setup SELinux, enable service

# Create Python virtual environment
if [ ! -d %{install_dir}/venv ]; then
    python3 -m venv %{install_dir}/venv
fi

# Install/upgrade dependencies in virtualenv
%{install_dir}/venv/bin/pip install --upgrade pip setuptools wheel 2>/dev/null || true
%{install_dir}/venv/bin/pip install --upgrade requests pyyaml 2>/dev/null || true

# Install the agent package itself
cd %{install_dir} && %{install_dir}/venv/bin/pip install -e . 2>/dev/null || true

# Create symlink for raid-agent command
ln -sf %{install_dir}/venv/bin/raid-agent /usr/local/bin/raid-agent

# Build and install SELinux policy module if semodule is available
if command -v semodule >/dev/null 2>&1 && [ -f %{selinux_dir}/raid-agent.te ]; then
    echo "Building SELinux policy module..."
    if command -v make >/dev/null 2>&1 && [ -f /usr/share/selinux/devel/Makefile ]; then
        cd %{selinux_dir}
        make -f /usr/share/selinux/devel/Makefile raid-agent.pp 2>/dev/null || true
        if [ -f raid-agent.pp ]; then
            semodule -i raid-agent.pp 2>/dev/null || true
            echo "SELinux policy module installed"
        fi
        # Apply file contexts
        if [ -f raid-agent.fc ]; then
            restorecon -R %{install_dir} 2>/dev/null || true
            restorecon -R %{config_dir} 2>/dev/null || true
            restorecon -R %{log_dir} 2>/dev/null || true
        fi
    else
        echo "SELinux development tools not found, skipping policy build"
    fi
fi

# Reload systemd, enable and start service
systemctl daemon-reload
systemctl enable raid-agent.service 2>/dev/null || true

# Start service only on fresh install (not upgrade)
if [ $1 -eq 1 ]; then
    echo "RAID Monitor Agent installed. Configure /etc/raid-agent/config.yml and run:"
    echo "  raid-agent --register"
    echo "  systemctl start raid-agent"
elif [ $1 -ge 2 ]; then
    # Upgrade: restart service if running
    systemctl try-restart raid-agent.service 2>/dev/null || true
fi

%preun
# Pre-uninstall: stop and disable service
if [ $1 -eq 0 ]; then
    # Full uninstall (not upgrade)
    systemctl stop raid-agent.service 2>/dev/null || true
    systemctl disable raid-agent.service 2>/dev/null || true

    # Remove SELinux policy module
    if command -v semodule >/dev/null 2>&1; then
        semodule -r raid-agent 2>/dev/null || true
    fi
fi

%postun
if [ $1 -ge 1 ]; then
    # Upgrade: restart service
    systemctl try-restart raid-agent.service 2>/dev/null || true
fi

if [ $1 -eq 0 ]; then
    # Full uninstall: clean up virtualenv and symlink
    rm -f /usr/local/bin/raid-agent 2>/dev/null || true
    rm -rf %{install_dir}/venv 2>/dev/null || true
    rm -rf %{install_dir}/__pycache__ 2>/dev/null || true
    rm -rf %{install_dir}/raid_agent/__pycache__ 2>/dev/null || true
fi

%files
%defattr(-,root,root,-)

# Application files
%dir %{install_dir}
%dir %{install_dir}/raid_agent
%dir %{install_dir}/raid_agent/selinux
%{install_dir}/raid_agent/__init__.py
%{install_dir}/raid_agent/main.py
%{install_dir}/raid_agent/config.py
%{install_dir}/raid_agent/collector.py
%{install_dir}/raid_agent/system_info.py
%{install_dir}/raid_agent/reporter.py
%{install_dir}/raid_agent/installer.py
%{install_dir}/raid_agent/updater.py
%{install_dir}/setup.py
%{install_dir}/raid_agent/selinux/*

# Configuration (noreplace = don't overwrite user changes on upgrade)
%dir %attr(0750,root,root) %{config_dir}
%config(noreplace) %attr(0600,root,root) %{config_dir}/config.yml

# Log directory
%dir %attr(0750,root,root) %{log_dir}

# systemd service
%{_unitdir}/raid-agent.service

# logrotate
%config(noreplace) %{_sysconfdir}/logrotate.d/raid-agent

%changelog
* Tue Feb 25 2026 RAID Monitor Team <admin@raid-monitor.example.com> - 1.0.4-1
- Fix: CacheVault data collection — /cx/cv show all J now executed correctly
- BBU/CV fallback logic rewritten: try BBU first, then CV, then controller fallback
- CacheVault extended data (capacitance, pack_energy, design_capacity) now collected
- Web UI: Charge field shows Capacitance for CacheVault, Energy shows pack/design ratio

* Tue Feb 25 2026 RAID Monitor Team <admin@raid-monitor.example.com> - 1.0.3-1
- Fix: command poll errors now logged at WARNING level (were silently swallowed at DEBUG)
- Improved diagnostics for server communication failures

* Tue Feb 25 2026 RAID Monitor Team <admin@raid-monitor.example.com> - 1.0.2-1
- Background command poll thread (30s) for fast debug toggle and log upload
- Commands no longer wait for full 10min collection cycle

* Tue Feb 25 2026 RAID Monitor Team <admin@raid-monitor.example.com> - 1.0.1-1
- Fix: PD interface fallback from detailed attrs and speed inference
- Fix: immediate log level switching on debug command from server
- Agent version now reported to server for display in web UI

* Mon Feb 24 2026 RAID Monitor Team <admin@raid-monitor.example.com> - 1.0.0-1
- Initial release
- storcli64 data collection for MegaRAID controllers
- HTTPS reporting to central server
- Agent self-registration and auto-update
- SELinux policy module included
- systemd service with automatic restart on failure
