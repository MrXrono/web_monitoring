%define name        raid-agent
%define version     1.1.8
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

Requires:       systemd
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
cp -a raid_agent/smartctl_collector.py %{buildroot}%{install_dir}/raid_agent/

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
# Pre-install: check and install system dependencies
echo "=== Checking system dependencies ==="

# --- python3 ---
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not found, installing..."
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y python3 2>/dev/null
    elif command -v yum >/dev/null 2>&1; then
        yum install -y python3 2>/dev/null
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        echo "ERROR: Failed to install python3. Install it manually and retry."
        exit 1
    fi
    echo "  python3 installed: $(python3 --version 2>&1)"
else
    echo "  python3: $(python3 --version 2>&1)"
fi

# --- python3-pip (needed for venv/pip bootstrap) ---
if ! python3 -m pip --version >/dev/null 2>&1; then
    echo "python3-pip not found, installing..."
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y python3-pip 2>/dev/null
    elif command -v yum >/dev/null 2>&1; then
        yum install -y python3-pip 2>/dev/null
    fi
    # Fallback: ensurepip
    if ! python3 -m pip --version >/dev/null 2>&1; then
        python3 -m ensurepip --upgrade 2>/dev/null || true
    fi
    if ! python3 -m pip --version >/dev/null 2>&1; then
        echo "WARNING: pip not available. venv bootstrap may be limited."
    else
        echo "  pip installed: $(python3 -m pip --version 2>&1)"
    fi
else
    echo "  pip: $(python3 -m pip --version 2>&1)"
fi

# --- python3-venv (some distros ship it separately) ---
if ! python3 -m venv --help >/dev/null 2>&1; then
    echo "python3-venv not available, installing..."
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y python3-libs 2>/dev/null
    elif command -v yum >/dev/null 2>&1; then
        yum install -y python3-libs 2>/dev/null
    fi
fi

echo "=== Dependencies OK ==="

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

# Create symlinks for raid-agent command
# /usr/local/bin — for regular users
# /usr/sbin — for sudo (secure_path does not include /usr/local/bin)
ln -sf %{install_dir}/venv/bin/raid-agent /usr/local/bin/raid-agent
ln -sf %{install_dir}/venv/bin/raid-agent /usr/sbin/raid-agent

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

# ---------------------------------------------------------------------------
# Handle RAID_SERVER_URL environment variable for auto-registration
# Usage: RAID_SERVER_URL=https://web-monitoring.vniizht.lan rpm -ivh raid-agent.rpm
# ---------------------------------------------------------------------------
if [ -n "${RAID_SERVER_URL:-}" ] && [ $1 -eq 1 ]; then
    echo "=== Auto-configuration ==="
    echo "Server URL: ${RAID_SERVER_URL}"

    # Write server_url to config
    %{install_dir}/venv/bin/python3 -c "
import yaml, os
config_path = '%{config_dir}/config.yml'
config = {}
if os.path.isfile(config_path):
    with open(config_path) as f:
        config = yaml.safe_load(f) or {}
config['server_url'] = '${RAID_SERVER_URL}'.rstrip('/')
config.setdefault('ssl_verify', True)
config.setdefault('collection_interval', 600)
with open(config_path, 'w') as f:
    yaml.safe_dump(config, f, default_flow_style=False, sort_keys=False)
os.chmod(config_path, 0o600)
" 2>/dev/null

    if [ $? -eq 0 ]; then
        echo "Config updated: server_url=${RAID_SERVER_URL}"

        # Auto-register with the server
        echo "Registering agent with server..."
        %{install_dir}/venv/bin/raid-agent --register 2>&1 | tail -5

        if [ $? -eq 0 ]; then
            echo "Registration successful. Starting service..."
            # daemon-reload before start (moved here to avoid blocking earlier steps)
            systemctl daemon-reload
            systemctl enable raid-agent.service 2>/dev/null || true
            systemctl start raid-agent.service 2>/dev/null || true
        else
            echo "WARNING: Auto-registration failed. Register manually:"
            echo "  sudo raid-agent --register"
        fi
    else
        echo "WARNING: Failed to update config. Register manually:"
        echo "  sudo raid-agent --register"
    fi
    echo "=== Auto-configuration complete ==="
elif [ $1 -ge 2 ]; then
    # Upgrade: daemon-reload + deferred restart
    # Restart in background with delay so rpm -Uvh can finish first
    # (the running agent process is the one calling rpm — killing it
    # immediately causes "signal 15" error and breaks the update)
    (sleep 2 && systemctl daemon-reload && systemctl restart raid-agent.service) &>/dev/null &
else
    # Fresh install without RAID_SERVER_URL — manual setup
    # daemon-reload in background (don't block RPM install)
    systemctl daemon-reload &
    systemctl enable raid-agent.service 2>/dev/null || true
    echo ""
    echo "RAID Monitor Agent v%{version} installed."
    echo ""
    echo "Quick start:"
    echo "  RAID_SERVER_URL=https://your-server rpm -ivh raid-agent.rpm  (auto-register)"
    echo ""
    echo "Or manual setup:"
    echo "  1. Edit /etc/raid-agent/config.yml — set server_url"
    echo "  2. sudo raid-agent --register"
    echo "  3. systemctl start raid-agent"
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
    # Full uninstall: clean up virtualenv and symlinks
    rm -f /usr/local/bin/raid-agent 2>/dev/null || true
    rm -f /usr/sbin/raid-agent 2>/dev/null || true
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
%{install_dir}/raid_agent/smartctl_collector.py
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
* Thu Feb 26 2026 RAID Monitor Team <admin@raid-monitor.example.com> - 1.1.8-1
- Fix: exclude MegaRAID-managed drives from smartctl collection at agent level
- Previously filtering was only server-side and unreliable when physical_drives table was empty

* Thu Feb 26 2026 RAID Monitor Team <admin@raid-monitor.example.com> - 1.1.7-1
- Add: scan_type field in smart_drive reports (megaraid, sat, nvme, scsi, etc.)
- Fix: smartctl section no longer shows MegaRAID-managed drives on servers with hardware RAID
- Fix: RAID controller virtual disk devices filtered by known vendor models

* Thu Feb 26 2026 RAID Monitor Team <admin@raid-monitor.example.com> - 1.1.6-1
- Add: Software RAID (mdadm) monitoring — /proc/mdstat + mdadm --detail
- Add: SMART data collection via smartctl for standalone drives
- Add: smartctl_collector.py module (mdadm parser, smartctl JSON, ATA/NVMe support)
- Add: Software RAID tab in web UI with state badges and rebuild progress
- Add: SMART modal for physical drives (attributes table, NVMe health log)
- Add: SoftwareRaid DB model with member_devices JSONB
- Add: Server-side processing for software_raid and smart_drives in agent reports
- Fix: smartctl_version tracked per server

* Thu Feb 26 2026 RAID Monitor Team <admin@raid-monitor.example.com> - 1.1.5-1
- Add: smartctl (smartmontools) auto-detection, auto-install via system package manager
- Add: hourly smartctl availability re-check in daemon loop (same pattern as storcli)
- Add: ensure_smartctl() with find/install/verify lifecycle
- Supported package managers: dnf, yum, apt-get, zypper, apk, pacman

* Thu Feb 26 2026 RAID Monitor Team <admin@raid-monitor.example.com> - 1.1.4-1
- Fix: storcli download SSL error on self-signed certificates (verify=False like reporter)

* Thu Feb 26 2026 RAID Monitor Team <admin@raid-monitor.example.com> - 1.1.3-1
- Fix: periodic storcli re-check every hour in daemon loop (auto-install if missing)
- Fix: ensure_storcli on collect_now command (was only find, no install)
- Fix: delete all old agent logs on collect (not just >7 days)

* Thu Feb 26 2026 RAID Monitor Team <admin@raid-monitor.example.com> - 1.1.2-1
- Add: auto-cleanup of old agent logs (>7 days) on upload and collection
- Add: "Log Request Status" table on debug settings page

* Thu Feb 26 2026 RAID Monitor Team <admin@raid-monitor.example.com> - 1.1.1-1
- Fix: self-update SHA256 mismatch — server now refreshes hash on RPM rebuild
- Fix: self-update signal 15 — deferred restart in %%post, removed explicit restart from updater
- Fix: health status text overflow on server card — click to expand/collapse
- Fix: NameError '_' not defined in dashboard_page
- Fix: footer version hardcoded — now dynamic
- Fix: agent package current version detection on server startup
- Fix: systemctl daemon-reload blocking RPM install for 2-3 minutes

* Thu Feb 26 2026 RAID Monitor Team <admin@raid-monitor.example.com> - 1.1.0-1
- Auto-install dependencies in %%pre: python3, pip, venv (dnf/yum)
- Auto-register via env var: RAID_SERVER_URL=https://server rpm -ivh raid-agent.rpm
- Remove hard Requires on python3/python3-pip (handled dynamically in %%pre)
- Fix: sudo raid-agent not found — add symlink to /usr/sbin for secure_path compatibility

* Thu Feb 26 2026 RAID Monitor Team <admin@raid-monitor.example.com> - 1.0.6-1
- Fix: updater SSL verification — now trusts self-signed certs (same as reporter)
- Update check failures now logged at WARNING level (were DEBUG — invisible)

* Thu Feb 26 2026 RAID Monitor Team <admin@raid-monitor.example.com> - 1.0.5-1
- All timestamps switched to Moscow timezone (MSK, UTC+3)
- Docker containers configured with TZ=Europe/Moscow
- PostgreSQL timezone set to Europe/Moscow via PGTZ
- Agent systemd service configured with TZ=Europe/Moscow
- Telegram notifications now display MSK instead of UTC
- Footer: added GitHub link, contacts, proprietary license notice
- Added LICENSE file (Proprietary, all rights reserved)

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
