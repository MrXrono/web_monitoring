#!/bin/bash
# RAID Monitor Agent — update script
# Usage: curl -sk https://SERVER/api/v1/agent/package/latest -o /tmp/raid-agent.rpm && bash update-agent.sh
#   or:  bash update-agent.sh https://web-monitoring.vniizht.lan
#
# The script:
#   1. Checks the server for the latest agent version
#   2. Compares with the installed version
#   3. Downloads and installs the RPM if an update is available
#   4. Restarts the service

set -euo pipefail

SERVER_URL="${1:-}"
TMP_RPM="/tmp/raid-agent-latest.rpm"

# ---------------------------------------------------------------------------
# Determine server URL from config if not passed as argument
# ---------------------------------------------------------------------------
if [ -z "$SERVER_URL" ]; then
    if [ -f /etc/raid-agent/config.yml ]; then
        SERVER_URL=$(grep -E '^\s*server_url:' /etc/raid-agent/config.yml | head -1 | sed 's/.*server_url:\s*//' | tr -d '"' | tr -d "'")
    fi
fi

if [ -z "$SERVER_URL" ]; then
    echo "ERROR: Server URL not specified."
    echo "Usage: $0 https://web-monitoring.vniizht.lan"
    exit 1
fi

# Remove trailing slash
SERVER_URL="${SERVER_URL%/}"

echo "=== RAID Monitor Agent Update ==="
echo "Server: ${SERVER_URL}"

# ---------------------------------------------------------------------------
# Get installed version
# ---------------------------------------------------------------------------
INSTALLED_VERSION=""
if rpm -q raid-agent &>/dev/null; then
    INSTALLED_VERSION=$(rpm -q --queryformat '%{VERSION}' raid-agent 2>/dev/null || echo "")
    echo "Installed version: ${INSTALLED_VERSION}"
else
    echo "Agent not installed yet"
fi

# ---------------------------------------------------------------------------
# Check latest version on server
# ---------------------------------------------------------------------------
echo "Checking for updates..."
VERSION_INFO=$(curl -sk "${SERVER_URL}/api/v1/agent/package/version" 2>/dev/null || echo "")

if [ -z "$VERSION_INFO" ]; then
    echo "ERROR: Cannot reach server at ${SERVER_URL}/api/v1/agent/package/version"
    exit 1
fi

LATEST_VERSION=$(echo "$VERSION_INFO" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('version',''))" 2>/dev/null || echo "")
LATEST_SHA256=$(echo "$VERSION_INFO" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('sha256',''))" 2>/dev/null || echo "")

if [ -z "$LATEST_VERSION" ] || [ "$LATEST_VERSION" = "None" ]; then
    echo "No agent package available on server."
    exit 0
fi

echo "Latest version on server: ${LATEST_VERSION}"

# ---------------------------------------------------------------------------
# Compare versions
# ---------------------------------------------------------------------------
if [ "$INSTALLED_VERSION" = "$LATEST_VERSION" ]; then
    echo "Agent is already up to date (v${INSTALLED_VERSION})."
    exit 0
fi

echo "Update available: ${INSTALLED_VERSION:-not installed} -> ${LATEST_VERSION}"

# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------
echo "Downloading agent RPM..."
HTTP_CODE=$(curl -sk -w '%{http_code}' -o "$TMP_RPM" "${SERVER_URL}/api/v1/agent/package/latest")

if [ "$HTTP_CODE" != "200" ]; then
    echo "ERROR: Download failed with HTTP ${HTTP_CODE}"
    rm -f "$TMP_RPM"
    exit 1
fi

# Verify checksum if available
if [ -n "$LATEST_SHA256" ] && command -v sha256sum &>/dev/null; then
    ACTUAL_SHA256=$(sha256sum "$TMP_RPM" | awk '{print $1}')
    if [ "$ACTUAL_SHA256" != "$LATEST_SHA256" ]; then
        echo "ERROR: SHA256 checksum mismatch!"
        echo "  Expected: ${LATEST_SHA256}"
        echo "  Got:      ${ACTUAL_SHA256}"
        rm -f "$TMP_RPM"
        exit 1
    fi
    echo "Checksum verified OK"
fi

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
echo "Installing raid-agent ${LATEST_VERSION}..."
rpm -U --force "$TMP_RPM"

echo "Restarting raid-agent service..."
systemctl restart raid-agent

rm -f "$TMP_RPM"

echo "=== Update complete: raid-agent ${LATEST_VERSION} ==="
