#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# Argus — Full Infra-to-Parsers Deployment Setup Script
# ══════════════════════════════════════════════════════════════════════════════
# Idempotent installation of Python dependencies, verification of databases,
# and setup of external forensic binary tools (Hayabusa, Zeek, Suricata, RegRipper).
# ══════════════════════════════════════════════════════════════════════════════

set -e

# Make sure stdout uses bold colors for clarity
export TERM=xterm
BOLD="\033[1m"
GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
NC="\033[0m" # No Color

echo -e "${BOLD}======================================================================${NC}"
echo -e "${BOLD}              Argus — Deployment Setup & Health Check                 ${NC}"
echo -e "${BOLD}======================================================================${NC}"

# Check that the script is run in Linux environment
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" || "$OSTYPE" == "cygwin" ]]; then
    echo -e "${RED}Error: This setup script is designed for Debian/Ubuntu-based Linux systems.${NC}"
    echo -e "For Windows environments, please install these tools manually."
    exit 1
fi

# Ensure running from correct directory (where requirements.txt exists)
if [ ! -f "requirements.txt" ]; then
    echo -e "${RED}Error: requirements.txt not found. Please run this script from the 'argus' directory.${NC}"
    exit 1
fi

# ──────────────────────────────────────────────────────────────────────────────
# Phase 1: Python Dependencies
# ──────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[Phase 1/4] Installing Python dependencies from requirements.txt...${NC}"

# Find or install pip
PIP_CMD=""
if command -v pip3 >/dev/null 2>&1; then
    PIP_CMD="pip3"
elif command -v pip >/dev/null 2>&1; then
    PIP_CMD="pip"
else
    echo -e "${YELLOW}pip is missing. Installing python3-pip...${NC}"
    sudo apt-get update && sudo apt-get install -y python3-pip
    if command -v pip3 >/dev/null 2>&1; then
        PIP_CMD="pip3"
    elif command -v pip >/dev/null 2>&1; then
        PIP_CMD="pip"
    else
        echo -e "${RED}Error: Failed to install pip. Please install python3-pip manually.${NC}"
        exit 1
    fi
fi

# Remove conflicting apt-installed python packages that block pip upgrades
echo -e "${YELLOW}Removing conflicting system python3-typing-extensions package...${NC}"
sudo apt-get remove -y python3-typing-extensions || true

# Pre-install CPU-only PyTorch to avoid downloading massive GPU dependencies (~1.5GB+)
echo -e "${YELLOW}Pre-installing CPU-only version of PyTorch to save bandwidth and disk space...${NC}"
if ! $PIP_CMD install torch --index-url https://download.pytorch.org/whl/cpu; then
    $PIP_CMD install torch --index-url https://download.pytorch.org/whl/cpu --break-system-packages --ignore-installed
fi

if ! $PIP_CMD install -r requirements.txt; then
    echo -e "${YELLOW}Retrying with --break-system-packages and --ignore-installed (needed for system Python 3.11+)...${NC}"
    $PIP_CMD install -r requirements.txt --break-system-packages --ignore-installed
fi
echo -e "${GREEN}Python dependencies installed successfully.${NC}"

# ──────────────────────────────────────────────────────────────────────────────
# Phase 2: PostgreSQL and MinIO Connectivity Verification
# ──────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[Phase 2/4] Verifying PostgreSQL and MinIO connectivity...${NC}"

export PYTHONPATH=.
python3 -c "
import sys

# Try importing config
try:
    from config.settings import settings
except ImportError as e:
    print('Failed to import config.settings. Are you running setup_tools.sh from the argus directory?', file=sys.stderr)
    print(e, file=sys.stderr)
    sys.exit(1)

# Check PostgreSQL
print('  Connecting to PostgreSQL...')
try:
    import psycopg2
    conn = psycopg2.connect(
        host=settings.postgres_host,
        port=settings.postgres_port,
        database=settings.postgres_db,
        user=settings.postgres_user,
        password=settings.postgres_password,
        connect_timeout=5
    )
    conn.close()
    print('    \033[32mOK - PostgreSQL database is reachable!\033[0m')
except Exception as e:
    print(f'    \033[31mFAIL - PostgreSQL is unreachable!\033[0m', file=sys.stderr)
    print(f'    Detail: {e}', file=sys.stderr)
    print(f'    Please verify your .env file credentials and ensure the Postgres service/container is running.', file=sys.stderr)
    sys.exit(1)

# Check MinIO
print('  Connecting to MinIO...')
try:
    from minio import Minio
    endpoint = settings.minio_endpoint
    if '://' in endpoint:
        endpoint = endpoint.split('://')[1]
    
    client = Minio(
        endpoint,
        access_key=settings.minio_access_key,
        secret_key=settings.minio_secret_key,
        secure=settings.minio_secure
    )
    # Test connection by listing buckets
    client.list_buckets()
    print('    \033[32mOK - MinIO storage is reachable!\033[0m')
except Exception as e:
    print(f'    \033[31mFAIL - MinIO is unreachable!\033[0m', file=sys.stderr)
    print(f'    Detail: {e}', file=sys.stderr)
    print(f'    Please verify your .env file credentials and ensure the MinIO service/container is running.', file=sys.stderr)
    sys.exit(1)
" || { echo -e "${RED}Infrastructure connectivity check failed. Exiting.${NC}"; exit 1; }

echo -e "${GREEN}Infrastructure connectivity checks passed successfully!${NC}"

# ──────────────────────────────────────────────────────────────────────────────
# Phase 3: Install/Verify External Binary Dependencies
# ──────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[Phase 3/4] Installing / Verifying external binaries...${NC}"

# Ensure basic utilities are present
for cmd in curl unzip git; do
    if ! command -v $cmd >/dev/null 2>&1; then
        echo -e "${YELLOW}  Installing missing package: $cmd${NC}"
        sudo apt-get update && sudo apt-get install -y $cmd
    fi
done

# Initialize status variables
PERL_STATUS="Installed"
PARSE_STATUS="Installed"
ZEEK_STATUS="Installed"
SURICATA_STATUS="Installed"
HAYABUSA_STATUS="Installed"
REGRIPPER_STATUS="Installed"

# 1. Perl
if command -v perl >/dev/null 2>&1; then
    echo -e "  Perl: ${GREEN}OK (already installed)${NC}"
else
    echo -e "  Perl: ${YELLOW}Missing. Installing...${NC}"
    sudo apt-get update && sudo apt-get install -y perl
    if command -v perl >/dev/null 2>&1; then
        PERL_STATUS="Installed"
    else
        PERL_STATUS="Failed"
    fi
fi

# 2. Perl Parse::Win32Registry CPAN Dependency
if perl -MParse::Win32Registry -e '1' >/dev/null 2>&1; then
    echo -e "  Perl Parse::Win32Registry: ${GREEN}OK (already installed)${NC}"
else
    echo -e "  Perl Parse::Win32Registry: ${YELLOW}Missing. Installing...${NC}"
    # Try installing via apt-get first, fallback to CPAN
    sudo apt-get install -y libparse-win32registry-perl || sudo cpan Parse::Win32Registry
    if perl -MParse::Win32Registry -e '1' >/dev/null 2>&1; then
        PARSE_STATUS="Installed"
    else
        PARSE_STATUS="Failed"
    fi
fi

# 3. Zeek
if command -v zeek >/dev/null 2>&1; then
    echo -e "  Zeek: ${GREEN}OK (already installed)${NC}"
else
    echo -e "  Zeek: ${YELLOW}Missing. Installing...${NC}"
    sudo apt-get update && sudo apt-get install -y zeek || sudo apt-get install -y zeek-lts || ZEEK_STATUS="Failed"
    if [ "$ZEEK_STATUS" != "Failed" ] && command -v zeek >/dev/null 2>&1; then
        ZEEK_STATUS="Installed"
    else
        ZEEK_STATUS="Failed"
    fi
fi

# 4. Suricata
if command -v suricata >/dev/null 2>&1; then
    echo -e "  Suricata: ${GREEN}OK (already installed)${NC}"
else
    echo -e "  Suricata: ${YELLOW}Missing. Installing...${NC}"
    sudo apt-get update && sudo apt-get install -y suricata || SURICATA_STATUS="Failed"
    if [ "$SURICATA_STATUS" != "Failed" ] && command -v suricata >/dev/null 2>&1; then
        SURICATA_STATUS="Installed"
    else
        SURICATA_STATUS="Failed"
    fi
fi

# 5. Hayabusa
if command -v hayabusa >/dev/null 2>&1; then
    echo -e "  Hayabusa: ${GREEN}OK (already installed)${NC}"
else
    echo -e "  Hayabusa: ${YELLOW}Missing. Downloading latest release from GitHub...${NC}"
    
    HAYABUSA_URL=$(python3 -c '
import urllib.request, json
try:
    req = urllib.request.Request("https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest", headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req) as r:
        data = json.loads(r.read().decode())
        url = [a["browser_download_url"] for a in data["assets"] if "linux-x64.zip" in a["name"]][0]
        print(url)
except Exception:
    print("https://github.com/Yamato-Security/hayabusa/releases/latest/download/hayabusa-linux-x64.zip")
')

    echo "  Downloading from $HAYABUSA_URL..."
    curl -L -o /tmp/hayabusa.zip "$HAYABUSA_URL"
    mkdir -p /tmp/hayabusa_extracted
    unzip -o /tmp/hayabusa.zip -d /tmp/hayabusa_extracted
    
    BINARY_PATH=$(find /tmp/hayabusa_extracted -type f -name "hayabusa" | head -n 1)
    if [ -f "$BINARY_PATH" ]; then
        sudo cp "$BINARY_PATH" /usr/local/bin/hayabusa
        sudo chmod +x /usr/local/bin/hayabusa
        HAYABUSA_STATUS="Installed"
    else
        ALT_BINARY_PATH=$(find /tmp/hayabusa_extracted -type f -name "hayabusa-*" | head -n 1)
        if [ -f "$ALT_BINARY_PATH" ]; then
            sudo cp "$ALT_BINARY_PATH" /usr/local/bin/hayabusa
            sudo chmod +x /usr/local/bin/hayabusa
            HAYABUSA_STATUS="Installed"
        else
            HAYABUSA_STATUS="Failed"
        fi
    fi
    rm -rf /tmp/hayabusa.zip /tmp/hayabusa_extracted
fi

# 6. RegRipper3.0
if command -v rip.pl >/dev/null 2>&1 || command -v rip >/dev/null 2>&1; then
    echo -e "  RegRipper3.0: ${GREEN}OK (already installed)${NC}"
else
    echo -e "  RegRipper3.0: ${YELLOW}Missing. Installing from GitHub...${NC}"
    if [ -d "/opt/regripper" ]; then
        sudo rm -rf /opt/regripper
    fi
    sudo git clone https://github.com/keydet89/RegRipper3.0.git /opt/regripper
    sudo chmod +x /opt/regripper/rip.pl
    
    # Create wrapper scripts
    cat << 'EOF' | sudo tee /usr/local/bin/rip.pl > /dev/null
#!/bin/bash
perl /opt/regripper/rip.pl "$@"
EOF
    sudo chmod +x /usr/local/bin/rip.pl
    sudo ln -sf /usr/local/bin/rip.pl /usr/local/bin/rip
    
    if command -v rip.pl >/dev/null 2>&1 || command -v rip >/dev/null 2>&1; then
        REGRIPPER_STATUS="Installed"
    else
        REGRIPPER_STATUS="Failed"
    fi
fi

# ──────────────────────────────────────────────────────────────────────────────
# Phase 3b: Capture tool versions → config/tool_versions.json
# ──────────────────────────────────────────────────────────────────────────────
# This file is read by every parser at runtime to stamp tool_version into
# every Artifact's raw_fields, making each finding traceable to the exact
# tool version that produced it.
# ──────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[Phase 3b] Capturing installed tool versions...${NC}"

# Helper: run a command, capture stdout, return first non-empty line.
# Usage: _get_version_line <cmd> [args...]
_get_version_line() {
    "$@" 2>&1 | grep -m1 '[0-9]' | sed 's/^[^0-9]*//' | awk '{print $1}' || echo "unknown"
}

# Hayabusa: `hayabusa --version`  → "hayabusa 2.18.0"
if command -v hayabusa >/dev/null 2>&1; then
    HAYABUSA_VER=$(hayabusa --version 2>&1 | grep -oP '\d+\.\d+[\.\d]*' | head -n1 || echo "unknown")
else
    HAYABUSA_VER="unknown"
fi
echo -e "  hayabusa version   : ${GREEN}${HAYABUSA_VER}${NC}"

# Zeek: `zeek --version`  → "zeek version 6.0.3"
if command -v zeek >/dev/null 2>&1; then
    ZEEK_VER=$(zeek --version 2>&1 | grep -oP '\d+\.\d+[\.\d]*' | head -n1 || echo "unknown")
else
    ZEEK_VER="unknown"
fi
echo -e "  zeek version       : ${GREEN}${ZEEK_VER}${NC}"

# Suricata: `suricata --build-info`  → "This is Suricata version 7.0.3 ..."
if command -v suricata >/dev/null 2>&1; then
    SURICATA_VER=$(suricata --build-info 2>&1 | grep -oP 'version \K\d+\.\d+[\.\d]*' | head -n1 || echo "unknown")
else
    SURICATA_VER="unknown"
fi
echo -e "  suricata version   : ${GREEN}${SURICATA_VER}${NC}"

# Volatility 3: `vol --version`  → "Volatility 3 Framework 2.7.1"
# vol may not be installed via setup_tools.sh (it's a pip package), so check PATH.
if command -v vol >/dev/null 2>&1; then
    VOL3_VER=$(vol --version 2>&1 | grep -oP '\d+\.\d+[\.\d]*' | head -n1 || echo "unknown")
elif python3 -c "import volatility3" 2>/dev/null; then
    VOL3_VER=$(python3 -c "import volatility3; print(getattr(volatility3, '__version__', 'unknown'))" 2>/dev/null || echo "unknown")
else
    VOL3_VER="unknown"
fi
echo -e "  volatility3 version: ${GREEN}${VOL3_VER}${NC}"

# RegRipper: parse version from rip.pl header comment (e.g. "# v.20201114")
# The date-based version is the most reliable identifier for RegRipper.
if command -v rip.pl >/dev/null 2>&1 || command -v rip >/dev/null 2>&1; then
    RIP_CMD="rip.pl"
    command -v rip.pl >/dev/null 2>&1 || RIP_CMD="rip"
    # rip.pl -h prints "Rip v.20201114" or similar
    REGRIPPER_VER=$($RIP_CMD -h 2>&1 | grep -oP 'v\.\K[0-9]+' | head -n1 || echo "unknown")
    [ -z "$REGRIPPER_VER" ] && REGRIPPER_VER="unknown"
elif [ -f /opt/regripper/rip.pl ]; then
    REGRIPPER_VER=$(grep -oP 'v\.\K[0-9]+' /opt/regripper/rip.pl | head -n1 || echo "unknown")
    [ -z "$REGRIPPER_VER" ] && REGRIPPER_VER="unknown"
else
    REGRIPPER_VER="unknown"
fi
echo -e "  regripper version  : ${GREEN}${REGRIPPER_VER}${NC}"

# Write config/tool_versions.json
VERSIONS_FILE="config/tool_versions.json"
mkdir -p config
WRITTEN_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat > "${VERSIONS_FILE}" <<EOF
{
  "written_at":  "${WRITTEN_AT}",
  "hayabusa":    "${HAYABUSA_VER}",
  "zeek":        "${ZEEK_VER}",
  "suricata":    "${SURICATA_VER}",
  "volatility3": "${VOL3_VER}",
  "regripper":   "${REGRIPPER_VER}"
}
EOF

echo -e "${GREEN}Tool versions written to ${VERSIONS_FILE}${NC}"

# ──────────────────────────────────────────────────────────────────────────────
# Phase 4: Final Summary Table
# ──────────────────────────────────────────────────────────────────────────────
echo -e "\n${BOLD}[Phase 4/4] Summary Status Report${NC}"
echo "======================================================================"
printf "| %-25s | %-12s | %-21s |\n" "Component/Dependency" "Status" "Type"
echo "======================================================================"
printf "| %-25s | \033[32m%-12s\033[0m | %-21s |\n" "Python Libraries" "Installed" "pip"
printf "| %-25s | \033[32m%-12s\033[0m | %-21s |\n" "PostgreSQL Database" "Reachable" "Service"
printf "| %-25s | \033[32m%-12s\033[0m | %-21s |\n" "MinIO Object Storage" "Reachable" "Service"

status_color() {
    if [ "$1" == "Installed" ]; then
        echo -e "\033[32mInstalled\033[0m"
    else
        echo -e "\033[31mFailed\033[0m"
    fi
}

printf "| %-25s | %b | %-21s |\n" "Perl Language" "$(status_color $PERL_STATUS)" "System Binary"
printf "| %-25s | %b | %-21s |\n" "Parse::Win32Registry" "$(status_color $PARSE_STATUS)" "Perl CPAN Module"
printf "| %-25s | %b | %-21s |\n" "Zeek Traffic Parser" "$(status_color $ZEEK_STATUS)" "System Binary"
printf "| %-25s | %b | %-21s |\n" "Suricata IDS" "$(status_color $SURICATA_STATUS)" "System Binary"
printf "| %-25s | %b | %-21s |\n" "Hayabusa EVTX Engine" "$(status_color $HAYABUSA_STATUS)" "System Binary"
printf "| %-25s | %b | %-21s |\n" "RegRipper3.0 Registry" "$(status_color $REGRIPPER_STATUS)" "System Binary / git"
echo "======================================================================"

# Final error check
if [ "$PERL_STATUS" == "Failed" ] || [ "$PARSE_STATUS" == "Failed" ] || [ "$ZEEK_STATUS" == "Failed" ] || [ "$SURICATA_STATUS" == "Failed" ] || [ "$HAYABUSA_STATUS" == "Failed" ] || [ "$REGRIPPER_STATUS" == "Failed" ]; then
    echo -e "\n${RED}Warning: One or more external parser binaries failed to install.${NC}"
    echo -e "Please check the terminal log output above for specific errors."
    exit 1
else
    echo -e "\n${GREEN}Deployment Setup completed successfully! All components are verified and operational.${NC}"
    exit 0
fi
