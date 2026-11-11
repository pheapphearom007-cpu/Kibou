#!/usr/bin/env bash
# ==============================================================================
# Kibuo Installation & Environment Setup Script
# Supported Platforms: Kali Linux, Debian, Ubuntu
# ==============================================================================

set -e

# Terminal colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}"
cat << "EOF"
  ██╗  ██╗██╗██████╗ ██╗   ██╗ ██████╗ 
  ██║ ██╔╝██║██╔══██╗██║   ██║██╔═══██╗
  █████═╝ ██║██████╔╝██║   ██║██║   ██║
  ██╔═██╗ ██║██╔══██╗██║   ██║██║   ██║
  ██║ ╚██╗██║██████╔╝╚██████╔╝╚██████╔╝
  ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝  ╚═════╝ 
  KIBUO ENVIRONMENT SETUP & INSTALLER
EOF
echo -e "${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${CYAN}[*] Detecting operating system...${NC}"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME=$NAME
    OS_ID=$ID
    echo -e "${GREEN}[✔] Detected OS: $OS_NAME ($OS_ID)${NC}"
else
    echo -e "${YELLOW}[!] Warning: /etc/os-release not found. Assuming generic Linux.${NC}"
    OS_ID="linux"
fi

# 1. Check Python3
echo -e "${CYAN}[*] Verifying Python 3 installation...${NC}"
if command -v python3 >/dev/null 2>&1; then
    PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')")
    echo -e "${GREEN}[✔] Python 3 is installed ($PY_VER)${NC}"
else
    echo -e "${RED}[✖] Python 3 is required but not installed.${NC}"
    echo -e "${YELLOW}Please install Python 3: sudo apt install -y python3 python3-pip python3-venv${NC}"
    exit 1
fi

# 2. Virtual Environment Setup
echo -e "${CYAN}[*] Setting up Python virtual environment...${NC}"
if [ ! -d ".venv" ]; then
    python3 -m venv .venv 2>/dev/null || {
        echo -e "${YELLOW}[!] Notice: 'python3-venv' not found. Installing system packages or running in local environment.${NC}"
    }
fi

if [ -d ".venv" ]; then
    echo -e "${GREEN}[✔] Virtual environment created at .venv${NC}"
    # Activate virtual environment
    source .venv/bin/activate
    PIP_CMD="pip"
else
    PIP_CMD="pip3"
fi

# 3. Install Python Dependencies
echo -e "${CYAN}[*] Installing required Python packages...${NC}"
if command -v $PIP_CMD >/dev/null 2>&1; then
    $PIP_CMD install --upgrade pip --quiet 2>/dev/null || true
    $PIP_CMD install -r requirements.txt
    echo -e "${GREEN}[✔] Python dependencies successfully installed.${NC}"
else
    echo -e "${YELLOW}[!] pip was not found. Attempting to run via system python3 -m pip...${NC}"
    python3 -m pip install -r requirements.txt || {
        echo -e "${YELLOW}[!] Ensure 'rich', 'requests', and 'psutil' are installed.${NC}"
    }
fi

# 4. Check System Tools
echo -e "\n${CYAN}[*] Checking recommended Linux cybersecurity utilities:${NC}"

TOOLS=("nmap" "curl" "whois" "dig" "traceroute" "arp-scan" "whatweb" "searchsploit" "enum4linux" "nikto")
MISSING_TOOLS=()

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo -e "  [✔] ${GREEN}$tool${NC} is available"
    else
        echo -e "  [ ] ${YELLOW}$tool${NC} is missing"
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    echo -e "\n${YELLOW}[!] The following tools are missing: ${MISSING_TOOLS[*]}${NC}"
    echo -e "${CYAN}To install recommended tools on Debian/Ubuntu/Kali:${NC}"
    echo -e "  ${GREEN}sudo apt update && sudo apt install -y nmap curl whois dnsutils traceroute arp-scan whatweb exploitdb nikto enum4linux iproute2 python3-psutil${NC}"
else
    echo -e "\n${GREEN}[✔] All core reconnaissance tools are detected and available.${NC}"
fi

# Make scripts executable
chmod +x main.py run.sh 2>/dev/null || true

echo -e "\n${GREEN}====================================================${NC}"
echo -e "${GREEN} Kibuo installation completed successfully!${NC}"
echo -e "${GREEN} Launch Kibuo anytime with:${NC} ${YELLOW}./run.sh${NC} or ${YELLOW}python3 main.py${NC}"
echo -e "${GREEN}====================================================${NC}"
