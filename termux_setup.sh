#!/data/data/com.termux/files/usr/bin/bash
# ==============================================================================
# CyberShield SOC - Automated 1-Click Termux (Android) Installer & Launcher
# Works on both Rooted and Non-Rooted Android environments.
# ==============================================================================

set -e

echo -e "\e[1;36m=====================================================================\e[0m"
echo -e "\e[1;32m 🛡️  CyberShield Multi-Platform Network Traffic Analyzer & SOC\e[0m"
echo -e "\e[1;33m [*] Initializing Android Termux Environment Setup...\e[0m"
echo -e "\e[1;36m=====================================================================\e[0m"

echo -e "\e[1;34m[*] Step 1/4: Updating Termux core packages...\e[0m"
pkg update -y && pkg upgrade -y

echo -e "\e[1;34m[*] Step 2/4: Installing Python, libpcap, clang, and essential build tools...\e[0m"
pkg install -y python python-pip libpcap clang make git tsu termux-tools

echo -e "\e[1;34m[*] Step 3/4: Installing Python SOC dependencies...\e[0m"
pip install --upgrade pip setuptools wheel
pip install scapy rich fastapi uvicorn psutil pydantic reportlab matplotlib jinja2 requests anyio

echo -e "\e[1;34m[*] Step 4/4: Granting network permissions...\e[0m"
chmod +x main.py

echo -e "\e[1;32m=====================================================================\e[0m"
echo -e "\e[1;32m[✓] CyberShield Installation Complete!\e[0m"
echo -e "\e[1;33m[!] How to run CyberShield on Termux:\e[0m"
echo -e "    1. Regular Terminal Mode:  \e[1;36mpython main.py\e[0m"
echo -e "    2. Rooted Full-Capture:    \e[1;36msudo python main.py\e[0m (or \e[1;36mtsu -c 'python main.py'\e[0m)"
echo -e "    3. Web Dashboard Mode:     \e[1;36mpython main.py --web\e[0m"
echo -e "\e[1;32m=====================================================================\e[0m"

# Auto-launch
read -p "Do you want to start CyberShield TUI now? (Y/n): " choice
if [[ "$choice" != "n" && "$choice" != "N" ]]; then
    python main.py
fi
