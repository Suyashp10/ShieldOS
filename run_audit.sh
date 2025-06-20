#!/bin/bash

# ───────────── ANSI Colors ───────────── #
RED="\e[31m"
GREEN="\e[32m"
CYAN="\e[36m"
BOLD="\e[1m"
RESET="\e[0m"

# ───────────── Banner ───────────── #
echo -e "${CYAN}${BOLD}"
echo "███████╗██╗  ██╗██╗███████╗██╗     ██████╗  ██████╗ ███████╗"
echo "██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗██╔═══██╗██╔════╝"
echo "███████╗███████║██║█████╗  ██║     ██║  ██║██║   ██║███████╗"
echo "╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║██║   ██║╚════██║"
echo "███████║██║  ██║██║███████╗███████╗██████╔╝╚██████╔╝███████║"
echo "╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝"
echo -e "${RESET}${BOLD}"
echo "         LINUX HARDENING AUDIT TOOL"
echo -e "${RESET}"

# ───────────── Cyber Tip of the Day ───────────── #
tips=(
    "🔐 Disable root SSH login unless absolutely necessary."
    "🛡️ Keep your firewall active — minimal ports, max control."
    "🧯 Monitor /tmp and /var/tmp for unexpected executables."
    "🔍 Audit SUID binaries often — privilege escalation risks."
    "📦 Uninstall unused packages. Less software = smaller attack surface."
    "⚠️ Check for users with UID 0 — root shouldn't have clones."
    "🚪 Close unnecessary open ports. Netstat is your friend."
    "🧑‍💻 Principle of Least Privilege — always."
    "🧬 Use auditd or journald to keep trail of system activity."
    "🌐 Never trust input — sanitize, validate, escape."
)
echo -e "${GREEN}${BOLD}💡 Security Tip: ${tips[$RANDOM % ${#tips[@]}]}${RESET}\n"

# ───────────── --help Message ───────────── #
if [[ "$1" == "--help" ]]; then
    echo -e "\nShieldOS - Linux Hardening Audit Tool"
    echo -e "Usage: ./run_audit.sh [options]\n"
    echo "Core Flags:"
    echo "  --html-only         Generate only the HTML report (skip .txt)"
    echo "  --text-only         Generate only the text report (skip .html)"
    echo "  --no-browser        Prevent auto-opening of the HTML report"
    echo "  --verbose           Print detailed logs while auditing"
    echo "  --no-color          Disable colored terminal output"
    echo
    echo "Scan Control Flags:"
    echo "  --fast              Skip slow checks (e.g., world-writable files)"
    echo "  --skip-rootkit      Skip rootkit scan"
    echo "  --skip-services     Skip service audit"
    echo "  --section=LIST      Run only selected modules (comma-separated)"
    echo "  --scan-path=LIST    Only scan specific paths (e.g., /etc,/home)"
    echo "  --exclude=LIST      Exclude paths from scan (e.g., /proc,/mnt)"
    echo
    echo "Output Flags:"
    echo "  --output=FILENAME   Set base name for report files"
    echo "  --json              Export audit results to audit_report.json"
    echo "  --log=LOGFILE       Save terminal output to a log file"
    echo
    echo "Example:"
    echo "  ./run_audit.sh --fast --section=users,permissions --html-only --output=myserver"
    echo
    exit 0
fi

# ───────────── Requirements Check ───────────── #
if ! command -v python3 &>/dev/null; then
    echo "${RED}Python3 is not installed!${RESET}"
    exit 1
fi

if [[ ! -f "audit.py" ]]; then
    echo "${RED}audit.py not found in the current directory!${RESET}"
    exit 1
fi

if ! python3 -c "import jinja2" &>/dev/null; then
    echo "Installing missing Jinja2 dependency..."
    python3 -m pip install jinja2 || {
        echo "${RED}Failed to install Jinja2!${RESET}"
        exit 1
    }
fi

# ───────────── Run Audit ───────────── #
echo "Running audit..."
sudo python3 audit.py "$@"

echo -e "\n${GREEN}✔️ Audit complete!${RESET}"

# Output file base name
OUT_FILE="audit_report"
for arg in "$@"; do
    if [[ "$arg" == --output=* ]]; then
        OUT_FILE="${arg#*=}"
        break
    fi
done

# Print report file names
if [[ ! " $* " =~ "--html-only" ]]; then
    echo "Text Report: ${OUT_FILE}.txt"
fi
if [[ ! " $* " =~ "--text-only" ]]; then
    echo "HTML Report: ${OUT_FILE}.html"
fi
if [[ " $* " =~ "--json" ]]; then
    echo "JSON Report: ${OUT_FILE}.json"
fi

# Auto-open HTML report (unless disabled)
if [[ ! " $* " =~ "--no-browser" ]]; then
    if command -v xdg-open &>/dev/null; then
        xdg-open "${OUT_FILE}.html" &>/dev/null
    elif command -v open &>/dev/null; then
        open "${OUT_FILE}.html" &>/dev/null
    else
        echo "Please open the HTML report manually in your browser."
    fi
fi

exit 0
# ───────────── End of Script ───────────── #
# Thank you for using ShieldOS! Stay secure! 🛡 ️