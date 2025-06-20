# 🛡️ ShieldOS – Linux Hardening Audit Tool

> **Secure your Linux systems like a pro — audit, analyze, and armor-up.**

ShieldOS is an advanced yet user-friendly Linux hardening audit tool. Built with extensibility and automation in mind, it empowers system administrators and cybersecurity professionals to identify vulnerabilities, misconfigurations, and security weaknesses in their infrastructure.

## 🎯 Key Features

- 🔐 Automated security auditing across multiple hardening domains
- 📁 HTML and text report generation with clean, professional formatting
- 🧠 Smart CLI interface with modular flags for customized scanning
- 🧪 Support for dry runs, fast scans, and section-specific audits
- 📊 Optional JSON export and logging support for integration and auditing trails
- 💡 Bonus: A randomized **security tip of the day** with every run
- ⚠️ **Performance Note:** On large systems or WSL, the full audit may take a long time due to deep file permission and rootkit scans. Use the `--fast` flag or restrict scope via `--section` or `--scan-path` to reduce runtime.

---

## 🧰 Prerequisites

- Python 3.8+
- `jinja2` Python module (auto-installed if missing)
- Bash-compatible shell

---

## 🚀 Getting Started

### 🔧 Installation

```bash
git clone https://github.com/Suyashp10/ShieldOS.git
cd ShieldOS
chmod +x run_audit.sh
```

### 🧪 Run an Audit

```bash
./run_audit.sh
```

> This runs the full audit, generates both `.txt` and `.html` reports, and opens the HTML in your browser.

---

## 🖥️ CLI Usage

```bash
./run_audit.sh [options]
```

### 🔧 Core Flags

| Flag           | Description                          |
| -------------- | ------------------------------------ |
| `--html-only`  | Generate only the HTML report        |
| `--text-only`  | Generate only the text report        |
| `--no-browser` | Don't open HTML report automatically |
| `--no-color`   | Disable colored output in terminal   |

### ⚙️ Scan Control Flags

| Flag              | Description                                                                 |
| ----------------- | --------------------------------------------------------------------------- |
| `--fast`          | Skip slow checks like world-writable files (in users and advanced sections) |
| `--skip-rootkit`  | Skip rootkit detection module                                               |
| `--skip-services` | Skip the system services audit                                              |
| `--section=LIST`  | Run only selected modules (comma-separated)                                 |
| `--scan-path=LIST`| Only scan specified directories (e.g., `/etc,/home`)                        |
| `--exclude=LIST`  | Exclude specified directories from scan (e.g., `/proc,/mnt`)                |

### 📝 Output Flags

| Flag                | Description                             |
| ------------------- | --------------------------------------- |
| `--output=FILENAME` | Set base name for output reports        |
| `--json`            | Export results to `audit_report.json`   |
| `--log=LOGFILE`     | Save CLI logs to the specified log file |

### 📌 Example

```bash
# Fast audit of user and permissions modules, only HTML report generated
./run_audit.sh --fast --html-only --section=users,permissions --output=myserver_audit

# Targeted scan on /home and /etc, excluding /proc and /mnt for performance
./run_audit.sh --scan-path=/home,/etc --exclude=/proc,/mnt --fast --output=targeted_audit
```

---

## 📦 Output

After a successful run, you will find:

- `audit_report.txt`: Terminal-friendly audit summary
- `audit_report.html`: Beautifully formatted browser report
- `audit_report.json`: Optional structured data export
- Custom output filenames if `--output` is used

---

## 🧠 Tip of the Day

ShieldOS motivates good habits by displaying a randomized security tip every time you run the tool. 👨‍🏫

> 💡 *"Disable root SSH login unless absolutely necessary."*

---

## 🛡️ Contributing

ShieldOS is open-source and growing fast — contributions welcome!

```bash
# Fork → Clone → Create Feature Branch → PR 
```

Got an idea for a new module or feature? File an issue or drop a pull request.

---

## 👨‍💻 Maintainer

**Suyash Pathade**  
Computer Engineering Student @ PICT  
Cybersecurity • Linux Internals • Offensive & Defensive Tooling

> *"In the war for system security, ShieldOS is your silent sentinel."*

---

## 🔮 Roadmap Ideas

- [ ] Live dashboard mode
- [ ] Integration with systemd timers or cron
- [ ] Ansible playbook compatibility
- [ ] Notification hooks (Slack/email/webhook)
- [ ] Vuln DB integration (e.g., CVEs tied to services)