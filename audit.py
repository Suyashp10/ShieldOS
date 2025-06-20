import subprocess
import os 
import stat
import datetime
import json
import traceback
import time
import webbrowser
import glob
import argparse
from jinja2 import Environment, FileSystemLoader
from html_export_utils import (
    format_check_result,
    summarize_results
)

os.makedirs("reports", exist_ok=True)

def parse_arguments():
    parser = argparse.ArgumentParser(description="ShieldOS - Linux Hardening Audit Tool")

    parser.add_argument('--html-only', action='store_true', help="Generate only the HTML report (skip .txt)")
    parser.add_argument('--text-only', action='store_true', help="Generate only the text report (skip .html)")
    parser.add_argument('--no-browser', action='store_true', help="Prevent auto-opening of the HTML report")
    parser.add_argument('--no-color', action='store_true', help="Disable colored terminal output")
    parser.add_argument('--verbose', action='store_true', help="Print detailed debug logs while auditing")
    parser.add_argument('--skip-rootkit', action='store_true', help="Skip rootkit scan")
    parser.add_argument('--skip-services', action='store_true', help="Skip service audit")
    parser.add_argument('--fast', action='store_true', help="Skip slow checks like world-writable files")
    parser.add_argument('--output', type=str, default="audit_report", help="Specify base name for report files")
    parser.add_argument('--section', type=str, help="Only audit selected sections (comma-separated: firewall,ssh,services,etc.)")
    parser.add_argument('--json', action='store_true', help="Export results to audit_report.json")
    parser.add_argument('--scan-path', default='/', help="Comma-separated paths to scan")
    parser.add_argument('--exclude', default='/proc,/sys,/dev,/run,/snap,/mnt', help="Comma-separated paths to exclude")

    return parser.parse_args()

def check_os_version():
    try:
        name = version = "Unknown"

        with open("/etc/os-release", "r") as f:
            for line in f:
                if line.startswith("NAME=") and name == "Unknown":
                    name = line.split('=', 1)[1].strip().strip('"')
                elif line.startswith("VERSION=") and version == "Unknown":
                    version = line.split('=', 1)[1].strip().strip('"')

        if name != "Unknown" or version != "Unknown":
            return [format_check_result(
                "OS Version",
                f"Operating System: {name} {version}",
                "info"
            )]
        else:
            return [format_check_result(
                "OS Version",
                "Unable to determine OS version.",
                "warn"
            )]

    except FileNotFoundError:
        return [format_check_result(
            "OS Version",
            "/etc/os-release file not found.",
            "warn"
        )]
    except Exception as e:
        return [format_check_result(
            "OS Version",
            f"Error checking OS version: {e}",
            "warn"
        )]

def check_firewall_status():
    try:
        result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
        status = result.stdout.strip().lower()
        if "inactive" in status:
            return [format_check_result("Firewall status", "Firewall is inactive.", "fail", "Enable the firewall using 'ufw enable' or configure iptables.")]
        elif "active" in status:
            if "allow" in status or "deny" in status:
                return [format_check_result("Firewall status", "Firewall is active and configured.", "pass")]
            else:
                return [format_check_result("Firewall status", "Firewall is active but no rules are defined.", "warn", "Consider adding rules to allow only necessary traffic.")]
        else:
            return [format_check_result("Firewall status", "Unable to determine firewall status.", "warn")]
    except Exception as e:
        return [format_check_result("Firewall status", f"Error checking firewall status: {e}", "warn")]
    
def check_ssh_status():
    try:
        result = subprocess.run(['systemctl', 'is-active', 'ssh'], capture_output=True, text=True)
        status = result.stdout.strip().lower()
        if status == "inactive":
            return [format_check_result("SSH Service status", "SSH service is not running.", "fail", "Disable SSH if not needed, or ensure it is securely configured.")]
        elif status == "active":
            return [format_check_result("SSH Service status", "SSH service is running.", "pass")]
        elif status in ["failed", "deactivating"]:
            return [format_check_result("SSH Service status", f"SSH service status is '{status}' — not secure.", "fail")]
        else:
            return [format_check_result("SSH Service status", f"SSH service status is '{status}' — unclear.", "warn")]
    except FileNotFoundError:
            return [format_check_result("SSH Service status", "SSH service not found. Is SSH installed?", "warn")]
    except PermissionError:
        return [format_check_result("SSH Service status", "Permission denied while checking SSH service status.", "warn")]
    except Exception as e:
        return [format_check_result("SSH Service status", f"Error checking SSH status: {e}", "warn")]



def check_ssh_root_login():
    try:
        ssh_config_files = ["/etc/ssh/sshd_config"] + sorted(
            glob.glob("/etc/ssh/sshd_config.d/*.conf")
        )

        last_value = None
        conflicting_values = set()

        for file in ssh_config_files:
            try:
                with open(file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.split()[0] == "PermitRootLogin":
                            value = line.split()[1].lower()
                            conflicting_values.add(value)
                            last_value = value
            except FileNotFoundError:
                continue
            except PermissionError:
                return [format_check_result(
                    "SSH Root Login",
                    f"Permission denied while accessing {file}.",
                    "warn"
                )]

        if last_value is None:
            return [format_check_result(
                "SSH Root Login",
                "PermitRootLogin directive not found in any SSH config.",
                "warn"
            )]

        if len(conflicting_values) > 1:
            status = "warn"
            message = f"Conflicting PermitRootLogin values found: {', '.join(conflicting_values)}. Last applied value: {last_value}"
        elif last_value == "no":
            status = "pass"
            message = "Root login via SSH is disabled."
        elif last_value == "yes":
            status = "fail"
            message = "Root login via SSH is enabled."
        else:
            status = "warn"
            message = f"PermitRootLogin is set to '{last_value}' — unclear behavior."

        return [format_check_result(
            "SSH Root Login",
            message,
            status,
            "Edit /etc/ssh/sshd_config or any .conf override and set 'PermitRootLogin no'. Restart SSH."
            if status != "pass" else None
        )]

    except Exception as e:
        return [format_check_result(
            "SSH Root Login",
            f"Error checking SSH root login: {e}",
            "warn"
        )]

def check_file_permissions(file_path, expected_octal):
    try:
        file_stat = os.stat(file_path)
        actual_mode = stat.S_IMODE(file_stat.st_mode)
        symbolic = stat.filemode(file_stat.st_mode)

        if actual_mode == expected_octal:
            description = f"{file_path} permissions are correct ({symbolic}, {oct(actual_mode)})."
            return [format_check_result(file_path, description, "pass")]
        else:
            description = (
                f"{file_path} permissions are {symbolic} ({oct(actual_mode)}), "
                f"expected {oct(expected_octal)}."
            )
            recommendation = f"Fix using: chmod {oct(expected_octal)} {file_path}"
            return [format_check_result(file_path, description, "fail", recommendation)]

    except FileNotFoundError:
        return [format_check_result(file_path, f"{file_path} not found.", "warn")]
    except PermissionError:
        return [format_check_result(file_path, f"Permission denied while accessing {file_path}.", "warn")]
    except Exception as e:
        return [format_check_result(file_path, f"Error checking {file_path}: {e}", "warn")]

def run_file_permission_audit():
    critical_files = {
        "/etc/passwd": 0o644,     # -rw-r--r-- : OK — required by system
        "/etc/shadow": 0o600,     # -rw------- : STRONGLY recommended (640 is too loose)
        "/etc/group": 0o644,      # -rw-r--r-- : OK
        "/etc/gshadow": 0o600,    # -rw------- : Like shadow, secure group info
        "/etc/sudoers": 0o440,    # -r--r----- : Secure to avoid privilege escalation
    }
    
    results = []
    for file_path, expected_octal in critical_files.items():
        results.extend(check_file_permissions(file_path, expected_octal))

    return results

def check_rootkits_with_chkrootkit():
    results = []
    try:
        result = subprocess.run(['chkrootkit'], capture_output=True, text=True)
        output = result.stdout

        suspicious_lines = [
            line for line in output.split('\n')
            if 'INFECTED' in line or 'not found' in line
        ]

        if suspicious_lines:
            for line in suspicious_lines:
                results.append(format_check_result(
                    "chkrootkit",
                    line,
                    "fail",
                    "Investigate and remove suspicious binaries manually or with a malware removal tool."
                ))
        else:
            results.append(format_check_result(
                "chkrootkit",
                "No rootkit signatures detected by chkrootkit.",
                "pass"
            ))

    except FileNotFoundError:
        results.append(format_check_result(
            "chkrootkit",
            "chkrootkit is not installed.",
            "warn"
        ))

    except Exception as e:
        results.append(format_check_result(
            "chkrootkit",
            f"Error running chkrootkit: {e}",
            "warn"
        ))

    return results


def manual_rootkit_scan():
    results = []

    suspicious_paths = [
        '/dev/.udev', '/dev/.tmp', '/dev/.static',
        '/lib/.something', '/usr/lib/libkeystroke.so', '/usr/lib/libproc.so'
    ]

    for path in suspicious_paths:
        if os.path.exists(path):
            results.append(format_check_result(
                "Manual Rootkit Scan",
                f"Suspicious path detected: {path}",
                "fail",
                "Investigate and remove unauthorized hidden directories."
            ))

    try:
        suid_output = subprocess.getoutput("find / -perm -4000 -type f 2>/dev/null")
        flagged_suid = [
            line for line in suid_output.split('\n')
            if any(term in line.lower() for term in ['nmap', 'netcat', '/tmp'])
        ]

        for suid in flagged_suid:
            results.append(format_check_result(
                "Manual Rootkit Scan",
                f"Suspicious SUID binary: {suid}",
                "fail",
                "Investigate and remove or restrict execution of this binary."
            ))

    except Exception as e:
        results.append(format_check_result(
            "Manual Rootkit Scan",
            f"Error checking SUID binaries: {e}",
            "warn"
        ))

    if not results:
        results.append(format_check_result(
            "Manual Rootkit Scan",
            "No suspicious files or binaries detected manually.",
            "pass"
        ))

    return results

def export_to_textfile(results: list, filename="audit_report.txt"):
    try:
        os.makedirs("reports", exist_ok=True)
        path = os.path.join("reports", filename)
        with open(path, "w") as f:
            f.write(f"Linux Hardening Audit Report\nGenerated: {datetime.datetime.now()}\n")
            f.write("====================================\n\n")
            for item in results:
                if isinstance(item, dict):
                    f.write(f"[{item['status'].upper()}] {item['name']}\n")
                    f.write(f"  - {item['description']}\n")
                    if item.get('recommendations'):
                        f.write(f"  → Recommendation: {item['recommendations']}\n")
                    f.write("\n")
                else:
                    f.write(str(item) + "\n")
        print(f"Text report saved to 'reports/{filename}'")
    except Exception as e:
        print(f"Failed to export report: {e}")


def detect_os():
    try:
        with open("/etc/os-release", "r") as f:
            for line in f:
                if line.startswith("ID="):
                    return line.strip().split("=")[1].strip('"')
    except:
        return "unknown"

def get_known_safe_services():
    os_id = detect_os()

    ubuntu_services = {
        'ssh.service', 'cron.service', 'rsyslog.service', 'ufw.service',
        'snapd.service', 'systemd-journald.service', 'systemd-logind.service', 'dbus.service'
    }

    centos_services = {
        'sshd.service', 'crond.service', 'rsyslog.service', 'firewalld.service',
        'systemd-journald.service', 'systemd-logind.service', 'dbus.service'
    }

    if os_id in ['ubuntu', 'debian']:
        return ubuntu_services
    elif os_id in ['centos', 'rhel', 'fedora']:
        return centos_services
    else:
        return set()  


def audit_running_services():
    results = []

    try:
        result = subprocess.run(
            ['systemctl', 'list-units', '--type=service', '--state=running'],
            capture_output=True, text=True
        )
        output = result.stdout.strip()
        running_services = [
            line.split()[0] for line in output.split('\n') if ".service" in line
        ]

        if not running_services:
            results.append(format_check_result(
                "Running Services",
                "No running services found.",
                "warn"
            ))
            return results, 0, 0

        known_safe = {s.lower() for s in get_known_safe_services()}
        safe_count = suspicious_count = 0

        for svc in running_services:
            svc_lower = svc.lower()
            if svc_lower in known_safe:
                results.append(format_check_result(
                    "Running Services",
                    f"{svc} is a known safe service.",
                    "pass"
                ))
                safe_count += 1
            else:
                results.append(format_check_result(
                    "Running Services",
                    f"{svc} is a suspicious or unknown service.",
                    "fail",
                    f"Review the purpose of '{svc}' and disable it if unnecessary (e.g., 'systemctl disable {svc}')."
                ))
                suspicious_count += 1

        results.append(format_check_result(
            "Running Services",
            f"Total running services: {len(running_services)}",
            "info"
        ))
        results.append(format_check_result(
            "Running Services",
            f"Safe services: {safe_count}, Suspicious services: {suspicious_count}",
            "info"
        ))

        return results, safe_count, suspicious_count

    except Exception as e:
        return [format_check_result(
            "Running Services",
            f"Error auditing services: {e}",
            "warn"
        )], 0, 0

def check_world_writable_files(scan_paths, exclude_paths):
    try:
        find_cmd = ["find"] + scan_paths + ["-type", "f", "-perm", "-0002"]
        for path in exclude_paths:
            find_cmd += ["!", "-path", f"{path}/*"]

        result = subprocess.check_output(find_cmd, stderr=subprocess.DEVNULL, text=True)
        files = [f for f in result.strip().split('\n') if f.strip()]

        if files:
            results = [format_check_result(
                "World Writable Files",
                f"Found {len(files)} world-writable files (showing up to 10):",
                "fail"
            )]
            for idx, file in enumerate(files[:10], 1):
                results.append(format_check_result(
                    "World Writable Files",
                    f"{idx}. {file}",
                    "fail",
                    f"Remove world-writable permission using: chmod o-w '{file}'"
                ))
            return results
        else:
            return [format_check_result(
                "World Writable Files",
                "No world writable files found.",
                "pass"
            )]
    except Exception as e:
        return [format_check_result(
            "World Writable Files",
            f"Error checking world writable files: {e}",
            "warn"
        )]

    
def check_uid_0_users():
    try:
        result = subprocess.getoutput("awk -F: '($3 == 0) {print $1}' /etc/passwd")
        users = [u for u in result.split('\n') if u.strip()]

        if not users:
            return [format_check_result(
                "UID 0 Users",
                "No users with UID 0 found — this is unusual.",
                "warn"
            )]
        elif len(users) == 1 and users[0] == 'root':
            return [format_check_result(
                "UID 0 Users",
                "Only root user has UID 0.",
                "pass"
            )]
        else:
            return [format_check_result(
                "UID 0 Users",
                f"Multiple users with UID 0 found: {', '.join(users)}",
                "fail",
                "Remove or reassign UID 0 accounts not intended for administrative use."
            )]

    except Exception as e:
        return [format_check_result(
            "UID 0 Users",
            f"Error checking UID 0 users: {e}",
            "warn"
        )]
    
def check_passwordless_sudo():
    try:
        result = subprocess.getoutput(
            "grep -E '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null"
        )
        entries = [line for line in result.strip().split('\n') if line.strip()]

        if entries:
            results = [format_check_result(
                "Passwordless Sudo",
                f"Found {len(entries)} NOPASSWD entries (showing up to 5):",
                "fail",
                "Remove or restrict NOPASSWD entries in /etc/sudoers and /etc/sudoers.d/"
            )]
            for entry in entries[:5]:
                results.append(format_check_result(
                    "Passwordless Sudo",
                    f"  - {entry.strip()}",
                    "fail"
                ))
            return results
        else:
            return [format_check_result(
                "Passwordless Sudo",
                "No passwordless sudoers found.",
                "pass"
            )]

    except Exception as e:
        return [format_check_result(
            "Passwordless Sudo",
            f"Error checking passwordless sudo: {e}",
            "warn"
        )]

def check_empty_password_users():
    try:
        result = subprocess.getoutput("awk -F: '($2 == \"\") {print $1}' /etc/shadow")
        users = [u for u in result.split('\n') if u.strip()]

        if users:
            user_list = ", ".join(users[:10]) + ("..." if len(users) > 10 else "")
            return [format_check_result(
                "Empty Passwords",
                f"Users with empty passwords found: {user_list}",
                "fail",
                "Lock these accounts or set strong passwords immediately using 'passwd -l username'."
            )]
        else:
            return [format_check_result(
                "Empty Passwords",
                "No users with empty passwords found.",
                "pass"
            )]

    except Exception as e:
        return [format_check_result(
            "Empty Passwords",
            f"Error checking empty password users: {e}",
            "warn"
        )]

def check_privileged_groups():
    try:
        privileged_groups = ['sudo', 'wheel', 'admin']
        results = []

        for group in privileged_groups:
            group_info = subprocess.getoutput(f"getent group {group}").strip()

            if not group_info:
                results.append(format_check_result(
                    "Privileged Group Check",
                    f"Group '{group}' does not exist.",
                    "warn"
                ))
                continue

            parts = group_info.split(':')
            if len(parts) >= 4 and parts[3]:
                members = [m.strip() for m in parts[3].split(',') if m.strip()]
                if members:
                    member_list = ', '.join(members[:5]) + ("..." if len(members) > 5 else "")
                    results.append(format_check_result(
                        "Privileged Group Check",
                        f"Group '{group}' has members: {member_list}",
                        "fail",
                        f"Remove unnecessary users from '{group}' using: gpasswd -d username {group}"
                    ))
                else:
                    results.append(format_check_result(
                        "Privileged Group Check",
                        f"Group '{group}' exists but has no members.",
                        "pass"
                    ))
            else:
                results.append(format_check_result(
                    "Privileged Group Check",
                    f"Group '{group}' exists but member list is empty.",
                    "pass"
                ))

        return results

    except Exception as e:
        return [format_check_result(
            "Privileged Group Check",
            f"Error checking privileged groups: {e}",
            "warn"
        )]

def check_disabled_users():
    try:
        result = subprocess.getoutput(
            "awk -F: '($7 == \"/sbin/nologin\" || $7 == \"/bin/false\") {print $1}' /etc/passwd"
        )
        users = [u for u in result.split('\n') if u.strip()]

        if users:
            user_list = ', '.join(users[:10]) + ("..." if len(users) > 10 else "")
            return [format_check_result(
                "Disabled Accounts",
                f"Users with login disabled: {user_list}",
                "info",
                "No action needed unless any of these users are expected to be active."
            )]
        else:
            return [format_check_result(
                "Disabled Accounts",
                "No disabled user accounts found.",
                "pass"
            )]

    except Exception as e:
        return [format_check_result(
            "Disabled Accounts",
            f"Error checking disabled users: {e}",
            "warn"
        )]

def check_unattended_upgrades():
    try:
        result = subprocess.run(
            ['dpkg', '-l', 'unattended-upgrades'],
            capture_output=True,
            text=True
        )
        output = result.stdout.strip().split('\n')

        installed = False
        for line in output:
            if line.startswith('ii') and 'unattended-upgrades' in line:
                installed = True
                break

        if installed:
            return [format_check_result(
                "Unattended Upgrades",
                "Unattended upgrades are installed.",
                "pass"
            )]
        else:
            return [format_check_result(
                "Unattended Upgrades",
                "Unattended upgrades are not installed.",
                "fail",
                "Install it using: sudo apt install unattended-upgrades"
            )]

    except Exception as e:
        return [format_check_result(
            "Unattended Upgrades",
            f"Error checking unattended upgrades: {e}",
            "warn"
        )]
    
def check_login_banner():
    try:
        paths = ["/etc/issue.net", "/etc/motd"]
        found_banner = False
        results = []

        for path in paths:
            if os.path.exists(path):
                with open(path, "r") as f:
                    content = f.read().strip()

                if content:
                    preview = content[:150] + ("..." if len(content) > 150 else "")
                    results.append(format_check_result(
                        "Login Banner",
                        f"Login banner set in {path}:\n\"{preview}\"",
                        "pass"
                    ))
                    found_banner = True
                else:
                    results.append(format_check_result(
                        "Login Banner",
                        f"Login banner file {path} exists but is empty.",
                        "fail",
                        f"Add a legal warning message to {path} (e.g., unauthorized access is prohibited)."
                    ))
            else:
                results.append(format_check_result(
                    "Login Banner",
                    f"Login banner file {path} does not exist.",
                    "warn"
                ))

        if found_banner:
            return results
        else:
            results.append(format_check_result(
                "Login Banner",
                "No valid login banner found.",
                "fail",
                "Set a login banner in /etc/issue.net or /etc/motd for legal compliance."
            ))
            return results

    except Exception as e:
        return [format_check_result(
            "Login Banner",
            f"Error checking login banner: {e}",
            "warn"
        )]
    
def check_audit_logging():
    try:
        audit_config_path = "/etc/audit/auditd.conf"

        if not os.path.exists(audit_config_path):
            return [format_check_result(
                "Audit Logging",
                f"Audit configuration file {audit_config_path} does not exist.",
                "fail",
                "Install and configure auditd to enable system audit logging."
            )]

        log_file_path = None

        with open(audit_config_path, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("log_file") and not line.startswith("#"):
                    parts = line.split('=', 1)
                    if len(parts) == 2:
                        log_file_path = parts[1].strip()
                        break

        if log_file_path:
            if os.path.exists(log_file_path):
                return [format_check_result(
                    "Audit Logging",
                    f"Audit logging is enabled. Logs are stored at: {log_file_path}",
                    "pass"
                )]
            else:
                return [format_check_result(
                    "Audit Logging",
                    f"log_file directive is set to '{log_file_path}', but the file does not exist.",
                    "fail",
                    "Verify auditd is running and has permission to write logs to this file."
                )]
        else:
            return [format_check_result(
                "Audit Logging",
                "Audit config exists but no valid 'log_file' directive was found.",
                "warn",
                "Ensure 'log_file' is set correctly in /etc/audit/auditd.conf"
            )]

    except Exception as e:
        return [format_check_result(
            "Audit Logging",
            f"Error checking audit logging: {e}",
            "warn"
        )]

def run_firewall_ssh_checks():
    results = ["===Firewall and SSH Checks==="]
    results.append(check_firewall_status())
    results.append(check_ssh_status())
    results.append(check_ssh_root_login())
    return results

def run_file_permission_audits():
    results = ["\n===File Permission Audit==="]
    results.extend(run_file_permission_audit())
    return results

def run_rootkit_checks():
    results = ["\n===Rootkit Checks==="]
    results.extend(check_rootkits_with_chkrootkit())
    results.extend(manual_rootkit_scan())
    return results

def run_user_account_security_checks(scan_paths, exclude_paths, fast=False):
    results = ["\n===User Account Security Checks==="]
    results.append(check_world_writable_files(scan_paths, exclude_paths))
    results.append(check_uid_0_users())
    results.append(check_passwordless_sudo())
    results.append(check_empty_password_users())
    results.extend(check_privileged_groups())
    results.append(check_disabled_users())
    return results

def run_service_audit():
    results = ["\n===Service Audit==="]
    service_results, safe_count, suspicious_count = audit_running_services()
    results.extend(service_results)
    results.append(f"\nService Audit Summary:\n----------------------\n"
                   f"Safe Services     : {safe_count}\n"
                   f"Suspicious Services: {suspicious_count}\n"
                   f"Total Running       : {safe_count + suspicious_count}\n")
    return results, safe_count, suspicious_count

def run_advanced_hardening_checks(scan_paths, exclude_paths, fast=False):
    results = ["\n===Advanced System Hardening Checks==="]
    results.extend(check_world_writable_files(scan_paths, exclude_paths))
    results.extend(check_passwordless_sudo())
    results.extend(check_unattended_upgrades())
    results.extend(check_login_banner())
    results.extend(check_audit_logging())
    return results

def export_to_html(sections, filename="audit_report.html"):
    try:
        os.makedirs("reports", exist_ok=True)
        template_dir = os.path.dirname(os.path.abspath(__file__))
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template("report_template.html")
        summary = summarize_results(sections)

        html_output = template.render(
            title="Linux Hardening Audit Report",
            timestamp=datetime.datetime.now().strftime("%A %d %B %Y %H:%M:%S"),
            sections=sections,
            total_items=summary["total_items"],
            passed=summary["passed"],
            failed=summary["failed"],
            warnings=summary["warnings"],
            info=summary["info"]
        )

        path = os.path.join("reports", filename)
        with open(path, "w") as f:
            f.write(html_output)

        print(f"HTML report saved to 'reports/{filename}'")
    except Exception as e:
        print("Failed to export HTML report.")
        traceback.print_exc()


def export_to_json(results, filename="audit_report.json"):
    try:
        os.makedirs("reports", exist_ok=True)
        path = os.path.join("reports", filename)
        with open(path, "w") as f:
            json.dump(results, f, indent=4, default=str)
        print(f"JSON report saved to 'reports/{filename}'")
    except Exception as e:
        print(f"Failed to export JSON report: {e}")


def calculate_score(results):
    passed = failed = warning = 0

    for line in results:
        line_lower = line.lower()
        if "no suspicious" in line_lower or "is active" in line_lower:
            passed += 1
        elif "is enabled" in line_lower or "suspicious" in line_lower:
            failed += 1
        elif "unclear" in line_lower or "not found" in line_lower:
            warning += 1

    total = passed + failed + warning
    score = f"""
==============================
Linux Hardening Scorecard
==============================
Passed    : {passed}
Failed    : {failed}
Warnings  : {warning}
Final Score: {passed} / {total} ({'Secure' if failed == 0 else 'Needs Attention'})
==============================
"""
    return score.strip()



if __name__ == "__main__":
    args = parse_arguments()
    
    sections = []
    selected = [s.strip().lower() for s in args.section.split(',')] if args.section else []
    scan_paths = args.scan_path.split(',')  # turns "/etc,/home" into ['/etc', '/home']
    exclude_paths = args.exclude.split(',') # same for exclusions
    print("[*] Starting Linux Hardening Audit...")
    if not selected or 'system' in selected:
        print("[*] Running System Information Check...")
        sections.append({"heading": "System Information", "items": check_os_version()})

    if not selected or 'firewall' in selected:
        print("[*] Running Firewall and SSH Checks...")
        sections.append({"heading": "Firewall and SSH Checks", "items": run_firewall_ssh_checks()})

    if not selected or 'permissions' in selected:
        print("[*] Running File Permission Audit...")
        sections.append({"heading": "File Permission Audit", "items": run_file_permission_audit()})

    if not selected or 'rootkit' in selected:
        if args.skip_rootkit:
            print("[*] Skipping Rootkit Checks as requested.")
        else:
            print("[*] Performing Rootkit Scan...")
            sections.append({"heading": "Rootkit Checks", "items": run_rootkit_checks()})

    if not selected or 'users' in selected:
        print("[*] Running User Account Security Checks...")
        sections.append({"heading": "User Account Security", "items": run_user_account_security_checks(scan_paths, exclude_paths, fast=args.fast)})

    safe_count = suspicious_count = 0
    if not selected or 'services' in selected:
        if args.skip_services:
            print("[*] Skipping Service Audit as requested.")
        else:
            print("[*] Auditing Running Services...")
            service_results, safe_count, suspicious_count = audit_running_services()
            sections.append({"heading": "Service Audit", "items": service_results})

    if not selected or 'advanced' in selected:
        print("[*] Running Advanced System Hardening Checks...")
        sections.append({"heading": "Advanced Hardening", "items": run_advanced_hardening_checks(scan_paths, exclude_paths, fast=args.fast)})

    print("[*] Generating Scorecard Summary...")
    scorecard = summarize_results(sections)
    sections.append({
        "heading": "Scorecard Summary",
        "items": [
            format_check_result(
                "Score Summary",
                f"Passed: {scorecard['passed']}, Failed: {scorecard['failed']}, "
                f"Warnings: {scorecard['warnings']}, Info: {scorecard['info']}, "
                f"Total Checks: {scorecard['total_items']}",
                "info"
            )
        ]
    })

    base_filename = args.output
    flat_results = [item for sec in sections for item in sec['items']]

    if not args.html_only:
        print("[*] Exporting to Text File...")
        export_to_textfile(flat_results, filename=f"{base_filename}.txt")

    if not args.text_only:
        print("[*] Exporting to HTML Report...")
        export_to_html(sections, filename=f"{base_filename}.html")
        if not args.no_browser:
            print("[*] Opening HTML Report in Browser...")
            webbrowser.open(f"file://{os.path.abspath(base_filename)}.html")

    if args.json:
        print("[*] Exporting to JSON...")
        export_to_json(flat_results, filename=f"{base_filename}.json")

    print("\nAudit complete!")
    if not args.html_only:
        print(f"Text Report: {base_filename}.txt")
    if not args.text_only:
        print(f"HTML Report: {base_filename}.html")
    if args.json:
        print(f"JSON Report: {base_filename}.json")
