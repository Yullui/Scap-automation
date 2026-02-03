import subprocess
import logging
import os
import json
import yaml
import hashlib
from datetime import datetime, timezone
import winreg

# =========================
# CONFIGURATION
# =========================
LOG_FILE = "stig_remediation.log"
CATALOG = "windows11_stig_catalog.yaml"
REPORT_FILE = "stig_results.json"

# =========================
# LOGGING
# =========================
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S %p",
)

logger = logging.getLogger("stig")

# =========================
# GLOBAL RESULTS
# =========================
results = []

# =========================
# CORE HELPERS
# =========================
def run_ps(cmd: str) -> str:
    """Run PowerShell command safely and return stdout"""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logger.error(f"PowerShell failed: {cmd} | {result.stderr.strip()}")
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()

def record_result(stig_id, category, severity, status, details=None):
    results.append({
        "stig_id": stig_id,
        "category": category,
        "severity": severity,
        "status": status,
        "details": details,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

# =========================
# SERVICES
# =========================
def disable_service(service):
    logger.info(f"Disabling service: {service}")
    run_ps(f"Stop-Service -Name '{service}' -Force -ErrorAction SilentlyContinue")
    run_ps(f"Set-Service -Name '{service}' -StartupType Disabled")

# =========================
# FIREWALL
# =========================
def fw_block(port, proto):
    logger.info(f"Blocking port {port}/{proto}")
    run_ps(
        f'if (-not (Get-NetFirewallRule -DisplayName "STIG Block {port} {proto}" '
        f'-ErrorAction SilentlyContinue)) {{ '
        f'New-NetFirewallRule '
        f'-DisplayName "STIG Block {port} {proto}" '
        f'-Direction Inbound '
        f'-Protocol {proto} '
        f'-LocalPort {port} '
        f'-Action Block }}'
    )

def enforce_ports(control):
    port = control.get("port")
    protocols = control.get("protocol", ["TCP"])

    if control.get("action") == "disable_service_and_block":
        service = control.get("service")
        if service:
            disable_service(service)

    for proto in protocols:
        fw_block(port, proto)

    record_result(
        control.get("stig_id", "UNKNOWN"),
        "ports",
        control.get("severity", "CAT II"),
        "ENFORCED",
        f"Port {port} blocked"
    )

# =========================
# FILESYSTEM
# =========================
def remove_cert_files(paths):
    for path in paths:
        if os.path.exists(path):
            try:
                os.remove(path)
                logger.info(f"Removed file: {path}")
            except Exception as e:
                logger.error(f"Failed to remove {path}: {e}")

def enforce_default_acls():
    run_ps("icacls C:\\ /inheritance:e")

def find_duplicate_files(paths):
    hashes = {}
    duplicates = {}

    for path in paths:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as f:
                h = hashlib.sha256(f.read()).hexdigest()
            if h in hashes:
                duplicates.setdefault(h, []).append(path)
            else:
                hashes[h] = path
        except Exception as e:
            logger.error(f"Hashing failed for {path}: {e}")

    return duplicates

# =========================
# REGISTRY
# =========================
def set_registry(path, name, value, reg_type="DWORD"):
    hive_map = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
    }

    hive, subkey = path.split("\\", 1)
    key = winreg.CreateKey(hive_map[hive], subkey)

    if reg_type.upper() == "DWORD":
        winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, int(value))
    else:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(value))

    logger.info(f"Registry set: {path}\\{name} = {value}")

# =========================
# MAIN ENGINE
# =========================
def main():
    if not os.path.exists(CATALOG):
        raise FileNotFoundError("STIG catalog not found")

    with open(CATALOG, "r") as f:
        data = yaml.safe_load(f)

    controls = data.get("controls", [])

    if isinstance(controls, dict):
        controls = controls.values()

    for ctl in controls:
        try:
            if not isinstance(ctl, dict):
                continue

            vid = ctl.get("stig_id", "UNKNOWN")
            cat = ctl.get("category")
            sev = ctl.get("severity", "CAT II")

            if cat == "service":
                disable_service(ctl.get("name"))
                record_result(vid, cat, sev, "ENFORCED", ctl.get("name"))

            elif cat == "ports":
                enforce_ports(ctl)

            elif cat == "filesystem":
                if ctl.get("action") == "remove_cert_files":
                    remove_cert_files(ctl.get("paths", []))
                elif ctl.get("action") == "enforce_default_acls":
                    enforce_default_acls()
                record_result(vid, cat, sev, "ENFORCED", ctl.get("action"))

            elif cat == "registry":
                set_registry(
                    ctl.get("path"),
                    ctl.get("name"),
                    ctl.get("value"),
                    ctl.get("type", "DWORD"),
                )
                record_result(vid, cat, sev, "ENFORCED", ctl.get("name"))

            else:
                record_result(vid, cat, sev, "SKIPPED", "Unknown category")

        except Exception as e:
            logger.error(f"STIG {vid} failed: {e}")
            record_result(vid, cat, sev, "FAIL", str(e))

    with open(REPORT_FILE, "w") as r:
        json.dump(results, r, indent=2)

    logger.info("STIG remediation completed")

# =========================
# ENTRY POINT
# =========================
if __name__ == "__main__":
    main()
