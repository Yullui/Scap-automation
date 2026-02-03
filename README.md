# Scap-automation

Automated SCAP-based Windows 11 STIG application utility.

This repository provides scripts and SCAP content to automate the application of **Security Content Automation Protocol (SCAP)** checklists for **Windows 11** hardening, aligned with STIG (Security Technical Implementation Guide) benchmarks.

SCAP is a suite of interoperable specifications defined by **NIST** that standardizes how vulnerability and configuration data is expressed and processed for automated security assessment and compliance evaluation. :contentReference[oaicite:1]{index=1}

---

## 📌 Overview

This project contains:
- **`apply_windows11_stig.py`** — Python automation script to evaluate and/or apply STIG profile settings on Windows 11.
- **`windows11_stig_catalog.yaml`** — SCAP-formatted catalog/checklist of Windows 11 STIG rules, benchmarks, or profiles to assess compliance.

The goal is to streamline compliance scanning and remediation steps against standardized security baselines using SCAP content.

---

## 🧰 Requirements

Before using this repository, ensure you have:

- **Python 3.8+** installed.
- A Windows 11 host or compatible environment for evaluating/applying STIG settings.
- SCAP engine or interpreter capable of processing SCAP content (OVAL/XCCDF), such as:
  - **OpenSCAP (or equivalent SCAP tool)** if leveraging XCCDF/OVAL scanning.
  - Windows-native SCAP/PowerShell toolchain if available.
- Required Python packages (install via `pip`):
  
