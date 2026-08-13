#!/usr/bin/env python3
import json
import os
import sys
import argparse
from typing import Dict, List, Any
from packaging.version import parse as parse_version, InvalidVersion

# Định nghĩa các dải phiên bản bị ảnh hưởng dựa trên CVE-2025-55182 & CVE-2025-66478[cite: 1]
VULNERABILITY_RULES = {
    "react": [
        {"min": "19.0.0-alpha", "max": "19.2.3", "fixed": "19.2.4"}
    ],
    "react-dom": [
        {"min": "19.0.0-alpha", "max": "19.2.3", "fixed": "19.2.4"}
    ],
    "react-server-dom-webpack": [
        {"min": "19.0.0-alpha", "max": "19.2.3", "fixed": "19.2.4"}
    ],
    "next": [
        {"min": "13.0.0", "max": "14.2.14", "fixed": "14.2.15"},
        {"min": "15.0.0", "max": "15.2.2", "fixed": "15.2.3"}
    ]
}

def check_version_vulnerable(pkg_name: str, version_str: str) -> Dict[str, Any]:
    clean_version = version_str.lstrip("^~=><")
    
    try:
        ver = parse_version(clean_version)
    except InvalidVersion:
        return {
            "is_vulnerable": False,
            "status": "UNKNOWN",
            "recommendation": f"Invalid version format: {version_str}"
        }

    rules = VULNERABILITY_RULES.get(pkg_name, [])
    for rule in rules:
        try:
            min_ver = parse_version(rule["min"])
            max_ver = parse_version(rule["max"])
            
            if min_ver <= ver <= max_ver:
                return {
                    "is_vulnerable": True,
                    "status": "VULNERABLE",
                    "recommendation": f"Upgrade {pkg_name} to >= {rule['fixed']}"
                }
        except InvalidVersion:
            continue

    return {
        "is_vulnerable": False,
        "status": "SAFE",
        "recommendation": "No action required"
    }

def scan_package_json(filepath: str) -> List[Dict[str, Any]]:
    results = []
    if not os.path.isfile(filepath):
        return results

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        dep_sections = ["dependencies", "devDependencies", "peerDependencies"]
        for section in dep_sections:
            deps = data.get(section, {})
            for pkg_name, version_spec in deps.items():
                if pkg_name in VULNERABILITY_RULES:
                    analysis = check_version_vulnerable(pkg_name, version_spec)
                    results.append({
                        "package": pkg_name,
                        "detected_version": version_spec,
                        "source_file": filepath,
                        "status": analysis["status"],
                        "is_vulnerable": analysis["is_vulnerable"],
                        "recommendation": analysis.get("recommendation", "")
                    })
    except Exception as e:
        print(f"[!] Error parsing {filepath}: {e}", file=sys.stderr)

    return results

def scan_package_lock_json(filepath: str) -> List[Dict[str, Any]]:
    results = []
    if not os.path.isfile(filepath):
        return results

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        packages = data.get("packages", {})
        for pkg_path, details in packages.items():
            pkg_name = details.get("name") or pkg_path.replace("node_modules/", "")
            if pkg_name in VULNERABILITY_RULES:
                version = details.get("version", "unknown")
                analysis = check_version_vulnerable(pkg_name, version)
                results.append({
                    "package": pkg_name,
                    "detected_version": version,
                    "source_file": filepath,
                    "status": analysis["status"],
                    "is_vulnerable": analysis["is_vulnerable"],
                    "recommendation": analysis.get("recommendation", "")
                })
    except Exception as e:
        print(f"[!] Error parsing {filepath}: {e}", file=sys.stderr)

    return results

def run_scanner(target_path: str) -> List[Dict[str, Any]]:
    findings = []
    
    # Nếu đường dẫn truyền vào là một thư mục
    if os.path.isdir(target_path):
        pkg_json = os.path.join(target_path, "package.json")
        pkg_lock = os.path.join(target_path, "package-lock.json")
        
        findings.extend(scan_package_json(pkg_json))
        findings.extend(scan_package_lock_json(pkg_lock))
    
    # Nếu đường dẫn truyền vào thẳng file .json
    elif os.path.isfile(target_path):
        if target_path.endswith("package-lock.json"):
            findings.extend(scan_package_lock_json(target_path))
        else:
            findings.extend(scan_package_json(target_path))
            
    return findings

def print_cli_report(findings: List[Dict[str, Any]]):
    print("\n=======================================================")
    print("      NeoReact2Shell Local Vulnerability Scanner       ")
    print("=======================================================\n")

    if not findings:
        print("[+] No target packages detected.")
        return

    vulnerable_count = 0
    for item in findings:
        status_symbol = "[!]" if item["is_vulnerable"] else "[+]"
        print(f"{status_symbol} Package: {item['package']}")
        print(f"    Version Detected : {item['detected_version']}")
        print(f"    Source File      : {item['source_file']}")
        print(f"    Exposure Status  : {item['status']}")
        print(f"    Recommendation   : {item['recommendation']}")
        print("-" * 55)
        if item["is_vulnerable"]:
            vulnerable_count += 1

    print(f"\nScan Complete: {len(findings)} checked, {vulnerable_count} VULNERABLE.\n")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    findings = run_scanner(target)
    print_cli_report(findings)  