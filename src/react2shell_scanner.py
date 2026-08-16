import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional

# python src/react2shell_scanner.py lab/vulnerable
# python src/react2shell_scanner.py lab/patched

# Unified CVE for the React2Shell vulnerability
CVE_ID = "CVE-2025-55182"

# Affected version ranges based on official advisories
VULNERABILITY_RULES = {
    "react": [
        {"min": "19.0.0-alpha", "max": "19.0.0-rc", "fixed": "19.0.1"}
    ],
    "react-dom": [
        {"min": "19.0.0-alpha", "max": "19.0.0-rc", "fixed": "19.0.1"}
    ],
    "react-server-dom-webpack": [
        {"min": "19.0.0-alpha", "max": "19.0.0-rc", "fixed": "19.0.1"}
    ],
    "react-server-dom-parcel": [
        {"min": "19.0.0-alpha", "max": "19.0.0-rc", "fixed": "19.0.1"}
    ],
    "react-server-dom-turbopack": [
        {"min": "19.0.0-alpha", "max": "19.0.0-rc", "fixed": "19.0.1"}
    ],
    "next": [
        {"min": "13.0.0", "max": "14.2.14", "fixed": "14.2.15"},
        {"min": "15.0.0-canary.0", "max": "15.0.0-rc.0", "fixed": "15.0.1"}
    ]
}

def parse_semver(version_str: str) -> Optional[Tuple[int, int, int, str]]:
    """Parse version string into (major, minor, patch, prerelease)."""
    if not isinstance(version_str, str):
        return None
    
    clean_str = version_str.strip().lstrip("^~>=<v ")
    # Match semver pattern: e.g. 19.0.0-rc-65a56d0e-20241020 or 14.2.10
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?", clean_str)
    if not match:
        return None
        
    major, minor, patch, prerelease = match.groups()
    return (int(major), int(minor), int(patch), prerelease or "")

def compare_semver(v1: Tuple[int, int, int, str], v2: Tuple[int, int, int, str]) -> int:
    """Compare two semver tuples."""
    if v1[:3] != v2[:3]:
        return -1 if v1[:3] < v2[:3] else 1
    
    pre1, pre2 = v1[3], v2[3]
    if not pre1 and pre2:
        return 1
    if pre1 and not pre2:
        return -1
    if pre1 == pre2:
        return 0
    return -1 if pre1 < pre2 else 1

def check_version_status(pkg_name: str, version_str: str) -> Dict[str, Any]:
    """Evaluate version string against security rules."""
    parsed_target = parse_semver(version_str)
    
    if not parsed_target:
        return {
            "status": "UNKNOWN",
            "severity": "LOW",
            "recommendation": f"Invalid version format ({version_str}). Manual review required."
        }

    major, minor, patch, prerelease = parsed_target

    # Direct check for React 19 pre-releases (alpha, rc, canary)
    if pkg_name in {"react", "react-dom", "react-server-dom-webpack", "react-server-dom-parcel", "react-server-dom-turbopack"}:
        if major == 19 and minor == 0 and patch == 0:
            # Any 19.0.0 pre-release tag (rc, alpha, canary, commit hash) is vulnerable
            if prerelease:
                return {
                    "status": "VULNERABLE",
                    "severity": "CRITICAL",
                    "recommendation": f"Upgrade {pkg_name} to >= 19.0.1 immediately."
                }

    # Direct check for Next.js vulnerable ranges
    if pkg_name == "next":
        # Next.js 13.x & 14.x (< 14.2.15)
        if (major == 13) or (major == 14 and (minor < 2 or (minor == 2 and patch < 15))):
            return {
                "status": "VULNERABLE",
                "severity": "CRITICAL",
                "recommendation": "Upgrade next to >= 14.2.15 immediately."
            }
        # Next.js 15.x pre-releases
        if major == 15 and minor == 0 and patch == 0 and prerelease:
            return {
                "status": "VULNERABLE",
                "severity": "CRITICAL",
                "recommendation": "Upgrade next to >= 15.0.1 immediately."
            }

    return {
        "status": "PATCHED",
        "severity": "NONE",
        "recommendation": "No vulnerability detected for this package."
    }

def load_json(path: Path) -> Dict[str, Any]:
    """Safe load JSON file content."""
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def scan_project(project_dir: Path) -> List[Dict[str, Any]]:
    """Scan package.json and package-lock.json for affected dependencies."""
    pkg_file = project_dir / "package.json"
    lock_file = project_dir / "package-lock.json"

    if not pkg_file.exists():
        raise FileNotFoundError("package.json not found in target directory.")

    pkg_data = load_json(pkg_file)
    lock_data = load_json(lock_file) if lock_file.exists() else {}

    # Extract declared dependencies
    declared_deps = {}
    for section in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
        declared_deps.update(pkg_data.get(section, {}))

    # Extract locked dependencies
    locked_deps = {}
    if lock_data:
        packages = lock_data.get("packages", {})
        for pkg_path, details in packages.items():
            if not pkg_path or not isinstance(details, dict):
                continue
            pkg_name = details.get("name") or pkg_path.split("node_modules/")[-1]
            version = details.get("version")
            if pkg_name and version:
                locked_deps[pkg_name] = version

    findings = []
    target_packages = set(VULNERABILITY_RULES.keys())
    scanned_packages = target_packages.intersection(set(declared_deps.keys()).union(set(locked_deps.keys())))

    for pkg_name in sorted(scanned_packages):
        if pkg_name in locked_deps:
            version = locked_deps[pkg_name]
            source = "package-lock.json"
        else:
            version = declared_deps[pkg_name]
            source = "package.json"

        eval_result = check_version_status(pkg_name, version)
        
        findings.append({
            "package": pkg_name,
            "version": version,
            "source": source,
            "status": eval_result["status"],
            "severity": eval_result["severity"],
            "cve": CVE_ID,
            "recommendation": eval_result["recommendation"]
        })

    return findings

def print_cli_table(findings: List[Dict[str, Any]], project_dir: Path):
    """Print clean terminal output."""
    print("\n" + "-" * 70)
    print("           NEOREACT2SHELL LOCAL DEPENDENCY SCANNER")
    print("-" * 70)
    print(f"Target Directory : {project_dir.resolve()}")
    print(f"Target CVE       : {CVE_ID}")
    print(f"Total Detected   : {len(findings)} target package(s)")
    print("-" * 70)

    if not findings:
        print("[+] No React Server Components or Next.js packages detected.")
        print("=" * 70 + "\n")
        return

    vulnerable_cnt = 0
    for idx, item in enumerate(findings, 1):
        symbol = "[!]" if item["status"] == "VULNERABLE" else "[+]"
        print(f"{symbol} [{idx}] Package      : {item['package']}")
        print(f"    Version      : {item['version']}")
        print(f"    Source       : {item['source']}")
        print(f"    Status       : {item['status']}")
        print(f"    Severity     : {item['severity']}")
        print(f"    Action       : {item['recommendation']}")
        print("-" * 70)
        
        if item["status"] == "VULNERABLE":
            vulnerable_cnt += 1

    print("SCAN SUMMARY:")
    print(f"  - Total Scanned : {len(findings)}")
    print(f"  - Vulnerable    : {vulnerable_cnt}")
    print(f"  - Patched/Safe  : {len(findings) - vulnerable_cnt}")
    print("=" * 70 + "\n")

def main():
    parser = argparse.ArgumentParser(description="Local React2Shell dependency scanner")
    parser.add_argument("project", nargs="?", default=".", help="Path to project directory (default: current dir)")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()
    project_path = Path(args.project)

    if not project_path.is_dir():
        print(f"Error: Target path '{project_path}' is not a valid directory.", file=sys.stderr)
        return 2

    try:
        findings = scan_project(project_path)
    except Exception as err:
        print(f"Error during scan: {err}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        print_cli_table(findings, project_path)

    if any(f["status"] == "VULNERABLE" for f in findings):
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())