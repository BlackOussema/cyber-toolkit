#!/usr/bin/env python3
"""
CyberToolkit APK Analyzer - Professional Android Security Analysis

Static analysis tool for Android APK files with support for:
- APK decompilation (apktool, jadx)
- Manifest analysis
- Secret/credential detection
- MobSF integration

Author: Ghariani Oussema
License: MIT
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Dict, Any, List, Pattern

import requests

# Configuration
VERSION = "1.0.0"
DEFAULT_MOBSF_URL = os.environ.get("MOBSF_URL", "http://localhost:8000")
DEFAULT_MOBSF_KEY = os.environ.get("MOBSF_API_KEY", "")
COMMAND_TIMEOUT = 300
JADX_TIMEOUT = 600

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Default secret detection patterns
DEFAULT_SECRET_PATTERNS = [
    r"(?i)api[_-]?key\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    r"(?i)secret[_-]?key\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    r"(?i)access[_-]?token\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    r"(?i)client[_-]?secret\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    r"(?i)aws[_-]?secret\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    r"(?i)password\s*[:=]\s*['\"][^'\"]{4,}['\"]",
    r"AKIA[0-9A-Z]{16}",  # AWS Access Key ID
    r"(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
    r"(?i)-----BEGIN\s+CERTIFICATE-----",
    r"(?i)firebase[_-]?api[_-]?key",
    r"(?i)google[_-]?api[_-]?key",
    r"ghp_[a-zA-Z0-9]{36}",  # GitHub Personal Access Token
    r"sk_live_[a-zA-Z0-9]{24,}",  # Stripe Secret Key
    r"(?i)jdbc:[a-z]+://[^\s]+",  # Database connection strings
]

# Dangerous Android permissions
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS": "Access contacts",
    "android.permission.WRITE_CONTACTS": "Modify contacts",
    "android.permission.READ_CALL_LOG": "Read call history",
    "android.permission.WRITE_CALL_LOG": "Modify call history",
    "android.permission.READ_SMS": "Read SMS messages",
    "android.permission.SEND_SMS": "Send SMS messages",
    "android.permission.RECEIVE_SMS": "Receive SMS messages",
    "android.permission.CAMERA": "Access camera",
    "android.permission.RECORD_AUDIO": "Record audio",
    "android.permission.ACCESS_FINE_LOCATION": "Precise location",
    "android.permission.ACCESS_COARSE_LOCATION": "Approximate location",
    "android.permission.READ_EXTERNAL_STORAGE": "Read storage",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Write storage",
    "android.permission.READ_PHONE_STATE": "Read phone state",
    "android.permission.CALL_PHONE": "Make calls",
    "android.permission.PROCESS_OUTGOING_CALLS": "Process outgoing calls",
    "android.permission.SYSTEM_ALERT_WINDOW": "Draw over apps",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Install packages",
}


@dataclass
class CommandResult:
    """Result of a shell command execution."""
    returncode: int
    stdout: str
    stderr: str
    timeout: bool = False


@dataclass
class ManifestInfo:
    """Parsed Android manifest information."""
    package: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk: Optional[str] = None
    target_sdk: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    dangerous_permissions: List[Dict[str, str]] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    exported_components: List[str] = field(default_factory=list)
    debuggable: bool = False
    allow_backup: bool = True


@dataclass
class SecretFinding:
    """A detected secret or sensitive data."""
    rule: str
    file: str
    line: int
    match: str
    severity: str = "medium"


@dataclass
class AnalysisReport:
    """Complete APK analysis report."""
    apk_path: str
    apk_name: str
    timestamp: int
    manifest: Optional[ManifestInfo] = None
    secrets: List[SecretFinding] = field(default_factory=list)
    mobsf: Optional[Dict[str, Any]] = None
    apktool_status: Optional[Dict[str, Any]] = None
    jadx_status: Optional[Dict[str, Any]] = None
    errors: List[str] = field(default_factory=list)
    security_score: Optional[int] = None


def run_command(
    cmd: List[str],
    cwd: Optional[str] = None,
    timeout: int = COMMAND_TIMEOUT
) -> CommandResult:
    """Execute a shell command with timeout handling."""
    try:
        process = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(timeout=timeout)
        return CommandResult(
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
            timeout=False
        )
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        return CommandResult(
            returncode=-1,
            stdout=stdout or "",
            stderr=stderr or "",
            timeout=True
        )
    except FileNotFoundError:
        return CommandResult(
            returncode=-1,
            stdout="",
            stderr=f"Command not found: {cmd[0]}",
            timeout=False
        )


class MobSFClient:
    """MobSF API client for automated analysis."""
    
    def __init__(self, url: str = DEFAULT_MOBSF_URL, api_key: str = DEFAULT_MOBSF_KEY):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.session = requests.Session()
        if api_key:
            self.session.headers["Authorization"] = api_key
    
    def is_available(self) -> bool:
        """Check if MobSF is running."""
        try:
            response = self.session.get(f"{self.url}/api/v1/scans", timeout=5)
            return response.status_code in [200, 401]
        except requests.RequestException:
            return False
    
    def upload_and_scan(self, apk_path: str) -> Dict[str, Any]:
        """Upload APK to MobSF and retrieve analysis report."""
        try:
            # Upload
            with open(apk_path, "rb") as f:
                response = self.session.post(
                    f"{self.url}/api/v1/upload",
                    files={"file": f},
                    timeout=120
                )
            response.raise_for_status()
            upload_data = response.json()
            
            file_hash = upload_data.get("hash")
            if not file_hash:
                return {"error": "No hash in upload response"}
            
            # Trigger scan
            self.session.post(
                f"{self.url}/api/v1/scan",
                data={"hash": file_hash},
                timeout=300
            )
            
            # Get report
            report_response = self.session.post(
                f"{self.url}/api/v1/report_json",
                data={"hash": file_hash},
                timeout=60
            )
            report_response.raise_for_status()
            
            return {"report": report_response.json(), "hash": file_hash}
            
        except requests.RequestException as e:
            return {"error": str(e)}


class APKAnalyzer:
    """Professional APK static analyzer."""
    
    def __init__(self, rules_file: Optional[str] = None):
        self.secret_patterns = self._load_patterns(rules_file)
        self.temp_dir: Optional[str] = None
    
    def _load_patterns(self, rules_file: Optional[str]) -> List[Pattern]:
        """Load and compile secret detection patterns."""
        patterns = []
        
        if rules_file and os.path.exists(rules_file):
            with open(rules_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        patterns.append(line)
        
        if not patterns:
            patterns = DEFAULT_SECRET_PATTERNS
        
        compiled = []
        for pattern in patterns:
            try:
                compiled.append(re.compile(pattern))
            except re.error:
                compiled.append(re.compile(re.escape(pattern), re.IGNORECASE))
        
        return compiled
    
    def run_apktool(self, apk_path: str, output_dir: str) -> CommandResult:
        """Decompile APK using apktool."""
        logger.info("Running apktool...")
        return run_command(
            ["apktool", "d", "-f", "-o", output_dir, apk_path],
            timeout=COMMAND_TIMEOUT
        )
    
    def run_jadx(self, apk_path: str, output_dir: str) -> CommandResult:
        """Decompile APK to Java source using jadx."""
        logger.info("Running jadx...")
        return run_command(
            ["jadx", "-d", output_dir, "--no-res", apk_path],
            timeout=JADX_TIMEOUT
        )
    
    def parse_manifest(self, manifest_path: str) -> ManifestInfo:
        """Parse AndroidManifest.xml and extract security-relevant info."""
        info = ManifestInfo()
        
        try:
            content = Path(manifest_path).read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            logger.error(f"Failed to read manifest: {e}")
            return info
        
        # Package info
        if match := re.search(r'package="([^"]+)"', content):
            info.package = match.group(1)
        
        if match := re.search(r'android:versionName="([^"]+)"', content):
            info.version_name = match.group(1)
        
        if match := re.search(r'android:versionCode="([^"]+)"', content):
            info.version_code = match.group(1)
        
        if match := re.search(r'android:minSdkVersion="([^"]+)"', content):
            info.min_sdk = match.group(1)
        
        if match := re.search(r'android:targetSdkVersion="([^"]+)"', content):
            info.target_sdk = match.group(1)
        
        # Security flags
        info.debuggable = 'android:debuggable="true"' in content
        info.allow_backup = 'android:allowBackup="false"' not in content
        
        # Permissions
        permissions = re.findall(
            r'<uses-permission[^>]*android:name="([^"]+)"',
            content
        )
        info.permissions = sorted(set(permissions))
        
        # Identify dangerous permissions
        for perm in info.permissions:
            if perm in DANGEROUS_PERMISSIONS:
                info.dangerous_permissions.append({
                    "permission": perm,
                    "description": DANGEROUS_PERMISSIONS[perm]
                })
        
        # Components
        info.activities = sorted(set(re.findall(
            r'<activity[^>]*android:name="([^"]+)"', content
        )))
        info.services = sorted(set(re.findall(
            r'<service[^>]*android:name="([^"]+)"', content
        )))
        info.receivers = sorted(set(re.findall(
            r'<receiver[^>]*android:name="([^"]+)"', content
        )))
        info.providers = sorted(set(re.findall(
            r'<provider[^>]*android:name="([^"]+)"', content
        )))
        
        # Exported components (potential attack surface)
        exported_pattern = r'<(activity|service|receiver|provider)[^>]*android:exported="true"[^>]*android:name="([^"]+)"'
        for match in re.finditer(exported_pattern, content):
            info.exported_components.append(f"{match.group(1)}: {match.group(2)}")
        
        return info
    
    def search_secrets(
        self,
        search_paths: List[str],
        max_findings: int = 100
    ) -> List[SecretFinding]:
        """Search for secrets and sensitive data in decompiled code."""
        findings = []
        seen = set()
        
        # File extensions to search
        searchable_extensions = {
            ".java", ".kt", ".xml", ".json", ".properties",
            ".yml", ".yaml", ".gradle", ".smali", ".txt", ".config"
        }
        
        for base_path in search_paths:
            if not os.path.exists(base_path):
                continue
            
            for root, _, files in os.walk(base_path):
                for filename in files:
                    ext = os.path.splitext(filename)[1].lower()
                    if ext not in searchable_extensions:
                        continue
                    
                    filepath = os.path.join(root, filename)
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            for line_num, line in enumerate(f, start=1):
                                for pattern in self.secret_patterns:
                                    for match in pattern.finditer(line):
                                        key = (pattern.pattern, filepath, line_num)
                                        if key in seen:
                                            continue
                                        seen.add(key)
                                        
                                        findings.append(SecretFinding(
                                            rule=pattern.pattern[:100],
                                            file=filepath,
                                            line=line_num,
                                            match=match.group(0)[:200],
                                            severity=self._assess_severity(pattern.pattern)
                                        ))
                                        
                                        if len(findings) >= max_findings:
                                            return findings
                    except Exception:
                        continue
        
        return findings
    
    def _assess_severity(self, pattern: str) -> str:
        """Assess the severity of a secret finding."""
        high_severity_keywords = [
            "private.key", "password", "secret", "aws", "firebase",
            "stripe", "ghp_", "sk_live"
        ]
        pattern_lower = pattern.lower()
        
        if any(kw in pattern_lower for kw in high_severity_keywords):
            return "high"
        return "medium"
    
    def calculate_security_score(self, report: AnalysisReport) -> int:
        """Calculate a security score (0-100) based on findings."""
        score = 100
        
        if report.manifest:
            # Deduct for debuggable
            if report.manifest.debuggable:
                score -= 20
            
            # Deduct for allow backup
            if report.manifest.allow_backup:
                score -= 10
            
            # Deduct for dangerous permissions
            score -= min(len(report.manifest.dangerous_permissions) * 3, 30)
            
            # Deduct for exported components
            score -= min(len(report.manifest.exported_components) * 2, 15)
        
        # Deduct for secrets found
        high_severity = sum(1 for s in report.secrets if s.severity == "high")
        medium_severity = sum(1 for s in report.secrets if s.severity == "medium")
        score -= min(high_severity * 10 + medium_severity * 3, 25)
        
        return max(0, score)
    
    def analyze(
        self,
        apk_path: str,
        use_mobsf: bool = True,
        keep_temp: bool = False
    ) -> AnalysisReport:
        """Perform complete APK analysis."""
        import time
        
        apk_path = os.path.abspath(apk_path)
        report = AnalysisReport(
            apk_path=apk_path,
            apk_name=os.path.basename(apk_path),
            timestamp=int(time.time())
        )
        
        if not os.path.exists(apk_path):
            report.errors.append(f"APK file not found: {apk_path}")
            return report
        
        # Create temp directory
        self.temp_dir = tempfile.mkdtemp(prefix="apk_analyzer_")
        apktool_out = os.path.join(self.temp_dir, "apktool")
        jadx_out = os.path.join(self.temp_dir, "jadx")
        
        try:
            # MobSF analysis
            if use_mobsf:
                logger.info("Attempting MobSF analysis...")
                mobsf = MobSFClient()
                if mobsf.is_available():
                    report.mobsf = mobsf.upload_and_scan(apk_path)
                else:
                    logger.warning("MobSF not available")
                    report.mobsf = {"error": "MobSF not available"}
            
            # Apktool decompilation
            apktool_result = self.run_apktool(apk_path, apktool_out)
            report.apktool_status = {
                "success": apktool_result.returncode == 0,
                "returncode": apktool_result.returncode,
                "timeout": apktool_result.timeout
            }
            
            if apktool_result.returncode != 0:
                report.errors.append("apktool decompilation failed")
                if apktool_result.stderr:
                    report.apktool_status["error"] = apktool_result.stderr[-500:]
            
            # Parse manifest
            manifest_path = os.path.join(apktool_out, "AndroidManifest.xml")
            if os.path.exists(manifest_path):
                report.manifest = self.parse_manifest(manifest_path)
            else:
                report.errors.append("AndroidManifest.xml not found")
            
            # Jadx decompilation
            jadx_result = self.run_jadx(apk_path, jadx_out)
            report.jadx_status = {
                "success": jadx_result.returncode == 0,
                "returncode": jadx_result.returncode,
                "timeout": jadx_result.timeout
            }
            
            if jadx_result.returncode != 0:
                report.errors.append("jadx decompilation failed")
            
            # Secret scanning
            logger.info("Scanning for secrets...")
            findings = self.search_secrets([apktool_out, jadx_out])
            report.secrets = findings
            
            # Calculate security score
            report.security_score = self.calculate_security_score(report)
            
        finally:
            # Cleanup
            if not keep_temp and self.temp_dir:
                try:
                    shutil.rmtree(self.temp_dir)
                except Exception:
                    pass
            elif keep_temp:
                logger.info(f"Temp files kept at: {self.temp_dir}")
        
        return report


def report_to_dict(report: AnalysisReport) -> Dict[str, Any]:
    """Convert report to dictionary for JSON serialization."""
    result = {
        "apk_path": report.apk_path,
        "apk_name": report.apk_name,
        "timestamp": report.timestamp,
        "security_score": report.security_score,
        "errors": report.errors,
    }
    
    if report.manifest:
        result["manifest"] = asdict(report.manifest)
    
    if report.secrets:
        result["secrets"] = [asdict(s) for s in report.secrets]
    else:
        result["secrets"] = []
    
    if report.mobsf:
        result["mobsf"] = report.mobsf
    
    if report.apktool_status:
        result["apktool"] = report.apktool_status
    
    if report.jadx_status:
        result["jadx"] = report.jadx_status
    
    return result


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="CyberToolkit APK Analyzer - Professional Android Security Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s app.apk
  %(prog)s app.apk --output report.json
  %(prog)s app.apk --no-mobsf --keep-temp
  %(prog)s app.apk --rules custom_rules.txt
        """
    )
    parser.add_argument(
        "apk",
        help="Path to APK file"
    )
    parser.add_argument(
        "-o", "--output",
        default="-",
        help="Output file path (use - for stdout, default: stdout)"
    )
    parser.add_argument(
        "--no-mobsf",
        action="store_true",
        help="Skip MobSF analysis"
    )
    parser.add_argument(
        "--rules",
        help="Path to custom rules file (one regex per line)"
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="Keep temporary decompilation files"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"CyberToolkit APK Analyzer v{VERSION}"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate APK exists
    if not os.path.exists(args.apk):
        logger.error(f"APK file not found: {args.apk}")
        print(json.dumps({"error": f"APK not found: {args.apk}"}))
        sys.exit(2)
    
    # Run analysis
    analyzer = APKAnalyzer(rules_file=args.rules)
    report = analyzer.analyze(
        args.apk,
        use_mobsf=not args.no_mobsf,
        keep_temp=args.keep_temp
    )
    
    # Output
    output_json = json.dumps(report_to_dict(report), indent=2, default=str)
    
    if args.output == "-":
        print(output_json)
    else:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output_json, encoding="utf-8")
        logger.info(f"Report saved to {args.output}")


if __name__ == "__main__":
    main()
