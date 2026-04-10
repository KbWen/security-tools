import re
import os

class MobileConfigAuditor:
    def __init__(self):
        self.rules = [
            {
                "name": "android_debuggable_enabled",
                "file_pattern": r'AndroidManifest\.xml',
                "pattern": r'android:debuggable="true"',
                "severity": "CRITICAL",
                "message": "Android application is marked as debuggable.",
                "remediation": "Set android:debuggable to 'false' in production manifests."
            },
            {
                "name": "android_allow_backup_enabled",
                "file_pattern": r'AndroidManifest\.xml',
                "pattern": r'android:allowBackup="true"',
                "severity": "MEDIUM",
                "message": "Android backup is enabled, which may leak app data via adb backup.",
                "remediation": "Set android:allowBackup to 'false' if app handles sensitive data."
            },
            {
                "name": "ios_app_transport_security_insecure",
                "file_pattern": r'Info\.plist',
                "pattern": r'<key>NSAllowsArbitraryLoads<\/key>\s*<true\/>',
                "severity": "HIGH",
                "message": "iOS App Transport Security (ATS) is disabled (NSAllowsArbitraryLoads=true).",
                "remediation": "Enable ATS and whitelist specific domains if needed."
            },
            {
                "name": "mobile_hardcoded_google_api_key",
                "file_pattern": r'(GoogleService-Info\.plist|google-services\.json)',
                "pattern": r'(AIza[0-9A-Za-z-_]{35})',
                "severity": "HIGH",
                "message": "Potential hardcoded Google API Key found in mobile configuration file.",
                "remediation": "Ensure this key is restricted in Google Cloud Console by package name/signature."
            }
        ]

    def scan_file(self, file_path, content):
        findings = []
        filename = os.path.basename(file_path)
        
        for rule in self.rules:
            if not re.search(rule['file_pattern'], filename, re.IGNORECASE):
                continue
            
            matches = re.finditer(rule['pattern'], content)
            for match in matches:
                line_idx = content.count('\n', 0, match.start())
                val = match.group(0).strip()
                masked = val
                if rule['name'] == "mobile_hardcoded_google_api_key":
                    masked = val[:4] + "*" * (len(val) - 8) + val[-4:] if len(val) > 8 else "****"
                
                findings.append({
                    "file": file_path,
                    "line": line_idx + 1,
                    "name": rule['name'],
                    "severity": rule['severity'],
                    "message": rule['message'],
                    "remediation": rule['remediation'],
                    "value_preview": masked,
                    "context": masked
                })
        return findings
