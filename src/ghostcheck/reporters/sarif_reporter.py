import json
import os
from datetime import datetime

class SarifReporter:
    def __init__(self, version="1.0.0"):
        self.version = version

    def report(self, findings, output_path=None):
        sarif_log = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "GhostCheck",
                            "version": self.version,
                            "informationUri": "https://github.com/KbWen/security-tools",
                            "rules": self._get_rules(findings)
                        }
                    },
                    "results": self._get_results(findings)
                }
            ]
        }
        data = json.dumps(sarif_log, indent=2)
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(data)
        else:
            print(data)

    def _get_rules(self, findings):
        rules = {}
        for f in findings:
            rule_id = f.get('type', 'generic-security-finding')
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {
                        "text": f.get('message', 'Security finding detected by GhostCheck')
                    },
                    "defaultConfiguration": {
                        "level": self._map_severity(f.get('severity', 'MEDIUM'))
                    }
                }
        return list(rules.values())

    def _get_results(self, findings):
        results = []
        for f in findings:
            results.append({
                "ruleId": f.get('type', 'generic-security-finding'),
                "message": {
                    "text": f.get('message', '')
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.get('file', 'unknown')
                            },
                            "region": {
                                "startLine": f.get('line', 1)
                            }
                        }
                    }
                ],
                "level": self._map_severity(f.get('severity', 'MEDIUM'))
            })
        return results

    def _map_severity(self, severity):
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note"
        }
        return mapping.get(severity, "warning")
