import json
import os
from datetime import datetime
from ..interfaces import BaseReporterPlugin
from .. import __version__

class SarifReporter(BaseReporterPlugin):
    @property
    def name(self) -> str:
        return "sarif"

    def __init__(self, version=None):
        self.version = version or __version__

    def report(self, findings, stream=None, **kwargs):
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
        output_path = kwargs.get('output_path', 'ghostcheck-report.sarif')
        
        if stream:
            json.dump(sarif_log, stream, indent=2)
        else:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(sarif_log, f, indent=2)
            print(f"SARIF report generated at {output_path}")

    def _get_rule_id(self, f):
        return f.get('name', f.get('pattern_name', f.get('rule_id', 'generic-security-finding')))

    def _get_rules(self, findings):
        rules = {}
        for f in findings:
            rule_id = self._get_rule_id(f)
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {
                        "text": f.get('message', f.get('suggestion', 'Security finding detected by GhostCheck'))
                    },
                    "defaultConfiguration": {
                        "level": self._map_severity(f.get('severity', 'MEDIUM'))
                    }
                }
        return list(rules.values())

    def _get_results(self, findings):
        results = []
        for f in findings:
            rule_id = self._get_rule_id(f)
            results.append({
                "ruleId": rule_id,
                "message": {
                    "text": f.get('message', f.get('suggestion', ''))
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(f.get('file', 'unknown')).replace('\\', '/')
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
