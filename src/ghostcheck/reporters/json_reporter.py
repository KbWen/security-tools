import json

class JsonReporter:
    def report(self, findings):
        # Machine-readable output - simple JSON array
        print(json.dumps(findings, indent=2))
