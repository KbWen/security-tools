import json

class JsonReporter:
    def report(self, findings, output_path=None):
        # Machine-readable output - simple JSON array
        data = json.dumps(findings, indent=2)
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(data)
        else:
            print(data)
