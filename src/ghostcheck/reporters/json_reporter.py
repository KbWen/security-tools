import json
from ..interfaces import BaseReporterPlugin

class JsonReporter(BaseReporterPlugin):
    @property
    def name(self) -> str:
        return "json"

    def report(self, findings, stream=None, **kwargs):
        # Machine-readable output - simple JSON array
        sanitized = [
            {k: v for k, v in f.items() if not str(k).startswith('_')} if isinstance(f, dict) else f
            for f in findings
        ]
        data = json.dumps(sanitized, indent=2)
        if stream:
            stream.write(data)
        else:
            print(data)
