import json
from ..interfaces import BaseReporterPlugin

class JsonReporter(BaseReporterPlugin):
    @property
    def name(self) -> str:
        return "json"

    def report(self, findings, stream=None, **kwargs):
        # Machine-readable output - simple JSON array
        data = json.dumps(findings, indent=2)
        if stream:
            stream.write(data)
        else:
            print(data)
