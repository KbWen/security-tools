import json
import os
from datetime import datetime
from ..interfaces import BaseReporterPlugin

class HTMLReporter(BaseReporterPlugin):
    @property
    def name(self) -> str:
        return "html"

    def __init__(self, output_path="ghostcheck-report.html"):
        self.output_path = output_path

    def report(self, findings, stream=None, **kwargs):
        grade = kwargs.get('grade', 'F')
        score_val = kwargs.get('score_val', 0)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        severity_colors = {
            "CRITICAL": "#ff4d4f",
            "HIGH": "#ff7a45",
            "MEDIUM": "#ffc53d",
            "LOW": "#40a9ff",
            "INFO": "#73d13d"
        }
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GhostCheck Security Report</title>
    <style>
        body {{ font-family: 'Inter', -apple-system, sans-serif; background: #f0f2f5; margin: 0; padding: 20px; color: #1f1f1f; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        .card {{ background: white; border-radius: 12px; padding: 24px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); margin-bottom: 24px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #f0f0f0; padding-bottom: 16px; }}
        .score-box {{ text-align: center; padding: 16px; border-radius: 12px; min-width: 120px; }}
        .grade-A {{ background: #f6ffed; color: #52c41a; border: 1px solid #b7eb8f; }}
        .grade-B {{ background: #e6f7ff; color: #1890ff; border: 1px solid #91d5ff; }}
        .grade-C {{ background: #fffbe6; color: #faad14; border: 1px solid #ffe58f; }}
        .grade-D {{ background: #fff7e6; color: #ff7a45; border: 1px solid #ffd591; }}
        .grade-F {{ background: #fff1f0; color: #f5222d; border: 1px solid #ffa39e; }}
        .grade-text {{ font-size: 48px; font-weight: bold; margin: 0; }}
        .finding {{ border-left: 4px solid #ddd; padding: 12px 16px; margin-bottom: 12px; background: #fafafa; }}
        .severity {{ font-weight: bold; border-radius: 4px; padding: 2px 8px; font-size: 12px; color: white; display: inline-block; margin-bottom: 8px; }}
        .finding-title {{ font-weight: bold; font-size: 16px; margin-bottom: 4px; }}
        .finding-loc {{ color: #8c8c8c; font-size: 14px; margin-bottom: 8px; }}
        .context {{ font-family: monospace; background: #f5f5f5; padding: 8px; border-radius: 4px; display: block; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card header">
            <div>
                <h1>GhostCheck Scan Dashboard</h1>
                <p>Generated at: {now}</p>
            </div>
            <div class="score-box grade-{grade}">
                <p style="margin:0; font-size:14px;">Security Grade</p>
                <div class="grade-text">{grade}</div>
                <p style="margin:0; font-size:14px;">Score: {score_val}/100</p>
            </div>
        </div>

        <div class="card">
            <h2>Scan Findings ({len(findings)})</h2>
            <div id="findings-list">
        """
        
        for f in findings:
            sev = f.get('severity', 'INFO')
            color = severity_colors.get(sev, "#8c8c8c")
            title = f.get('name') or f.get('pattern_name') or "Security Issue"
            loc = f"{f.get('file')}:{f.get('line')}" if f.get('line') else f.get('file', 'N/A')
            owasp = f.get('owasp_llm', '')
            
            html_content += f"""
                <div class="finding" style="border-left-color: {color}">
                    <div class="severity" style="background: {color}">{sev}</div>
                    {f'<span class="severity" style="background: #1f1f1f; margin-left: 8px;">{owasp}</span>' if owasp else ''}
                    <div class="finding-title">{title}</div>
                    <div class="finding-loc">Location: {loc}</div>
                    <p>{f.get('message', '')}</p>
                    {f'<code class="context">{f.get("context") or f.get("value_preview", "")}</code>' if (f.get("context") or f.get("value_preview")) else ''}
                    <p><strong>Fix:</strong> {f.get('remediation') or f.get('suggestion', 'N/A')}</p>
                </div>
            """
            
        html_content += """
            </div>
        </div>
    </div>
</body>
</html>
        """
        
        if stream:
            stream.write(html_content)
        else:
            with open(self.output_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            print(f"HTML Report generated at {self.output_path}")
        return os.path.abspath(self.output_path)
