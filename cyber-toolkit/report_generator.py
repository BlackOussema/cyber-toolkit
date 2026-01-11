#!/usr/bin/env python3
"""
CyberToolkit Report Generator - Professional HTML Dashboard

Generates comprehensive HTML reports from scan results with:
- Modern responsive design
- Security score visualization
- Detailed findings breakdown
- Export capabilities

Author: Ghariani Oussema
License: MIT
"""

import argparse
import html
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

# Configuration
VERSION = "1.0.0"

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# HTML Template
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberToolkit Security Report</title>
    <style>
        :root {{
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --bg-dark: #0f172a;
            --bg-card: #1e293b;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --border: #334155;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        header {{
            text-align: center;
            margin-bottom: 3rem;
            padding: 2rem;
            background: linear-gradient(135deg, var(--bg-card) 0%, var(--bg-dark) 100%);
            border-radius: 16px;
            border: 1px solid var(--border);
        }}
        
        header h1 {{
            font-size: 2.5rem;
            background: linear-gradient(135deg, var(--primary) 0%, #a855f7 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 0.5rem;
        }}
        
        header p {{
            color: var(--text-secondary);
            font-size: 1.1rem;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        
        .stat-card {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            border: 1px solid var(--border);
            text-align: center;
        }}
        
        .stat-card h3 {{
            color: var(--text-secondary);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }}
        
        .stat-card .value {{
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--primary);
        }}
        
        .stat-card.success .value {{ color: var(--success); }}
        .stat-card.warning .value {{ color: var(--warning); }}
        .stat-card.danger .value {{ color: var(--danger); }}
        
        .section {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border);
        }}
        
        .section h2 {{
            font-size: 1.25rem;
            margin-bottom: 1rem;
            padding-bottom: 0.75rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .section h2::before {{
            content: '';
            width: 4px;
            height: 1.25rem;
            background: var(--primary);
            border-radius: 2px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }}
        
        th, td {{
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        
        th {{
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }}
        
        tr:hover {{
            background: rgba(99, 102, 241, 0.1);
        }}
        
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        
        .badge-success {{ background: rgba(16, 185, 129, 0.2); color: var(--success); }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.2); color: var(--warning); }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.2); color: var(--danger); }}
        .badge-info {{ background: rgba(99, 102, 241, 0.2); color: var(--primary); }}
        
        .score-circle {{
            width: 120px;
            height: 120px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2rem;
            font-weight: 700;
            margin: 0 auto 1rem;
            border: 4px solid;
        }}
        
        .score-high {{ border-color: var(--success); color: var(--success); }}
        .score-medium {{ border-color: var(--warning); color: var(--warning); }}
        .score-low {{ border-color: var(--danger); color: var(--danger); }}
        
        .finding-item {{
            padding: 1rem;
            background: rgba(0, 0, 0, 0.2);
            border-radius: 8px;
            margin-bottom: 0.75rem;
            border-left: 3px solid var(--warning);
        }}
        
        .finding-item.high {{
            border-left-color: var(--danger);
        }}
        
        .finding-item code {{
            background: rgba(0, 0, 0, 0.3);
            padding: 0.125rem 0.375rem;
            border-radius: 4px;
            font-size: 0.85rem;
            word-break: break-all;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
        }}
        
        footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}
        
        footer a {{
            color: var(--primary);
            text-decoration: none;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 1rem;
            }}
            
            header h1 {{
                font-size: 1.75rem;
            }}
            
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ CyberToolkit Security Report</h1>
            <p>Generated on {generation_time}</p>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Scans</h3>
                <div class="value">{total_scans}</div>
            </div>
            <div class="stat-card">
                <h3>Web Scans</h3>
                <div class="value">{web_scans}</div>
            </div>
            <div class="stat-card">
                <h3>APK Analyses</h3>
                <div class="value">{apk_scans}</div>
            </div>
            <div class="stat-card {secrets_class}">
                <h3>Secrets Found</h3>
                <div class="value">{total_secrets}</div>
            </div>
        </div>
        
        {content}
        
        <footer>
            <p>Generated by <a href="https://github.com/BlackOussema/cyber-toolkit">CyberToolkit</a> v{version}</p>
            <p>Created by Ghariani Oussema | Security Researcher</p>
        </footer>
    </div>
</body>
</html>
"""


class ReportGenerator:
    """Generate professional HTML reports from scan results."""
    
    def __init__(self, results_dir: str = "results"):
        self.results_dir = Path(results_dir)
        self.web_results: List[Dict[str, Any]] = []
        self.apk_results: List[Dict[str, Any]] = []
    
    def load_results(self) -> None:
        """Load all JSON result files from the results directory."""
        if not self.results_dir.exists():
            logger.warning(f"Results directory not found: {self.results_dir}")
            return
        
        for json_file in sorted(self.results_dir.glob("*.json")):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                data["_filename"] = json_file.name
                
                # Determine type based on content
                if "passive" in data or "security_headers" in data:
                    self.web_results.append(data)
                elif "apk" in data or "manifest" in data or "apk_path" in data:
                    self.apk_results.append(data)
                    
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse {json_file}: {e}")
            except Exception as e:
                logger.warning(f"Error loading {json_file}: {e}")
    
    def _escape(self, value: Any) -> str:
        """Safely escape HTML content."""
        if value is None:
            return "<em>N/A</em>"
        return html.escape(str(value))
    
    def _get_score_class(self, score: Optional[int]) -> str:
        """Get CSS class based on security score."""
        if score is None:
            return "score-medium"
        if score >= 70:
            return "score-high"
        if score >= 40:
            return "score-medium"
        return "score-low"
    
    def _generate_web_section(self) -> str:
        """Generate HTML for web scan results."""
        if not self.web_results:
            return ""
        
        rows = []
        for result in self.web_results:
            target = result.get("target", "Unknown")
            
            # Handle both old and new format
            if "passive" in result:
                passive = result["passive"]
                status = passive.get("status_code", "N/A")
                server = passive.get("server", "N/A")
                csp = "✓" if passive.get("content_security_policy") else "✗"
                xfo = "✓" if passive.get("x_frame_options") else "✗"
            else:
                status = result.get("status_code", "N/A")
                server = result.get("server", "N/A")
                headers = result.get("security_headers", {})
                csp = "✓" if headers.get("Content-Security-Policy", {}).get("present") else "✗"
                xfo = "✓" if headers.get("X-Frame-Options", {}).get("present") else "✗"
            
            csp_class = "badge-success" if csp == "✓" else "badge-danger"
            xfo_class = "badge-success" if xfo == "✓" else "badge-danger"
            
            rows.append(f"""
                <tr>
                    <td><code>{self._escape(target)}</code></td>
                    <td><span class="badge badge-info">{status}</span></td>
                    <td>{self._escape(server)}</td>
                    <td><span class="badge {csp_class}">{csp}</span></td>
                    <td><span class="badge {xfo_class}">{xfo}</span></td>
                </tr>
            """)
        
        return f"""
        <div class="section">
            <h2>Web Scan Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>Status</th>
                        <th>Server</th>
                        <th>CSP</th>
                        <th>X-Frame-Options</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>
        """
    
    def _generate_apk_section(self) -> str:
        """Generate HTML for APK analysis results."""
        if not self.apk_results:
            return ""
        
        sections = []
        
        for result in self.apk_results:
            apk_name = result.get("apk_name") or os.path.basename(result.get("apk", "Unknown"))
            manifest = result.get("manifest", {})
            secrets = result.get("secrets", [])
            score = result.get("security_score")
            
            package = manifest.get("package", "N/A")
            permissions_count = len(manifest.get("permissions", []))
            dangerous_perms = manifest.get("dangerous_permissions", [])
            debuggable = manifest.get("debuggable", False)
            
            score_class = self._get_score_class(score)
            score_display = score if score is not None else "N/A"
            
            # Security flags
            flags_html = ""
            if debuggable:
                flags_html += '<span class="badge badge-danger">Debuggable</span> '
            if manifest.get("allow_backup", True):
                flags_html += '<span class="badge badge-warning">Backup Allowed</span> '
            
            # Dangerous permissions
            perms_html = ""
            if dangerous_perms:
                perms_items = "".join([
                    f'<li><code>{self._escape(p.get("permission", p))}</code> - {self._escape(p.get("description", ""))}</li>'
                    for p in dangerous_perms[:10]
                ])
                perms_html = f'<ul style="margin-top: 0.5rem; padding-left: 1.5rem;">{perms_items}</ul>'
            
            # Secrets
            secrets_html = ""
            if secrets:
                for secret in secrets[:10]:
                    severity = secret.get("severity", "medium")
                    severity_class = "high" if severity == "high" else ""
                    secrets_html += f"""
                    <div class="finding-item {severity_class}">
                        <strong>File:</strong> <code>{self._escape(os.path.basename(secret.get('file', 'Unknown')))}</code><br>
                        <strong>Line:</strong> {secret.get('line', 'N/A')}<br>
                        <strong>Match:</strong> <code>{self._escape(secret.get('match', '')[:100])}</code>
                    </div>
                    """
                if len(secrets) > 10:
                    secrets_html += f'<p class="empty-state">... and {len(secrets) - 10} more findings</p>'
            else:
                secrets_html = '<p class="empty-state">No secrets detected</p>'
            
            sections.append(f"""
            <div class="section">
                <h2>📱 {self._escape(apk_name)}</h2>
                
                <div style="display: grid; grid-template-columns: 150px 1fr; gap: 2rem; margin-bottom: 1.5rem;">
                    <div>
                        <div class="score-circle {score_class}">{score_display}</div>
                        <p style="text-align: center; color: var(--text-secondary);">Security Score</p>
                    </div>
                    <div>
                        <table>
                            <tr><td><strong>Package:</strong></td><td><code>{self._escape(package)}</code></td></tr>
                            <tr><td><strong>Permissions:</strong></td><td>{permissions_count} total, {len(dangerous_perms)} dangerous</td></tr>
                            <tr><td><strong>Security Flags:</strong></td><td>{flags_html or '<span class="badge badge-success">None</span>'}</td></tr>
                        </table>
                    </div>
                </div>
                
                {f'<h3 style="margin: 1rem 0 0.5rem;">⚠️ Dangerous Permissions</h3>{perms_html}' if dangerous_perms else ''}
                
                <h3 style="margin: 1rem 0 0.5rem;">🔑 Secrets & Sensitive Data ({len(secrets)} found)</h3>
                {secrets_html}
            </div>
            """)
        
        return "".join(sections)
    
    def generate(self, output_path: str = "report.html") -> str:
        """Generate the complete HTML report."""
        self.load_results()
        
        total_secrets = sum(
            len(r.get("secrets", [])) for r in self.apk_results
        )
        
        secrets_class = "danger" if total_secrets > 10 else ("warning" if total_secrets > 0 else "success")
        
        content = self._generate_web_section() + self._generate_apk_section()
        
        if not content:
            content = '<div class="section"><p class="empty-state">No scan results found. Run some scans first!</p></div>'
        
        html_content = HTML_TEMPLATE.format(
            generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            total_scans=len(self.web_results) + len(self.apk_results),
            web_scans=len(self.web_results),
            apk_scans=len(self.apk_results),
            total_secrets=total_secrets,
            secrets_class=secrets_class,
            content=content,
            version=VERSION
        )
        
        # Write output
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(html_content, encoding="utf-8")
        
        logger.info(f"Report generated: {output_path}")
        return str(output_file.absolute())


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="CyberToolkit Report Generator - Create Professional Security Reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
  %(prog)s -d ./scan_results -o report.html
  %(prog)s --dir results --output dashboard.html
        """
    )
    parser.add_argument(
        "-d", "--dir",
        default="results",
        help="Directory containing JSON result files (default: results)"
    )
    parser.add_argument(
        "-o", "--output",
        default="results/report.html",
        help="Output HTML file path (default: results/report.html)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"CyberToolkit Report Generator v{VERSION}"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    generator = ReportGenerator(results_dir=args.dir)
    output_path = generator.generate(output_path=args.output)
    
    print(f"✓ Report generated: {output_path}")


if __name__ == "__main__":
    main()
