#!/usr/bin/env python3
"""
PENTRA-X Report Generator
Generate professional pentest reports.
"""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict

from ...core.colors import Colors, success, error, info, warning, header
from ...core.utils import safe_input, safe_press_enter
from ...core.logging import get_logger
from ...core.config import get_config


def generate_report(output_format: str = 'html') -> Optional[str]:
    """
    Generate a penetration testing report.
    
    Args:
        output_format: 'html', 'txt', or 'json'
        
    Returns:
        Path to generated report or None
    """
    logger = get_logger()
    config = get_config()
    
    header("Report Generator")
    
    # Get report details
    print(f"\n{Colors.OKCYAN}Report Information:{Colors.ENDC}")
    
    project_name = safe_input(f"{Colors.OKGREEN}Project/Target name: {Colors.ENDC}")
    if not project_name:
        error("Project name required")
        safe_press_enter()
        return None
    
    tester_name = safe_input(f"{Colors.OKGREEN}Tester name: {Colors.ENDC}") or "Security Tester"
    
    # Select format
    print(f"\n{Colors.OKCYAN}Output format:{Colors.ENDC}")
    print(f"  {Colors.OKCYAN}1.{Colors.ENDC} HTML (recommended)")
    print(f"  {Colors.OKCYAN}2.{Colors.ENDC} Plain Text")
    print(f"  {Colors.OKCYAN}3.{Colors.ENDC} JSON")
    
    format_choice = safe_input(f"\n{Colors.OKGREEN}Select format (default 1): {Colors.ENDC}") or '1'
    
    if format_choice == '2':
        output_format = 'txt'
        ext = '.txt'
    elif format_choice == '3':
        output_format = 'json'
        ext = '.json'
    else:
        output_format = 'html'
        ext = '.html'
    
    # Collect findings
    print(f"\n{Colors.OKCYAN}Add Findings (enter 'done' when finished):{Colors.ENDC}")
    
    findings: List[Dict] = []
    
    while True:
        print(f"\n{Colors.OKGREEN}--- Finding #{len(findings) + 1} ---{Colors.ENDC}")
        
        title = safe_input("Title (or 'done'): ")
        if not title or title.lower() == 'done':
            break
        
        severity = safe_input("Severity (critical/high/medium/low/info): ") or "medium"
        description = safe_input("Description: ") or "No description provided"
        recommendation = safe_input("Recommendation: ") or "Review and remediate"
        
        findings.append({
            'title': title,
            'severity': severity.lower(),
            'description': description,
            'recommendation': recommendation,
        })
    
    if not findings:
        warning("No findings added")
    
    logger.tool_start("Report Generator", project_name)
    
    # Generate report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_name = f"pentest_report_{project_name.replace(' ', '_')}_{timestamp}{ext}"
    
    results_dir = config.get('general.results_dir', '~/.pentrax/results')
    results_dir = os.path.expanduser(results_dir)
    os.makedirs(results_dir, exist_ok=True)
    
    report_path = os.path.join(results_dir, report_name)
    
    report_data = {
        'project': project_name,
        'tester': tester_name,
        'date': datetime.now().isoformat(),
        'findings_count': len(findings),
        'findings': findings,
    }
    
    try:
        if output_format == 'json':
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=2)
                
        elif output_format == 'txt':
            with open(report_path, 'w') as f:
                f.write("=" * 60 + "\n")
                f.write("PENETRATION TEST REPORT\n")
                f.write("=" * 60 + "\n\n")
                f.write(f"Project: {project_name}\n")
                f.write(f"Tester: {tester_name}\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Findings: {len(findings)}\n\n")
                f.write("-" * 60 + "\n")
                f.write("FINDINGS\n")
                f.write("-" * 60 + "\n\n")
                
                for i, finding in enumerate(findings, 1):
                    f.write(f"[{i}] {finding['title']}\n")
                    f.write(f"    Severity: {finding['severity'].upper()}\n")
                    f.write(f"    Description: {finding['description']}\n")
                    f.write(f"    Recommendation: {finding['recommendation']}\n\n")
                
                f.write("=" * 60 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 60 + "\n")
                
        else:  # HTML
            severity_colors = {
                'critical': '#e74c3c',
                'high': '#e67e22',
                'medium': '#f1c40f',
                'low': '#3498db',
                'info': '#95a5a6',
            }
            
            html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Pentest Report - {project_name}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        h1 {{ color: #00d9ff; border-bottom: 2px solid #00d9ff; padding-bottom: 10px; }}
        h2 {{ color: #00d9ff; }}
        .header {{ background: linear-gradient(135deg, #16213e, #1a1a2e); padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .meta {{ color: #888; }}
        .finding {{ background: #16213e; padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #00d9ff; }}
        .severity {{ display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; text-transform: uppercase; font-size: 12px; }}
        .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 20px 0; }}
        .summary-item {{ background: #16213e; padding: 15px; border-radius: 8px; text-align: center; }}
        .summary-count {{ font-size: 24px; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #0f0f23; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Penetration Test Report</h1>
            <p class="meta"><strong>Project:</strong> {project_name}</p>
            <p class="meta"><strong>Tester:</strong> {tester_name}</p>
            <p class="meta"><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <h2>📊 Executive Summary</h2>
        <div class="summary">
'''
            # Count by severity
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                count = sum(1 for f in findings if f['severity'] == sev)
                html += f'''            <div class="summary-item">
                <div class="summary-count" style="color: {severity_colors.get(sev, '#888')}">{count}</div>
                <div>{sev.upper()}</div>
            </div>
'''
            
            html += '''        </div>
        
        <h2>🔍 Findings</h2>
'''
            for i, finding in enumerate(findings, 1):
                sev_color = severity_colors.get(finding['severity'], '#888')
                html += f'''        <div class="finding">
            <h3>{i}. {finding['title']}</h3>
            <span class="severity" style="background: {sev_color}">{finding['severity']}</span>
            <p><strong>Description:</strong> {finding['description']}</p>
            <p><strong>Recommendation:</strong> {finding['recommendation']}</p>
        </div>
'''
            
            html += '''        
        <h2>📋 Appendix</h2>
        <p>Generated by PENTRA-X v2.0.0</p>
    </div>
</body>
</html>'''
            
            with open(report_path, 'w') as f:
                f.write(html)
        
        success(f"Report generated: {report_path}")
        logger.tool_end("Report Generator", success=True)
        
        safe_press_enter()
        return report_path
        
    except Exception as e:
        error(f"Report generation failed: {e}")
        logger.tool_end("Report Generator", success=False)
        safe_press_enter()
        return None


if __name__ == "__main__":
    generate_report()
