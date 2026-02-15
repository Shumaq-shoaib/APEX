#!/usr/bin/env python3
"""Verify scan results and check if new payloads are working."""

import json
import sys
from pathlib import Path

def analyze_report(report_file):
    """Analyze the scan report."""
    try:
        with open(report_file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Report file {report_file} not found. Scan may still be running.")
        return False
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
        return False
    
    findings = data.get('findings', [])
    total = len(findings)
    
    print("=" * 60)
    print("SCAN RESULTS VERIFICATION")
    print("=" * 60)
    print(f"\nTotal Findings: {total}")
    
    # Group by scanner
    by_scanner = {}
    for finding in findings:
        scanner_id = finding.get('scanner_id', 'UNKNOWN')
        if scanner_id not in by_scanner:
            by_scanner[scanner_id] = []
        by_scanner[scanner_id].append(finding)
    
    print(f"\nFindings by Scanner:")
    for scanner_id, scanner_findings in sorted(by_scanner.items()):
        print(f"  {scanner_id}: {len(scanner_findings)} findings")
    
    # Check Phase 2 scanners specifically
    print("\n" + "=" * 60)
    print("PHASE 2 SCANNER VERIFICATION")
    print("=" * 60)
    
    phase2_scanners = {
        'API-CMD-INJ': 'Command Injection',
        'API-REDIRECT': 'External Redirect',
        'API-XXE': 'XXE'
    }
    
    all_working = True
    for scanner_id, scanner_name in phase2_scanners.items():
        findings_list = by_scanner.get(scanner_id, [])
        count = len(findings_list)
        status = "WORKING" if count > 0 or scanner_id in by_scanner else "NO FINDINGS"
        print(f"\n{scanner_name} ({scanner_id}):")
        print(f"  Findings: {count}")
        print(f"  Status: {status}")
        
        # Show sample findings
        if findings_list:
            print(f"  Sample Finding:")
            sample = findings_list[0]
            print(f"    Title: {sample.get('title', 'N/A')}")
            print(f"    Severity: {sample.get('severity', 'N/A')}")
            print(f"    Path: {sample.get('path', 'N/A')}")
    
    # Check for WAF bypass payloads in evidence
    print("\n" + "=" * 60)
    print("WAF BYPASS PAYLOAD VERIFICATION")
    print("=" * 60)
    
    cmd_inj_findings = by_scanner.get('API-CMD-INJ', [])
    waf_bypass_found = False
    for finding in cmd_inj_findings:
        evidence = finding.get('evidence', '')
        if '$u' in evidence:
            waf_bypass_found = True
            print(f"\nWAF Bypass payload detected in finding:")
            print(f"  Title: {finding.get('title', 'N/A')}")
            print(f"  Evidence snippet: {evidence[:200]}...")
            break
    
    if not waf_bypass_found and cmd_inj_findings:
        print("\nNo WAF bypass payloads found in evidence (may be in payloads tested)")
    elif not cmd_inj_findings:
        print("\nNo Command Injection findings to check")
    
    # Check redirect payloads
    redirect_findings = by_scanner.get('API-REDIRECT', [])
    print(f"\nExternal Redirect Findings: {len(redirect_findings)}")
    if redirect_findings:
        print("  Sample payloads tested:")
        for finding in redirect_findings[:3]:
            evidence = finding.get('evidence', '')
            if 'Payload:' in evidence:
                payload_line = [l for l in evidence.split('\n') if 'Payload:' in l]
                if payload_line:
                    print(f"    {payload_line[0]}")
    
    # Check XXE payloads
    xxe_findings = by_scanner.get('API-XXE', [])
    print(f"\nXXE Findings: {len(xxe_findings)}")
    if xxe_findings:
        oast_found = any('oast' in f.get('evidence', '').lower() for f in xxe_findings)
        billion_found = any('lol' in f.get('evidence', '').lower() for f in xxe_findings)
        print(f"  OAST payload tested: {'YES' if oast_found else 'NO (may not have triggered)'}")
        print(f"  Billion Laughs tested: {'YES' if billion_found else 'NO (may not have triggered)'}")
    
    print("\n" + "=" * 60)
    print("VERIFICATION SUMMARY")
    print("=" * 60)
    
    phase2_working = all(
        scanner_id in by_scanner 
        for scanner_id in phase2_scanners.keys()
    )
    
    print(f"\nPhase 2 Scanners Loaded: {'YES' if phase2_working else 'NO'}")
    print(f"Total Findings Generated: {total}")
    print(f"Scan Status: {'COMPLETE' if total > 0 else 'IN PROGRESS OR NO FINDINGS'}")
    
    return True

if __name__ == "__main__":
    report_file = sys.argv[1] if len(sys.argv) > 1 else "phase2_test_report.json"
    analyze_report(report_file)
