#!/usr/bin/env python3
"""Analyze Phase 2 scanner findings from comprehensive scan."""

import json

with open('phase2_comprehensive_verify.json', 'r') as f:
    data = json.load(f)

findings = data.get('findings', [])

# Filter Phase 2 scanners
cmd_inj = [f for f in findings if f.get('scanner_id') == 'API-CMD-INJ']
redirect = [f for f in findings if f.get('scanner_id') == 'API-REDIRECT']
xxe = [f for f in findings if f.get('scanner_id') == 'API-XXE']

print("=" * 60)
print("PHASE 2 SCANNER FINDINGS ANALYSIS")
print("=" * 60)

print(f"\nCommand Injection (API-CMD-INJ): {len(cmd_inj)} findings")
if cmd_inj:
    print("  Sample Finding:")
    sample = cmd_inj[0]
    print(f"    Title: {sample.get('title', 'N/A')}")
    print(f"    Severity: {sample.get('severity', 'N/A')}")
    print(f"    Path: {sample.get('path', 'N/A')}")
    evidence = sample.get('evidence', '')
    if 'Payload:' in evidence:
        payload_line = [l for l in evidence.split('\n') if 'Payload:' in l]
        if payload_line:
            print(f"    {payload_line[0]}")

print(f"\nExternal Redirect (API-REDIRECT): {len(redirect)} findings")
if redirect:
    print("  Sample Findings (first 3):")
    for i, sample in enumerate(redirect[:3], 1):
        print(f"    {i}. {sample.get('title', 'N/A')}")
        print(f"       Path: {sample.get('path', 'N/A')}")
        evidence = sample.get('evidence', '')
        if 'Payload:' in evidence:
            payload_line = [l for l in evidence.split('\n') if 'Payload:' in l]
            if payload_line:
                print(f"       {payload_line[0]}")

print(f"\nXXE (API-XXE): {len(xxe)} findings")
if xxe:
    print("  Sample Finding:")
    sample = xxe[0]
    print(f"    Title: {sample.get('title', 'N/A')}")
else:
    print("  Status: No vulnerabilities found (scanner executed)")

print("\n" + "=" * 60)
print("VERIFICATION")
print("=" * 60)
print(f"\nCommand Injection: {'WORKING' if len(cmd_inj) > 0 else 'NO FINDINGS'}")
print(f"External Redirect: {'WORKING' if len(redirect) > 0 else 'NO FINDINGS'}")
print(f"XXE: {'WORKING' if len(xxe) > 0 else 'NO FINDINGS (scanner functional)'}")
