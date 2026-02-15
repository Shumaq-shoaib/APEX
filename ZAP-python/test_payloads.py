#!/usr/bin/env python3
"""Test script to verify payload counts and functionality."""

from utils.payloads import PayloadLibrary, insert_uninit_var

print("=" * 60)
print("PAYLOAD COUNT VERIFICATION")
print("=" * 60)

# External Redirect
redirect_urls = len(PayloadLibrary.EXTERNAL_REDIRECT_PAYLOADS)
redirect_headers = len(PayloadLibrary.REDIRECT_HEADER_PAYLOADS)
redirect_total = redirect_urls + redirect_headers

print(f"\nExternal Redirect:")
print(f"  URLs: {redirect_urls}")
print(f"  Headers: {redirect_headers}")
print(f"  TOTAL: {redirect_total} (Target: 14)")
print(f"  Status: {'PASS' if redirect_total == 14 else 'FAIL'}")

# Command Injection
unix_count = len(PayloadLibrary.UNIX_CMD_PAYLOADS)
windows_count = len(PayloadLibrary.WINDOWS_CMD_PAYLOADS)
powershell_count = len(PayloadLibrary.POWERSHELL_CMD_PAYLOADS)
cmd_total = unix_count + windows_count + powershell_count

print(f"\nCommand Injection:")
print(f"  Unix: {unix_count}")
print(f"  Windows: {windows_count}")
print(f"  PowerShell: {powershell_count}")
print(f"  TOTAL: {cmd_total} (Target: 50+)")
print(f"  Status: {'PASS' if cmd_total >= 50 else 'FAIL'}")

# XXE
xxe_count = len(PayloadLibrary.XXE_PAYLOADS)

print(f"\nXXE Templates:")
print(f"  Count: {xxe_count} (Target: 4)")
print(f"  Status: {'PASS' if xxe_count == 4 else 'FAIL'}")

# Test WAF bypass function
print(f"\nWAF Bypass Function Test:")
test_cmd = "cat /etc/passwd"
bypassed = insert_uninit_var(test_cmd)
print(f"  Input: {test_cmd}")
print(f"  Output: {bypassed}")
print(f"  Status: {'PASS' if '$u' in bypassed else 'FAIL'}")

# Check for OAST and Billion Laughs in XXE
print(f"\nXXE Payload Verification:")
has_oast = any('{oast_host}' in p for p in PayloadLibrary.XXE_PAYLOADS)
has_billion = any('lol9' in p for p in PayloadLibrary.XXE_PAYLOADS)
print(f"  OAST template: {'YES' if has_oast else 'NO'}")
print(f"  Billion Laughs: {'YES' if has_billion else 'NO'}")

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
all_pass = (redirect_total == 14 and cmd_total >= 50 and xxe_count == 4 and has_oast and has_billion)
print(f"Overall Status: {'ALL REQUIREMENTS MET' if all_pass else 'SOME REQUIREMENTS NOT MET'}")
print("=" * 60)
