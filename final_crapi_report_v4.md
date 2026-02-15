# ZAP-Python Security Report

**Target:** http://192.168.0.128:8888/
**Scanners:** Active IDOR Scanner, OS Command Injection, Missing Security Headers, Username Hash Disclosure (IDOR), SQL Injection, JWT Security Scanner, Mass Assignment Scanner, External Redirect Scanner, SSRF Scanner, XML External Entity (XXE)
**Total Findings:** 1140

## Critical Severity Findings

### JWT None Algorithm
**Category:** API2:2023 Broken Authentication
**Exploitability:** High
**Description:** The server accepted a JWT signed with the 'none' algorithm.

**Affected Endpoints (1):**

#### 1. GET /workshop/api/shop/products
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ6YXBfdXNlcl9hcTk5ZWRAZXhhbXBsZS5jb20iLCJpYXQiOjE3Njk0NTYwMTMsImV4cCI6MTc3MDA2MDgxMywicm9sZSI6InVzZXIifQ.
Response Code: 200
```

---
### JWT Signature Exclusion
**Category:** API2:2023 Broken Authentication
**Exploitability:** High
**Description:** The server accepted a JWT with the signature removed.

**Affected Endpoints (1):**

#### 1. GET /workshop/api/shop/products
```text
Token Used: eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ6YXBfdXNlcl9hcTk5ZWRAZXhhbXBsZS5jb20iLCJpYXQiOjE3Njk0NTYwMTMsImV4cCI6MTc3MDA2MDgxMywicm9sZSI6InVzZXIifQ.
Response Code: 200
```

---
### SSRF - Cloud Metadata Exposure
**Category:** API10:2023 Server Side Request Forgery (SSRF)
**Exploitability:** High
**Description:** The application appears to have fetched an internal/external resource requested via the 'email' parameter (Content Match).

**Affected Endpoints (2):**

#### 1. POST /community/api/v2/community/posts
```text
Payload: http://169.254.169.254/computeMetadata/v1/
Matched Regex: computeMetadata
Response Snippet: User was not found for parameters {userEmail=http://169.254.169.254/computeMetadata/v1/}
```

#### 2. POST /identity/api/auth/v4.0/user/login-with-token
```text
Payload: http://instance-data/latest/meta-data/
Matched Regex: latest/meta-data
Response Snippet: User was not found for parameters {userEmail=http://instance-data/latest/meta-data/}
```

---
### Blind Command Injection (Windows - Time Based)
**Category:** API8:2023 Injection
**Exploitability:** High
**Description:** The application responded in 6.89s, consistent with the injected time delay.

**Affected Endpoints (5):**

#### 1. GET /workshop/api/mechanic/receive_report
```text
Param: mechanic_code
Payload: timeout /t 5
Response Time: 6.89s
```

#### 2. GET /workshop/api/mechanic/receive_report
```text
Param: video_id
Payload: timeout /t 5
Response Time: 7.67s
```

#### 3. GET /workshop/api/mechanic/receive_report
```text
Param: limit
Payload: timeout /t 5
Response Time: 7.86s
```

#### 4. GET /workshop/api/mechanic/receive_report
```text
Param: report_id
Payload: timeout /t 5
Response Time: 8.07s
```

#### 5. GET /workshop/api/mechanic/receive_report
```text
Param: limit
Payload: timeout /t 5
Response Time: 7.56s
```

---
### Blind Command Injection (Unix - Time Based)
**Category:** API8:2023 Injection
**Exploitability:** High
**Description:** The application responded in 5.41s, consistent with the injected time delay.

**Affected Endpoints (12):**

#### 1. GET /workshop/api/mechanic/receive_report
```text
Param: vehicleId
Payload: sleep 5
Response Time: 5.41s
```

#### 2. GET /workshop/api/mechanic/receive_report
```text
Param: video_id
Payload: sleep 5
Response Time: 6.00s
```

#### 3. GET /workshop/api/mechanic/receive_report
```text
Param: postId
Payload: sleep 5
Response Time: 7.26s
```

#### 4. GET /workshop/api/mechanic/receive_report
```text
Param: video_id
Payload: sleep 5
Response Time: 7.57s
```

#### 5. GET /workshop/api/mechanic/receive_report
```text
Param: video_id
Payload: sleep 5
Response Time: 7.18s
```

#### 6. GET /workshop/api/mechanic/receive_report
```text
Param: postId
Payload: sleep 5
Response Time: 7.55s
```

#### 7. GET /workshop/api/mechanic/receive_report
```text
Param: video_id
Payload: sleep 5
Response Time: 8.26s
```

#### 8. GET /workshop/api/mechanic/receive_report
```text
Param: order_id
Payload: sleep 5
Response Time: 6.73s
```

#### 9. GET /workshop/api/mechanic/receive_report
```text
Param: order_id
Payload: sleep 5
Response Time: 6.80s
```

#### 10. GET /workshop/api/mechanic/receive_report
```text
Param: problem_details
Payload: sleep 5
Response Time: 6.82s
```

#### 11. GET /workshop/api/mechanic/receive_report
```text
Param: offset
Payload: sleep 5
Response Time: 6.61s
```

#### 12. GET /workshop/api/mechanic/receive_report
```text
Param: offset
Payload: sleep 5
Response Time: 6.14s
```

---
## High Severity Findings

### Potential IDOR (ID Fuzzing)
**Category:** API1:2023 Broken Object Level Authorization
**Exploitability:** High
**Description:** The endpoint returned a 2xx success code when accessing ID '1' via ID Fuzzing. Verify authorization.
Discovered sensitive key: \"email\":

**Affected Endpoints (1):**

#### 1. GET /workshop/api/shop/orders/{order_id}
```text
Method: GET
URL: http://192.168.0.128:8888/workshop/api/shop/orders/1
Payload: 1
Status: 200
```

---
### Potential IDOR (Method Swap (GET))
**Category:** API1:2023 Broken Object Level Authorization
**Exploitability:** High
**Description:** The endpoint returned a 2xx success code when accessing ID '1' via Method Swap (GET). Verify authorization.
Discovered sensitive key: \"email\":

**Affected Endpoints (1):**

#### 1. GET /workshop/api/shop/orders/{order_id}
```text
Method: GET
URL: http://192.168.0.128:8888/workshop/api/shop/orders/1
Payload: 1
Status: 200
```

---
## Medium Severity Findings

### Open Redirect (Header)
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Medium
**Description:** The application redirects to an arbitrary external domain specified in the request parameter.

**Affected Endpoints (14):**

#### 1. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: 5;URL='https://90a22e61-03e9-43a0-ad72-14ff19eab177.owasp.org'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/90a22e61-03e9-43a0-ad72-14ff19eab177.owasp.org%27/comment
```

#### 2. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: URL='http://90a22e61-03e9-43a0-ad72-14ff19eab177.owasp.org'
Location Header: /community/api/v2/community/posts/URL=%27http:/90a22e61-03e9-43a0-ad72-14ff19eab177.owasp.org%27/comment
```

#### 3. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: 5;URL='https://90a22e61-03e9-43a0-ad72-14ff19eab177.owasp.org/?foo'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/90a22e61-03e9-43a0-ad72-14ff19eab177.owasp.org/?foo'/comment
```

#### 4. GET /identity/api/v2/user/videos/convert_video
```text
Param: postId
Payload: http://19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org
Location Header: /community/api/v2/community/posts/http:/19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org
```

#### 5. GET /identity/api/v2/user/videos/convert_video
```text
Param: postId
Payload: https://19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org
Location Header: /community/api/v2/community/posts/https:/19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org
```

#### 6. GET /identity/api/v2/user/videos/convert_video
```text
Param: postId
Payload: //19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org
Location Header: /community/api/v2/community/posts/19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org
```

#### 7. GET /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: HtTp://19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org
Location Header: /community/api/v2/community/posts/HtTp:/19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org
```

#### 8. GET /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: https://19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org/?foo
Location Header: /community/api/v2/community/posts/https:/19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org/?foo
```

#### 9. GET /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: https://19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org
Location Header: /community/api/v2/community/posts/https:/19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org
```

#### 10. GET /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: https://\19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org
Location Header: /community/api/v2/community/posts/https:/%5C19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org
```

#### 11. GET /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: http://\19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org
Location Header: /community/api/v2/community/posts/http:/%5C19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org
```

#### 12. GET /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: 5;URL='https://19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org%27
```

#### 13. GET /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: URL='http://19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org'
Location Header: /community/api/v2/community/posts/URL=%27http:/19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org%27
```

#### 14. GET /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: 5;URL='https://19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org/?foo'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/19be6701-e00b-42ec-aa15-7843b50e82f8.owasp.org/?foo'
```

---
## Low Severity Findings

### Missing Content-Security-Policy Header
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Low
**Description:** The response is missing the Content-Security-Policy security header.

**Affected Endpoints (17):**

#### 1. GET /community/api/v2/community/posts/recent
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 2. GET /community/api/v2/community/posts/{postId}
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 3. DELETE /identity/api/v2/admin/videos/{video_id}
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 4. DELETE /identity/api/v2/admin/videos/{video_id}
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 5. GET /identity/api/v2/user/videos/convert_video
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 6. GET /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 7. GET /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 8. GET /workshop/api/mechanic/
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 9. GET /workshop/api/mechanic/
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 10. GET /workshop/api/mechanic/
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 11. GET /workshop/api/mechanic/
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'content-disposition', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 12. GET /workshop/api/mechanic/
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 13. GET /workshop/api/mechanic/mechanic_report
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 14. GET /workshop/api/mechanic/receive_report
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 15. GET /workshop/api/mechanic/service_requests
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 16. GET /workshop/api/shop/orders/all
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 17. GET /workshop/api/shop/orders/{order_id}
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

---
### Missing X-Content-Type-Options Header
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Low
**Description:** The response is missing the X-Content-Type-Options security header.

**Affected Endpoints (4):**

#### 1. GET /community/api/v2/community/posts/recent
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 2. GET /community/api/v2/community/posts/{postId}
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 3. DELETE /identity/api/v2/admin/videos/{video_id}
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 4. GET /workshop/api/mechanic/
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

---
### Missing Strict-Transport-Security Header
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Low
**Description:** The response is missing the Strict-Transport-Security security header.

**Affected Endpoints (17):**

#### 1. GET /community/api/v2/community/posts/recent
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 2. GET /community/api/v2/community/posts/{postId}
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 3. DELETE /identity/api/v2/admin/videos/{video_id}
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 4. DELETE /identity/api/v2/admin/videos/{video_id}
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 5. GET /identity/api/v2/user/videos/convert_video
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 6. GET /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 7. GET /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 8. GET /workshop/api/mechanic/
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 9. GET /workshop/api/mechanic/
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 10. GET /workshop/api/mechanic/
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 11. GET /workshop/api/mechanic/
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'content-disposition', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 12. GET /workshop/api/mechanic/
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 13. GET /workshop/api/mechanic/mechanic_report
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 14. GET /workshop/api/mechanic/receive_report
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 15. GET /workshop/api/mechanic/service_requests
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 16. GET /workshop/api/shop/orders/all
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 17. GET /workshop/api/shop/orders/{order_id}
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

---
