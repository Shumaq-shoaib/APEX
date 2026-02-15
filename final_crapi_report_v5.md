# ZAP-Python Security Report

**Target:** http://192.168.0.128:8888/
**Scanners:** Active IDOR Scanner, OS Command Injection, Missing Security Headers, Username Hash Disclosure (IDOR), SQL Injection, JWT Security Scanner, Mass Assignment Scanner, External Redirect Scanner, SSRF Scanner, XML External Entity (XXE)
**Total Findings:** 1112

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

**Affected Endpoints (7):**

#### 1. POST /identity/api/auth/v2.7/user/login-with-token
```text
Payload: http://169.254.169.254/computeMetadata/v1/
Matched Regex: computeMetadata
Response Snippet: User was not found for parameters {userEmail=http://169.254.169.254/computeMetadata/v1/}
```

#### 2. POST /identity/api/auth/v2.7/user/login-with-token
```text
Payload: http://100.100.100.200/latest/meta-data/
Matched Regex: latest/meta-data
Response Snippet: User was not found for parameters {userEmail=http://100.100.100.200/latest/meta-data/}
```

#### 3. POST /identity/api/auth/v2.7/user/login-with-token
```text
Payload: http://instance-data/latest/meta-data/
Matched Regex: latest/meta-data
Response Snippet: User was not found for parameters {userEmail=http://instance-data/latest/meta-data/}
```

#### 4. POST /workshop/api/shop/products
```text
Payload: http://169.254.169.254/latest/meta-data/
Matched Regex: latest/meta-data
Response Snippet: {"message":"Validation failed","details":"org.springframework.validation.BeanPropertyBindingResult: 
```

#### 5. POST /workshop/api/shop/products
```text
Payload: http://169.254.169.254/computeMetadata/v1/
Matched Regex: computeMetadata
Response Snippet: {"message":"Validation failed","details":"org.springframework.validation.BeanPropertyBindingResult: 
```

#### 6. POST /workshop/api/shop/products
```text
Payload: http://100.100.100.200/latest/meta-data/
Matched Regex: latest/meta-data
Response Snippet: {"message":"Validation failed","details":"org.springframework.validation.BeanPropertyBindingResult: 
```

#### 7. POST /workshop/api/shop/products
```text
Payload: http://instance-data/latest/meta-data/
Matched Regex: latest/meta-data
Response Snippet: {"message":"Validation failed","details":"org.springframework.validation.BeanPropertyBindingResult: 
```

---
### Blind Command Injection (Unix - Time Based)
**Category:** API8:2023 Injection
**Exploitability:** High
**Description:** The application responded in 6.57s, consistent with the injected time delay.

**Affected Endpoints (8):**

#### 1. GET /workshop/api/mechanic/receive_report
```text
Param: mechanic_code
Payload: sleep 5
Response Time: 6.57s
```

#### 2. GET /workshop/api/mechanic/receive_report
```text
Param: video_id
Payload: sleep 5
Response Time: 7.68s
```

#### 3. GET /workshop/api/mechanic/receive_report
```text
Param: limit
Payload: sleep 5
Response Time: 6.34s
```

#### 4. GET /workshop/api/mechanic/receive_report
```text
Param: limit
Payload: sleep 5
Response Time: 6.07s
```

#### 5. GET /workshop/api/mechanic/receive_report
```text
Param: order_id
Payload: sleep 5
Response Time: 6.00s
```

#### 6. GET /workshop/api/mechanic/receive_report
```text
Param: report_id
Payload: sleep 5
Response Time: 6.74s
```

#### 7. GET /workshop/api/mechanic/receive_report
```text
Param: limit
Payload: sleep 5
Response Time: 6.67s
```

#### 8. GET /workshop/api/mechanic/receive_report
```text
Param: offset
Payload: ;sleep 5;
Response Time: 5.06s
```

---
## High Severity Findings

### Potential IDOR (ID Fuzzing)
**Category:** API1:2023 Broken Object Level Authorization
**Exploitability:** High
**Description:** The endpoint returned a 2xx success code when accessing ID '1' via ID Fuzzing. Verify authorization.
Discovered sensitive key: \"email\":

**Affected Endpoints (1):**

#### 1. POST /community/api/v2/community/posts/{postId}/comment
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

#### 1. POST /community/api/v2/community/posts/{postId}/comment
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

**Affected Endpoints (20):**

#### 1. GET /community/api/v2/community/posts/recent
```text
Param: postId
Payload: HtTpS://92f578c2-d72d-445f-a7cc-1995a440ab96.owasp.org
Location Header: /community/api/v2/community/posts/HtTpS:/92f578c2-d72d-445f-a7cc-1995a440ab96.owasp.org/comment
```

#### 2. GET /community/api/v2/community/posts/recent
```text
Param: postId
Payload: HtTp://92f578c2-d72d-445f-a7cc-1995a440ab96.owasp.org
Location Header: /community/api/v2/community/posts/HtTp:/92f578c2-d72d-445f-a7cc-1995a440ab96.owasp.org/comment
```

#### 3. GET /community/api/v2/community/posts/recent
```text
Param: postId
Payload: https://92f578c2-d72d-445f-a7cc-1995a440ab96.owasp.org/?foo
Location Header: /community/api/v2/community/posts/https:/92f578c2-d72d-445f-a7cc-1995a440ab96.owasp.org/?foo/comment
```

#### 4. GET /community/api/v2/community/posts/recent
```text
Param: postId
Payload: https://92f578c2-d72d-445f-a7cc-1995a440ab96.owasp.org
Location Header: /community/api/v2/community/posts/https:/92f578c2-d72d-445f-a7cc-1995a440ab96.owasp.org/comment
```

#### 5. GET /community/api/v2/community/posts/recent
```text
Param: postId
Payload: https://\92f578c2-d72d-445f-a7cc-1995a440ab96.owasp.org
Location Header: /community/api/v2/community/posts/https:/%5C92f578c2-d72d-445f-a7cc-1995a440ab96.owasp.org/comment
```

#### 6. GET /community/api/v2/community/posts/recent
```text
Param: postId
Payload: http://\92f578c2-d72d-445f-a7cc-1995a440ab96.owasp.org
Location Header: /community/api/v2/community/posts/http:/%5C92f578c2-d72d-445f-a7cc-1995a440ab96.owasp.org/comment
```

#### 7. GET /community/api/v2/community/posts/recent
```text
Param: postId
Payload: 5;URL='https://92f578c2-d72d-445f-a7cc-1995a440ab96.owasp.org'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/92f578c2-d72d-445f-a7cc-1995a440ab96.owasp.org%27/comment
```

#### 8. GET /community/api/v2/community/posts/recent
```text
Param: postId
Payload: URL='http://92f578c2-d72d-445f-a7cc-1995a440ab96.owasp.org'
Location Header: /community/api/v2/community/posts/URL=%27http:/92f578c2-d72d-445f-a7cc-1995a440ab96.owasp.org%27/comment
```

#### 9. GET /community/api/v2/community/posts/recent
```text
Param: postId
Payload: 5;URL='https://92f578c2-d72d-445f-a7cc-1995a440ab96.owasp.org/?foo'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/92f578c2-d72d-445f-a7cc-1995a440ab96.owasp.org/?foo'/comment
```

#### 10. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: http://9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org
Location Header: /community/api/v2/community/posts/http:/9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org
```

#### 11. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: https://9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org
Location Header: /community/api/v2/community/posts/https:/9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org
```

#### 12. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: //9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org
Location Header: /community/api/v2/community/posts/9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org
```

#### 13. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: HtTpS://9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org
Location Header: /community/api/v2/community/posts/HtTpS:/9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org
```

#### 14. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: HtTp://9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org
Location Header: /community/api/v2/community/posts/HtTp:/9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org
```

#### 15. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: https://9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org/?foo
Location Header: /community/api/v2/community/posts/https:/9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org/?foo
```

#### 16. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: https://\9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org
Location Header: /community/api/v2/community/posts/https:/%5C9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org
```

#### 17. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: http://\9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org
Location Header: /community/api/v2/community/posts/http:/%5C9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org
```

#### 18. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: 5;URL='https://9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org%27
```

#### 19. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: URL='http://9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org'
Location Header: /community/api/v2/community/posts/URL=%27http:/9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org%27
```

#### 20. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: 5;URL='https://9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org/?foo'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/9d7d55b0-4c5d-4eba-b11a-3d061d3614fd.owasp.org/?foo'
```

---
## Low Severity Findings

### Missing Content-Security-Policy Header
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Low
**Description:** The response is missing the Content-Security-Policy security header.

**Affected Endpoints (20):**

#### 1. GET /community/api/v2/community/posts/recent
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 2. POST /community/api/v2/community/posts/{postId}/comment
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 3. POST /community/api/v2/community/posts/{postId}/comment
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 4. GET /identity/api/v2/user/videos/convert_video
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 5. DELETE /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 6. PUT /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 7. PUT /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 8. GET /identity/api/v2/vehicle/{vehicleId}/location
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 9. GET /workshop/api/management/users/all
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 10. GET /workshop/api/mechanic/mechanic_report
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 11. GET /workshop/api/mechanic/receive_report
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 12. GET /workshop/api/mechanic/service_requests
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 13. POST /workshop/api/merchant/contact_mechanic
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 14. POST /workshop/api/merchant/contact_mechanic
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 15. POST /workshop/api/merchant/contact_mechanic
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 16. POST /workshop/api/merchant/contact_mechanic
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'content-disposition', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 17. POST /workshop/api/merchant/contact_mechanic
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 18. GET /workshop/api/shop/orders/all
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 19. GET /workshop/api/shop/orders/{order_id}
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 20. PUT /workshop/api/shop/orders/{order_id}
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

---
### Missing Strict-Transport-Security Header
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Low
**Description:** The response is missing the Strict-Transport-Security security header.

**Affected Endpoints (20):**

#### 1. GET /community/api/v2/community/posts/recent
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 2. POST /community/api/v2/community/posts/{postId}/comment
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 3. POST /community/api/v2/community/posts/{postId}/comment
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 4. GET /identity/api/v2/user/videos/convert_video
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 5. DELETE /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 6. PUT /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 7. PUT /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 8. GET /identity/api/v2/vehicle/{vehicleId}/location
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 9. GET /workshop/api/management/users/all
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 10. GET /workshop/api/mechanic/mechanic_report
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 11. GET /workshop/api/mechanic/receive_report
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 12. GET /workshop/api/mechanic/service_requests
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 13. POST /workshop/api/merchant/contact_mechanic
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 14. POST /workshop/api/merchant/contact_mechanic
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'vary', 'x-content-type-options', 'x-xss-protection', 'cache-control', 'pragma', 'expires', 'x-frame-options']
```

#### 15. POST /workshop/api/merchant/contact_mechanic
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 16. POST /workshop/api/merchant/contact_mechanic
```text
Headers received: ['server', 'date', 'content-type', 'content-length', 'connection', 'content-disposition', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 17. POST /workshop/api/merchant/contact_mechanic
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 18. GET /workshop/api/shop/orders/all
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'allow', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 19. GET /workshop/api/shop/orders/{order_id}
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'vary', 'x-frame-options', 'x-content-type-options', 'referrer-policy', 'cross-origin-opener-policy']
```

#### 20. PUT /workshop/api/shop/orders/{order_id}
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

#### 2. POST /community/api/v2/community/posts/{postId}/comment
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 3. PUT /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

#### 4. POST /workshop/api/merchant/contact_mechanic
```text
Headers received: ['server', 'date', 'content-type', 'transfer-encoding', 'connection', 'access-control-allow-headers', 'access-control-allow-methods', 'access-control-allow-origin']
```

---
