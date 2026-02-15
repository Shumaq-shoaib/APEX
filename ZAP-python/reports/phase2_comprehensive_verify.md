# ZAP-Python Security Report

**Target:** http://localhost:8888
**Scanners:** OS Command Injection, Missing Security Headers, Username Hash Disclosure (IDOR), SQL Injection, JWT Security Scanner, Mass Assignment Scanner, External Redirect Scanner, SSRF Scanner, XML External Entity (XXE)
**Total Findings:** 1322

## Critical Severity Findings

### JWT None Algorithm
**Category:** API2:2023 Broken Authentication
**Exploitability:** High
**Description:** The server accepted a JWT signed with the 'none' algorithm.

**Affected Endpoints (4):**

#### 1. GET /community/api/v2/community/posts/recent
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ6YXBfdXNlcl81azI5NXVAZXhhbXBsZS5jb20iLCJpYXQiOjE3Njk1Mzk2ODUsImV4cCI6MTc3MDE0NDQ4NSwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 2. POST /identity/api/v2/vehicle/resend_email
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ6YXBfdXNlcl81azI5NXVAZXhhbXBsZS5jb20iLCJpYXQiOjE3Njk1Mzk2ODUsImV4cCI6MTc3MDE0NDQ4NSwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 3. GET /workshop/api/management/users/all
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ6YXBfdXNlcl81azI5NXVAZXhhbXBsZS5jb20iLCJpYXQiOjE3Njk1Mzk2ODUsImV4cCI6MTc3MDE0NDQ4NSwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 4. GET /workshop/api/mechanic/service_requests
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ6YXBfdXNlcl81azI5NXVAZXhhbXBsZS5jb20iLCJpYXQiOjE3Njk1Mzk2ODUsImV4cCI6MTc3MDE0NDQ4NSwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

---
### JWT Signature Exclusion
**Category:** API2:2023 Broken Authentication
**Exploitability:** High
**Description:** The server accepted a JWT with the signature removed.

**Affected Endpoints (1):**

#### 1. POST /identity/api/v2/vehicle/resend_email
```text
Token Used: eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ6YXBfdXNlcl81azI5NXVAZXhhbXBsZS5jb20iLCJpYXQiOjE3Njk1Mzk2ODUsImV4cCI6MTc3MDE0NDQ4NSwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

---
### NoSQL Injection (Logic Bypass)
**Category:** API8:2023 Injection
**Exploitability:** High
**Description:** The endpoint returned HTTP 200 OK for a NoSQL logic bypass payload. This suggests it accepted the query.

**Affected Endpoints (7):**

#### 1. POST /workshop/api/merchant/contact_mechanic
```text
Param: body
Payload: {'coupon_code': {'$ne': None}}
Response Code: 200
```

#### 2. POST /workshop/api/merchant/contact_mechanic
```text
Param: body
Payload: {'coupon_code': {'$gt': ''}}
Response Code: 200
```

#### 3. POST /workshop/api/merchant/contact_mechanic
```text
Param: body
Payload: {'content': "'; return true; var foo='", 'title': 'test'}
Response Code: 200
```

#### 4. POST /workshop/api/merchant/contact_mechanic
```text
Param: body
Payload: {'email': "'; return true; var foo='", 'password': 'test'}
Response Code: 200
```

#### 5. POST /workshop/api/merchant/contact_mechanic
```text
Param: body
Payload: {'coupon_code': 'test', 'amount': "'; return true; var foo='"}
Response Code: 200
```

#### 6. POST /workshop/api/merchant/contact_mechanic
```text
Param: body
Payload: {'content': 'test', 'title': "'; return true; var foo='"}
Response Code: 200
```

#### 7. POST /workshop/api/merchant/contact_mechanic
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

**Affected Endpoints (2):**

#### 1. POST /identity/api/v2/user/reset-password
```text
Payload: http://localhost:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

#### 2. GET /workshop/api/management/users/all
```text
Payload: http://localhost:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

---
### Blind Command Injection (Windows - Time Based)
**Category:** API8:2023 Injection
**Exploitability:** High
**Description:** The application responded in 6.21s, consistent with the injected time delay.

**Affected Endpoints (1):**

#### 1. GET /workshop/api/mechanic/receive_report
```text
Param: order_id
Payload: | timeout /t 5
Response Time: 6.21s
```

---
## High Severity Findings

### SSRF - Connection Attempt Failed
**Category:** API10:2023 Server Side Request Forgery (SSRF)
**Exploitability:** High
**Description:** The application revealed a connection error when trying to access an internal port, indicating it attempted the connection.

**Affected Endpoints (2):**

#### 1. GET /workshop/api/mechanic/mechanic_report
```text
Payload: http://localhost:22
Response content indicates connection failure (Blind SSRF): '{"message":"Could not connect to mechanic api."}'
```

#### 2. GET /workshop/api/mechanic/mechanic_report
```text
Payload: http://127.0.0.1:22
Response content indicates connection failure (Blind SSRF): '{"message":"Could not connect to mechanic api."}'
```

---
## Medium Severity Findings

### Mass Assignment (Status Anomaly)
**Category:** API3:2023 Broken Object Property Level Authorization
**Exploitability:** Medium
**Description:** Injecting 'confirmed' caused a status code change from 400 to 200. Investigate for logic bypass.

**Affected Endpoints (1):**

#### 1. POST /workshop/api/shop/orders
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

**Affected Endpoints (18):**

#### 1. POST /workshop/api/shop/orders/return_order
```text
Param: postId
Payload: http://c3f28a6c-8c18-4fab-817e-6d792ea088e7.owasp.org
Location Header: /community/api/v2/community/posts/http:/c3f28a6c-8c18-4fab-817e-6d792ea088e7.owasp.org/comment
```

#### 2. POST /workshop/api/shop/orders/return_order
```text
Param: postId
Payload: https://c3f28a6c-8c18-4fab-817e-6d792ea088e7.owasp.org
Location Header: /community/api/v2/community/posts/https:/c3f28a6c-8c18-4fab-817e-6d792ea088e7.owasp.org/comment
```

#### 3. POST /workshop/api/shop/orders/return_order
```text
Param: postId
Payload: //c3f28a6c-8c18-4fab-817e-6d792ea088e7.owasp.org
Location Header: /community/api/v2/community/posts/c3f28a6c-8c18-4fab-817e-6d792ea088e7.owasp.org/comment
```

#### 4. POST /workshop/api/shop/orders/return_order
```text
Param: postId
Payload: HtTpS://c3f28a6c-8c18-4fab-817e-6d792ea088e7.owasp.org
Location Header: /community/api/v2/community/posts/HtTpS:/c3f28a6c-8c18-4fab-817e-6d792ea088e7.owasp.org/comment
```

#### 5. POST /workshop/api/shop/orders/return_order
```text
Param: postId
Payload: HtTp://c3f28a6c-8c18-4fab-817e-6d792ea088e7.owasp.org
Location Header: /community/api/v2/community/posts/HtTp:/c3f28a6c-8c18-4fab-817e-6d792ea088e7.owasp.org/comment
```

#### 6. POST /workshop/api/shop/orders/return_order
```text
Param: postId
Payload: https://c3f28a6c-8c18-4fab-817e-6d792ea088e7.owasp.org/?foo
Location Header: /community/api/v2/community/posts/https:/c3f28a6c-8c18-4fab-817e-6d792ea088e7.owasp.org/?foo/comment
```

#### 7. GET /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: //2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org
Location Header: /community/api/v2/community/posts/2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org
```

#### 8. GET /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: HtTpS://2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org
Location Header: /community/api/v2/community/posts/HtTpS:/2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org
```

#### 9. GET /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: HtTp://2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org
Location Header: /community/api/v2/community/posts/HtTp:/2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org
```

#### 10. GET /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: https://2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org/?foo
Location Header: /community/api/v2/community/posts/https:/2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org/?foo
```

#### 11. GET /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: https://2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org
Location Header: /community/api/v2/community/posts/https:/2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org
```

#### 12. GET /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: https://\2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org
Location Header: /community/api/v2/community/posts/https:/%5C2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org
```

#### 13. GET /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: http://\2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org
Location Header: /community/api/v2/community/posts/http:/%5C2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org
```

#### 14. GET /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: 5;URL='https://2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org%27
```

#### 15. GET /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: URL='http://2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org'
Location Header: /community/api/v2/community/posts/URL=%27http:/2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org%27
```

#### 16. GET /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: 5;URL='https://2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org/?foo'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/2cf8bfc1-25a2-4eab-9f55-72130b480a49.owasp.org/?foo'
```

#### 17. PUT /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: URL='http://c3f28a6c-8c18-4fab-817e-6d792ea088e7.owasp.org'
Location Header: /community/api/v2/community/posts/URL=%27http:/c3f28a6c-8c18-4fab-817e-6d792ea088e7.owasp.org%27/comment
```

#### 18. PUT /workshop/api/shop/orders/{order_id}
```text
Param: postId
Payload: 5;URL='https://c3f28a6c-8c18-4fab-817e-6d792ea088e7.owasp.org/?foo'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/c3f28a6c-8c18-4fab-817e-6d792ea088e7.owasp.org/?foo'/comment
```

---
## Low Severity Findings

### Missing Content-Security-Policy Header
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Low
**Description:** The response is missing the Content-Security-Policy security header.

**Affected Endpoints (13):**

#### 1. GET /community/api/v2/community/posts/recent
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 2. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Content-Disposition', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 3. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 4. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 5. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 6. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 7. GET /workshop/api/management/users/all
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 8. GET /workshop/api/mechanic/mechanic_report
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 9. GET /workshop/api/mechanic/receive_report
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 10. GET /workshop/api/mechanic/service_requests
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 11. GET /workshop/api/shop/orders/{order_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 12. GET /workshop/api/shop/orders/{order_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 13. GET /workshop/api/shop/orders/{order_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

---
### Missing Strict-Transport-Security Header
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Low
**Description:** The response is missing the Strict-Transport-Security security header.

**Affected Endpoints (13):**

#### 1. GET /community/api/v2/community/posts/recent
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 2. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Content-Disposition', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 3. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 4. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 5. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 6. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 7. GET /workshop/api/management/users/all
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 8. GET /workshop/api/mechanic/mechanic_report
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 9. GET /workshop/api/mechanic/receive_report
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 10. GET /workshop/api/mechanic/service_requests
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 11. GET /workshop/api/shop/orders/{order_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 12. GET /workshop/api/shop/orders/{order_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 13. GET /workshop/api/shop/orders/{order_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

---
### Missing X-Content-Type-Options Header
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Low
**Description:** The response is missing the X-Content-Type-Options security header.

**Affected Endpoints (3):**

#### 1. GET /community/api/v2/community/posts/recent
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 2. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 3. GET /workshop/api/shop/orders/{order_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

---
