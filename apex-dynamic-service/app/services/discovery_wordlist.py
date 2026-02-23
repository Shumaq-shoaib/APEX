"""
Curated wordlists for the APEX API Discovery Engine.
Organized by category and prioritized for maximum coverage with minimal probes.
"""

SPEC_PROBE_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/docs/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/api.json",
    "/api/schema",
    "/.well-known/openapi",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/api/v3/openapi.json",
    "/docs",
    "/redoc",
]

CORE_API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/users", "/api/user", "/api/accounts", "/api/account",
    "/api/auth", "/api/auth/login", "/api/auth/register", "/api/auth/signup",
    "/api/auth/token", "/api/auth/refresh", "/api/auth/logout",
    "/api/auth/forgot-password", "/api/auth/reset-password",
    "/api/auth/verify", "/api/auth/check-otp",
    "/api/login", "/api/register", "/api/signup",
    "/api/me", "/api/profile", "/api/user/profile",
    "/api/products", "/api/product", "/api/items", "/api/catalog",
    "/api/orders", "/api/order", "/api/cart", "/api/checkout",
    "/api/payments", "/api/payment", "/api/transactions", "/api/billing",
    "/api/invoices", "/api/subscriptions",
    "/api/posts", "/api/comments", "/api/messages", "/api/notifications",
    "/api/feeds", "/api/timeline", "/api/activity",
    "/api/files", "/api/upload", "/api/uploads", "/api/images", "/api/media",
    "/api/documents", "/api/attachments", "/api/download",
    "/api/search", "/api/search/users", "/api/search/products",
    "/api/categories", "/api/tags", "/api/labels",
    "/api/settings", "/api/config", "/api/preferences",
    "/api/dashboard", "/api/stats", "/api/analytics", "/api/reports",
    "/api/roles", "/api/permissions", "/api/groups",
    "/api/tokens", "/api/keys", "/api/apikeys",
    "/api/webhooks", "/api/hooks", "/api/callbacks",
    "/api/jobs", "/api/tasks", "/api/queue",
    "/api/logs", "/api/audit", "/api/events",
    "/api/contacts", "/api/addresses",
    "/api/vehicles", "/api/vehicle",
    "/api/shop", "/api/store",
    "/api/community", "/api/forum",
    "/api/reviews", "/api/ratings", "/api/feedback",
    "/health", "/healthz", "/ready", "/readyz",
    "/status", "/ping", "/version", "/info",
    "/api/health", "/api/status", "/api/ping", "/api/version",
]

SHADOW_PATHS = [
    "/api/internal", "/api/internal/users", "/api/internal/admin",
    "/api/internal/config", "/api/internal/debug",
    "/api/debug", "/api/debug/vars", "/api/debug/pprof",
    "/api/debug/requests", "/api/debug/sql",
    "/api/test", "/api/testing", "/api/staging", "/api/dev",
    "/api/sandbox", "/api/mock", "/api/demo",
    "/api/v0", "/api/v1beta", "/api/v2beta", "/api/v1alpha",
    "/api/legacy", "/api/old", "/api/deprecated",
    "/api/private", "/api/hidden", "/api/secret",
    "/api/graphql", "/graphql", "/gql", "/api/gql",
    "/api/batch", "/api/bulk", "/api/rpc",
    "/api/proxy", "/api/forward", "/api/relay",
    "/api/export", "/api/import", "/api/sync",
    "/api/backup", "/api/restore", "/api/migrate",
    "/_internal", "/_debug", "/_status", "/_health", "/_info",
    "/_api", "/_admin", "/_config",
    "/admin", "/admin/api", "/admin/users", "/admin/settings",
    "/admin/dashboard", "/admin/login",
    "/manage", "/management", "/manager",
    "/console", "/shell", "/terminal",
    "/metrics", "/prometheus", "/prometheus/metrics",
    "/env", "/config", "/configprops",
    "/trace", "/dump", "/heapdump",
    "/cgi-bin", "/server-info", "/server-status",
    "/api/swagger", "/api/spec", "/api/docs",
    "/api/admin", "/api/admin/users", "/api/admin/settings",
    "/api/admin/config", "/api/admin/dashboard",
    "/api/system", "/api/system/info", "/api/system/health",
    "/api/monitor", "/api/metrics",
    "/api/token", "/api/oauth", "/api/oauth/token",
    "/api/sso", "/api/saml",
]

FRAMEWORK_PATHS = {
    "spring": [
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/beans",
        "/actuator/mappings", "/actuator/configprops", "/actuator/trace",
        "/actuator/metrics", "/actuator/info", "/actuator/loggers",
        "/actuator/threaddump", "/actuator/heapdump", "/actuator/scheduledtasks",
        "/actuator/httptrace", "/actuator/flyway", "/actuator/liquibase",
        "/jolokia", "/jolokia/list",
    ],
    "django": [
        "/admin/", "/admin/login/", "/api/schema/",
        "/__debug__/", "/__debug__/sql/", "/__debug__/templates/",
        "/api/auth/", "/api/token/",
        "/static/", "/media/",
    ],
    "express": [
        "/api-json", "/api-yaml",
        "/api/v1/docs", "/api/v1/health",
        "/.env", "/package.json",
    ],
    "fastapi": [
        "/docs", "/redoc", "/openapi.json",
        "/api/docs", "/api/redoc",
    ],
    "rails": [
        "/rails/info", "/rails/info/properties", "/rails/info/routes",
        "/rails/mailers", "/sidekiq",
    ],
    "aspnet": [
        "/swagger/v1/swagger.json", "/_framework/",
        "/api/swagger", "/hangfire",
        "/_blazor",
    ],
    "laravel": [
        "/api/user", "/sanctum/csrf-cookie",
        "/telescope", "/horizon",
        "/_ignition/health-check",
    ],
    "nestjs": [
        "/api-json", "/api-yaml", "/api",
        "/graphql",
    ],
}

COMMON_PARAM_NAMES = [
    "id", "user_id", "userId", "account_id", "accountId",
    "email", "username", "name", "phone",
    "search", "q", "query", "filter", "keyword", "term",
    "sort", "order", "orderBy", "sortBy", "direction",
    "page", "limit", "offset", "per_page", "pageSize", "skip", "take",
    "token", "key", "api_key", "apiKey", "access_token",
    "format", "type", "status", "state", "category",
    "url", "redirect", "redirect_url", "callback", "return_url", "next",
    "file", "path", "filename", "dir",
    "action", "cmd", "command", "exec",
    "lang", "locale", "language",
    "fields", "include", "expand", "select",
    "start_date", "end_date", "from", "to", "date",
    "lat", "lng", "latitude", "longitude", "location",
    "price", "amount", "quantity", "count",
    "role", "permission", "group",
    "version", "v",
]

COMMON_BODY_FIELDS = {
    "id": 1,
    "name": "test",
    "email": "test@test.com",
    "username": "testuser",
    "password": "testpass123",
    "phone": "+1234567890",
    "address": "123 Test St",
    "role": "user",
    "status": "active",
    "title": "Test",
    "description": "Test description",
    "url": "http://example.com",
    "amount": 100,
    "quantity": 1,
    "type": "default",
    "category": "general",
    "is_admin": False,
    "admin": False,
    "verified": True,
}

GRAPHQL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""

HTTP_METHODS_TO_PROBE = ["GET", "POST", "PUT", "PATCH", "DELETE"]
