"""
APEX API Discovery Engine
Finds documented endpoints, undocumented shadow APIs, and hidden parameters
without requiring an OpenAPI spec file. Produces scanner-ready blueprints.
"""
import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx
import yaml

from app.services.discovery_wordlist import (
    SPEC_PROBE_PATHS, CORE_API_PATHS, SHADOW_PATHS, FRAMEWORK_PATHS,
    COMMON_PARAM_NAMES, COMMON_BODY_FIELDS, GRAPHQL_INTROSPECTION_QUERY,
    HTTP_METHODS_TO_PROBE,
)

logger = logging.getLogger(__name__)

MAX_TOTAL_PROBES = 800
DISCOVERY_TIMEOUT_SEC = 90
PER_REQUEST_TIMEOUT = 3.5
MINING_REQUEST_TIMEOUT = 5
MAX_CONCURRENCY = 30
RATE_LIMIT_CONCURRENCY = 5


@dataclass
class TechProfile:
    framework: Optional[str] = None
    api_style: str = "rest"
    version_prefix: Optional[str] = None
    auth_scheme: Optional[str] = None
    server_header: Optional[str] = None
    error_format: Optional[str] = None
    detected_hints: List[str] = field(default_factory=list)


@dataclass
class DiscoveredEndpoint:
    path: str
    method: str
    status_code: int = 0
    content_type: str = ""
    body_sample: str = ""
    params: List[Dict] = field(default_factory=list)
    schema: Dict = field(default_factory=dict)
    example: Dict = field(default_factory=dict)
    source: str = "discovery"

    def to_blueprint_entry(self) -> Dict:
        return {
            "path": self.path,
            "method": self.method.upper(),
            "params": self.params,
            "schema": self.schema,
            "example": self.example,
            "source": self.source,
        }


@dataclass
class DiscoveryResult:
    spec_blueprint: Optional[Dict] = None
    endpoints: List[Dict] = field(default_factory=list)
    tech_profile: Optional[TechProfile] = None
    stats: Dict = field(default_factory=dict)


class DiscoveryEngine:
    def __init__(self, target_url: str, auth_token: Optional[str] = None):
        self.base_url = target_url.rstrip("/")
        self.auth_token = auth_token
        self._seen: Set[str] = set()
        self._probe_count = 0
        self._start_time = 0.0
        self._rate_limited = False
        self._log_cb: Optional[Callable[[str], None]] = None
        self._discovered: Dict[Tuple[str, str], DiscoveredEndpoint] = {}

    def _headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {"User-Agent": "APEX-Scanner/1.0", "Accept": "application/json, */*"}
        if self.auth_token:
            token = self.auth_token
            if not token.lower().startswith("bearer "):
                token = f"Bearer {token}"
            h["Authorization"] = token
        return h

    def _log(self, msg: str):
        logger.info(msg)
        if self._log_cb:
            self._log_cb(msg)

    def _budget_ok(self) -> bool:
        if self._probe_count >= MAX_TOTAL_PROBES:
            return False
        if (time.monotonic() - self._start_time) > DISCOVERY_TIMEOUT_SEC:
            return False
        return True

    def _seen_key(self, method: str, path: str) -> str:
        return f"{method.upper()}:{path}"

    def _mark_seen(self, method: str, path: str) -> bool:
        """Returns True if newly added (not seen before)."""
        k = self._seen_key(method, path)
        if k in self._seen:
            return False
        self._seen.add(k)
        return True

    async def _probe(self, client: httpx.AsyncClient, method: str, url: str,
                     json_body: Optional[Dict] = None,
                     headers: Optional[Dict] = None,
                     timeout: float = PER_REQUEST_TIMEOUT) -> Optional[httpx.Response]:
        if not self._budget_ok():
            return None
        self._probe_count += 1
        try:
            kwargs: Dict = {"method": method, "url": url, "headers": headers or self._headers(),
                            "timeout": timeout, "follow_redirects": False}
            if json_body is not None:
                kwargs["json"] = json_body
                kwargs["headers"] = {**kwargs["headers"], "Content-Type": "application/json"}
            resp = await client.request(**kwargs)
            if resp.status_code == 429:
                self._rate_limited = True
                self._log("Rate limited (429) — reducing concurrency")
            return resp
        except (httpx.TimeoutException, httpx.ConnectError, httpx.HTTPError):
            return None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Phase 1: Spec Auto-Discovery
    # ------------------------------------------------------------------
    async def _phase1_spec_discovery(self, client: httpx.AsyncClient) -> Optional[Dict]:
        self._log("[Phase 1] Probing for OpenAPI / Swagger spec files...")

        async def check_spec(path: str) -> Optional[Dict]:
            url = f"{self.base_url}{path}"
            resp = await self._probe(client, "GET", url)
            if resp is None or resp.status_code != 200:
                return None
            text = resp.text.strip()
            if not text:
                return None
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                try:
                    data = yaml.safe_load(text)
                except Exception:
                    return None
            if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                return data
            return None

        tasks = [check_spec(p) for p in SPEC_PROBE_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, dict):
                self._log(f"[Phase 1] Found spec at {SPEC_PROBE_PATHS[i]}")
                try:
                    from app.services.direct_parser import DirectOASParser
                    raw = json.dumps(result).encode()
                    parser = DirectOASParser(raw, f"discovered-{SPEC_PROBE_PATHS[i]}")
                    blueprint = parser.generate_blueprint()
                    ep_count = len(blueprint.get("endpoints", []))
                    self._log(f"[Phase 1] Parsed spec: {ep_count} endpoints extracted")
                    return blueprint
                except Exception as e:
                    self._log(f"[Phase 1] Spec parse failed: {e}")

        # Check HTML pages for embedded spec URLs (Swagger UI pattern)
        for probe_path in ["/docs", "/swagger-ui.html", "/swagger-ui/", "/"]:
            resp = await self._probe(client, "GET", f"{self.base_url}{probe_path}")
            if resp and resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
                urls = re.findall(r'url\s*[:=]\s*["\']([^"\']+(?:openapi|swagger|api-docs)[^"\']*)["\']', resp.text, re.IGNORECASE)
                for spec_url in urls:
                    if spec_url.startswith("/"):
                        spec_url = f"{self.base_url}{spec_url}"
                    elif not spec_url.startswith("http"):
                        spec_url = f"{self.base_url}/{spec_url}"
                    spec_resp = await self._probe(client, "GET", spec_url)
                    if spec_resp and spec_resp.status_code == 200:
                        try:
                            data = json.loads(spec_resp.text)
                            if "openapi" in data or "swagger" in data:
                                from app.services.direct_parser import DirectOASParser
                                parser = DirectOASParser(spec_resp.text.encode(), "html-discovered")
                                blueprint = parser.generate_blueprint()
                                self._log(f"[Phase 1] Found spec via HTML at {spec_url}: {len(blueprint.get('endpoints', []))} endpoints")
                                return blueprint
                        except Exception:
                            pass

        self._log("[Phase 1] No spec file found — proceeding to active discovery")
        return None

    # ------------------------------------------------------------------
    # Phase 2: Technology Fingerprinting
    # ------------------------------------------------------------------
    async def _phase2_fingerprint(self, client: httpx.AsyncClient) -> TechProfile:
        self._log("[Phase 2] Fingerprinting target technology stack...")
        profile = TechProfile()

        root_resp = await self._probe(client, "GET", self.base_url)
        if root_resp:
            profile.server_header = root_resp.headers.get("server", "")
            powered = root_resp.headers.get("x-powered-by", "")
            if powered:
                profile.detected_hints.append(f"X-Powered-By: {powered}")

        err_resp = await self._probe(client, "GET", f"{self.base_url}/_apex_nonexistent_404_probe")
        if err_resp:
            ct = err_resp.headers.get("content-type", "")
            body = err_resp.text[:500]
            if "application/json" in ct:
                profile.error_format = "json"
            elif "text/html" in ct:
                profile.error_format = "html"
            else:
                profile.error_format = ct

            body_lower = body.lower()
            if "django" in body_lower or "csrfmiddlewaretoken" in body_lower:
                profile.framework = "django"
            elif "whitelabel error" in body_lower or "spring" in body_lower:
                profile.framework = "spring"
            elif "express" in body_lower or "cannot get" in body_lower:
                profile.framework = "express"
            elif "fastapi" in body_lower or "not found" in body_lower and profile.error_format == "json":
                profile.framework = "fastapi"
            elif "laravel" in body_lower or "symfony" in body_lower:
                profile.framework = "laravel"
            elif "asp.net" in body_lower or "iis" in (profile.server_header or "").lower():
                profile.framework = "aspnet"

        options_resp = await self._probe(client, "OPTIONS", self.base_url)
        if options_resp:
            allow = options_resp.headers.get("allow", "")
            if allow:
                profile.detected_hints.append(f"Allow: {allow}")

        for prefix in ["/api/v1", "/api/v2", "/api/v3", "/api", "/v1", "/v2"]:
            resp = await self._probe(client, "GET", f"{self.base_url}{prefix}")
            if resp and resp.status_code not in (404, 0):
                profile.version_prefix = prefix
                profile.detected_hints.append(f"Version prefix: {prefix}")
                break

        if root_resp and root_resp.status_code == 401:
            www_auth = root_resp.headers.get("www-authenticate", "")
            if www_auth:
                profile.auth_scheme = www_auth
                profile.detected_hints.append(f"WWW-Authenticate: {www_auth}")

        graphql_resp = await self._probe(client, "POST", f"{self.base_url}/graphql",
                                         json_body={"query": "{ __typename }"})
        if graphql_resp and graphql_resp.status_code == 200:
            try:
                data = graphql_resp.json()
                if "data" in data:
                    profile.api_style = "graphql"
                    profile.detected_hints.append("GraphQL detected")
            except Exception:
                pass

        fw_label = profile.framework or "unknown"
        self._log(f"[Phase 2] Framework: {fw_label} | Style: {profile.api_style} | Prefix: {profile.version_prefix or 'none'}")
        return profile

    # ------------------------------------------------------------------
    # Phase 3: Path Brute-Force
    # ------------------------------------------------------------------
    async def _phase3_path_brute(self, client: httpx.AsyncClient, profile: TechProfile) -> List[DiscoveredEndpoint]:
        self._log("[Phase 3] Probing common API paths...")

        paths_to_probe: List[str] = list(CORE_API_PATHS) + list(SHADOW_PATHS)

        if profile.framework and profile.framework in FRAMEWORK_PATHS:
            paths_to_probe.extend(FRAMEWORK_PATHS[profile.framework])
            self._log(f"[Phase 3] Added {len(FRAMEWORK_PATHS[profile.framework])} framework-specific paths for {profile.framework}")

        if profile.version_prefix:
            vp = profile.version_prefix.rstrip("/")
            generated = []
            for p in CORE_API_PATHS:
                if p.startswith("/api/") and not p.startswith(f"{vp}/"):
                    suffix = p[4:]
                    generated.append(f"{vp}{suffix}")
            paths_to_probe.extend(generated)

        unique_paths = []
        seen_set: Set[str] = set()
        for p in paths_to_probe:
            if p not in seen_set:
                seen_set.add(p)
                unique_paths.append(p)

        live: List[DiscoveredEndpoint] = []
        sem = asyncio.Semaphore(RATE_LIMIT_CONCURRENCY if self._rate_limited else MAX_CONCURRENCY)

        async def probe_path(path: str):
            if not self._budget_ok():
                return
            if not self._mark_seen("GET", path):
                return
            async with sem:
                url = f"{self.base_url}{path}"
                resp = await self._probe(client, "GET", url)
                if resp is None:
                    return
                ct = resp.headers.get("content-type", "")
                if resp.status_code in range(200, 300):
                    ep = DiscoveredEndpoint(path=path, method="GET", status_code=resp.status_code,
                                           content_type=ct, body_sample=resp.text[:2000])
                    live.append(ep)
                elif resp.status_code in (401, 403):
                    ep = DiscoveredEndpoint(path=path, method="GET", status_code=resp.status_code,
                                           content_type=ct, source="discovery-auth-required")
                    live.append(ep)
                elif resp.status_code == 405:
                    ep = DiscoveredEndpoint(path=path, method="GET", status_code=405,
                                           content_type=ct, source="discovery-method-not-allowed")
                    live.append(ep)

        batch_size = 50
        for i in range(0, len(unique_paths), batch_size):
            if not self._budget_ok():
                break
            batch = unique_paths[i:i + batch_size]
            await asyncio.gather(*[probe_path(p) for p in batch])

        self._log(f"[Phase 3] Found {len(live)} live endpoints from path probing")

        # Method discovery for live endpoints
        method_endpoints: List[DiscoveredEndpoint] = []
        for ep in live[:60]:
            if not self._budget_ok():
                break
            for method in ["POST", "PUT", "DELETE", "PATCH"]:
                if not self._mark_seen(method, ep.path):
                    continue
                async with sem:
                    resp = await self._probe(client, method, f"{self.base_url}{ep.path}")
                    if resp and resp.status_code not in (404, 405, 0):
                        mep = DiscoveredEndpoint(path=ep.path, method=method, status_code=resp.status_code,
                                                 content_type=resp.headers.get("content-type", ""),
                                                 body_sample=resp.text[:2000] if resp.status_code < 400 else "")
                        method_endpoints.append(mep)

        live.extend(method_endpoints)
        self._log(f"[Phase 3] Total after method discovery: {len(live)} endpoint/method combinations")
        return live

    # ------------------------------------------------------------------
    # Phase 4: Response Mining + Recursive Crawl
    # ------------------------------------------------------------------
    async def _phase4_response_mining(self, client: httpx.AsyncClient,
                                      endpoints: List[DiscoveredEndpoint]) -> List[DiscoveredEndpoint]:
        self._log("[Phase 4] Mining responses for hidden endpoints and IDs...")

        new_paths: Set[str] = set()
        id_parameterized: List[DiscoveredEndpoint] = []

        for ep in endpoints:
            if ep.status_code not in range(200, 300) or not ep.body_sample:
                continue
            try:
                data = json.loads(ep.body_sample)
            except (json.JSONDecodeError, ValueError):
                continue

            self._mine_json(data, ep.path, new_paths, id_parameterized)

        # GraphQL introspection
        graphql_endpoints = [ep for ep in endpoints if "graphql" in ep.path.lower() or "gql" in ep.path.lower()]
        for gep in graphql_endpoints:
            if not self._budget_ok():
                break
            resp = await self._probe(client, "POST", f"{self.base_url}{gep.path}",
                                     json_body={"query": GRAPHQL_INTROSPECTION_QUERY},
                                     timeout=MINING_REQUEST_TIMEOUT)
            if resp and resp.status_code == 200:
                try:
                    schema_data = resp.json()
                    gql_eps = self._parse_graphql_schema(schema_data, gep.path)
                    id_parameterized.extend(gql_eps)
                    self._log(f"[Phase 4] GraphQL introspection: {len(gql_eps)} operations discovered")
                except Exception:
                    pass

        # Recursive probe of newly discovered paths (depth 1)
        confirmed_new: List[DiscoveredEndpoint] = []
        sem = asyncio.Semaphore(RATE_LIMIT_CONCURRENCY if self._rate_limited else MAX_CONCURRENCY)

        async def confirm_path(path: str):
            if not self._budget_ok() or not self._mark_seen("GET", path):
                return
            async with sem:
                resp = await self._probe(client, "GET", f"{self.base_url}{path}")
                if resp and resp.status_code in range(200, 400):
                    ep = DiscoveredEndpoint(path=path, method="GET", status_code=resp.status_code,
                                           content_type=resp.headers.get("content-type", ""),
                                           body_sample=resp.text[:2000] if resp.status_code < 300 else "",
                                           source="discovery-mined")
                    confirmed_new.append(ep)
                    # Also mine this response for further paths (depth 2)
                    if resp.status_code < 300 and resp.text:
                        try:
                            deeper_data = json.loads(resp.text[:2000])
                            self._mine_json(deeper_data, path, new_paths, id_parameterized)
                        except Exception:
                            pass

        await asyncio.gather(*[confirm_path(p) for p in list(new_paths)[:100]])

        all_eps = endpoints + id_parameterized + confirmed_new
        self._log(f"[Phase 4] Mined {len(confirmed_new)} new endpoints, {len(id_parameterized)} parameterized paths")
        return all_eps

    def _mine_json(self, data, parent_path: str, new_paths: Set[str], parameterized: List[DiscoveredEndpoint]):
        """Extract paths, IDs, and links from JSON response data."""
        if isinstance(data, list) and len(data) > 0:
            for item in data[:5]:
                if isinstance(item, dict):
                    id_val = item.get("id") or item.get("_id") or item.get("uuid")
                    if id_val is not None:
                        concrete_path = f"{parent_path}/{id_val}"
                        new_paths.add(concrete_path)
                        template_path = f"{parent_path}/{{id}}"
                        parameterized.append(DiscoveredEndpoint(
                            path=template_path, method="GET",
                            params=[{"name": "id", "in": "path", "required": True}],
                            source="discovery-id-inferred"
                        ))
                    self._extract_links(item, new_paths)

        elif isinstance(data, dict):
            if "results" in data and isinstance(data["results"], list):
                self._mine_json(data["results"], parent_path, new_paths, parameterized)
            if "data" in data and isinstance(data["data"], list):
                self._mine_json(data["data"], parent_path, new_paths, parameterized)
            if "items" in data and isinstance(data["items"], list):
                self._mine_json(data["items"], parent_path, new_paths, parameterized)
            self._extract_links(data, new_paths)

    def _extract_links(self, obj: Dict, new_paths: Set[str]):
        """Extract URL paths from HATEOAS _links, href, next, prev fields."""
        if not isinstance(obj, dict):
            return
        for key in ("_links", "links"):
            links = obj.get(key)
            if isinstance(links, dict):
                for rel, link_obj in links.items():
                    href = link_obj.get("href") if isinstance(link_obj, dict) else None
                    if href and isinstance(href, str):
                        parsed = urlparse(href)
                        if parsed.path and parsed.path.startswith("/"):
                            new_paths.add(parsed.path)
            elif isinstance(links, list):
                for link_obj in links:
                    if isinstance(link_obj, dict):
                        href = link_obj.get("href", "")
                        if href.startswith("/"):
                            new_paths.add(href)

        for key in ("next", "prev", "next_page", "previous", "first", "last"):
            val = obj.get(key)
            if isinstance(val, str):
                if val.startswith("/"):
                    new_paths.add(val)
                elif val.startswith("http"):
                    parsed = urlparse(val)
                    if parsed.path:
                        new_paths.add(parsed.path)

        for key, val in obj.items():
            if isinstance(val, str) and val.startswith("/api/"):
                new_paths.add(val)

    def _parse_graphql_schema(self, schema_data: Dict, gql_path: str) -> List[DiscoveredEndpoint]:
        """Convert GraphQL introspection into virtual endpoints."""
        endpoints = []
        try:
            types = schema_data.get("data", {}).get("__schema", {}).get("types", [])
            query_type = schema_data.get("data", {}).get("__schema", {}).get("queryType", {}).get("name", "Query")
            mutation_type = schema_data.get("data", {}).get("__schema", {}).get("mutationType", {})
            mutation_name = mutation_type.get("name", "Mutation") if mutation_type else "Mutation"

            for t in types:
                name = t.get("name", "")
                if name.startswith("__") or not t.get("fields"):
                    continue
                is_query = name == query_type
                is_mutation = name == mutation_name
                if not is_query and not is_mutation:
                    continue
                for fld in t["fields"]:
                    method = "GET" if is_query else "POST"
                    virtual_path = f"{gql_path}/{fld['name']}"
                    params = [{"name": a["name"], "in": "query", "required": False} for a in fld.get("args", [])]
                    endpoints.append(DiscoveredEndpoint(
                        path=virtual_path, method=method, params=params, source="discovery-graphql"
                    ))
        except Exception:
            pass
        return endpoints

    # ------------------------------------------------------------------
    # Phase 5: Parameter Inference
    # ------------------------------------------------------------------
    async def _phase5_param_inference(self, client: httpx.AsyncClient,
                                      endpoints: List[DiscoveredEndpoint]) -> List[DiscoveredEndpoint]:
        self._log("[Phase 5] Inferring parameters for discovered endpoints...")

        sem = asyncio.Semaphore(RATE_LIMIT_CONCURRENCY if self._rate_limited else MAX_CONCURRENCY)

        # Deduplicate endpoints by (path, method)
        unique_map: Dict[Tuple[str, str], DiscoveredEndpoint] = {}
        for ep in endpoints:
            key = (ep.path, ep.method.upper())
            if key not in unique_map:
                unique_map[key] = ep
            else:
                existing = unique_map[key]
                if not existing.params and ep.params:
                    existing.params = ep.params
                if not existing.schema and ep.schema:
                    existing.schema = ep.schema

        deduped = list(unique_map.values())

        # 5a. Path parameter detection (numeric/UUID segments)
        for ep in deduped:
            segments = ep.path.strip("/").split("/")
            new_segments = []
            for seg in segments:
                if re.match(r"^\d+$", seg):
                    if not any(p["name"] == "id" and p["in"] == "path" for p in ep.params):
                        ep.params.append({"name": "id", "in": "path", "required": True})
                    new_segments.append("{id}")
                elif re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", seg, re.IGNORECASE):
                    if not any(p["name"] == "id" and p["in"] == "path" for p in ep.params):
                        ep.params.append({"name": "id", "in": "path", "required": True})
                    new_segments.append("{id}")
                else:
                    new_segments.append(seg)
            ep.path = "/" + "/".join(new_segments)

        # 5b. Query parameter discovery for GET endpoints
        get_endpoints = [ep for ep in deduped if ep.method.upper() == "GET"
                         and ep.status_code in range(200, 300) and not ep.params]

        async def probe_query_params(ep: DiscoveredEndpoint):
            if not self._budget_ok():
                return
            url = f"{self.base_url}{ep.path}"
            async with sem:
                baseline = await self._probe(client, "GET", url, timeout=MINING_REQUEST_TIMEOUT)
                if not baseline or baseline.status_code >= 400:
                    return
                baseline_len = len(baseline.text)

                for param in COMMON_PARAM_NAMES[:20]:
                    if not self._budget_ok():
                        return
                    resp = await self._probe(client, "GET", f"{url}?{param}=test")
                    if resp is None:
                        continue
                    if resp.status_code != baseline.status_code:
                        ep.params.append({"name": param, "in": "query", "required": False})
                    elif abs(len(resp.text) - baseline_len) > max(50, baseline_len * 0.1):
                        ep.params.append({"name": param, "in": "query", "required": False})

        await asyncio.gather(*[probe_query_params(ep) for ep in get_endpoints[:15]])

        # 5c. Body schema inference for POST/PUT/PATCH endpoints
        mutation_endpoints = [ep for ep in deduped if ep.method.upper() in ("POST", "PUT", "PATCH")
                              and not ep.schema and ep.status_code != 405]

        async def probe_body_schema(ep: DiscoveredEndpoint):
            if not self._budget_ok():
                return
            url = f"{self.base_url}{ep.path}"
            async with sem:
                headers = {**self._headers(), "Content-Type": "application/json"}
                empty_resp = await self._probe(client, ep.method, url, json_body={}, timeout=MINING_REQUEST_TIMEOUT)
                if not empty_resp:
                    return

                error_text = empty_resp.text.lower()
                inferred_props = {}

                field_patterns = [
                    re.compile(r"['\"](\w+)['\"].*(?:is required|required field|missing|must be provided)", re.IGNORECASE),
                    re.compile(r"(?:field|parameter|property)\s+['\"]?(\w+)['\"]?", re.IGNORECASE),
                    re.compile(r"(\w+)\s+(?:must be|should be|is not)\s+(?:a |an )?(string|integer|number|boolean|array|object)", re.IGNORECASE),
                ]
                for pattern in field_patterns:
                    for match in pattern.finditer(empty_resp.text):
                        field_name = match.group(1)
                        if len(field_name) > 1 and field_name not in ("the", "this", "that", "field", "value"):
                            field_type = "string"
                            if match.lastindex and match.lastindex >= 2:
                                ft = match.group(2).lower()
                                if ft in ("integer", "number"):
                                    field_type = ft
                                elif ft == "boolean":
                                    field_type = "boolean"
                            inferred_props[field_name] = {"type": field_type}

                if inferred_props:
                    ep.schema = {"type": "object", "properties": inferred_props}
                    return

                probe_resp = await self._probe(client, ep.method, url,
                                               json_body=COMMON_BODY_FIELDS, timeout=MINING_REQUEST_TIMEOUT)
                if probe_resp and probe_resp.status_code in range(200, 300):
                    ep.schema = {
                        "type": "object",
                        "properties": {k: {"type": "string"} for k in COMMON_BODY_FIELDS}
                    }
                    ep.example = COMMON_BODY_FIELDS

        await asyncio.gather(*[probe_body_schema(ep) for ep in mutation_endpoints[:15]])

        param_count = sum(len(ep.params) for ep in deduped)
        schema_count = sum(1 for ep in deduped if ep.schema)
        self._log(f"[Phase 5] Inferred {param_count} parameters, {schema_count} body schemas across {len(deduped)} endpoints")

        return deduped

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    async def run(self, log_callback: Optional[Callable[[str], None]] = None) -> DiscoveryResult:
        self._log_cb = log_callback
        self._start_time = time.monotonic()
        self._log(f"Starting API discovery on {self.base_url}")

        limits = httpx.Limits(max_connections=MAX_CONCURRENCY, max_keepalive_connections=10)
        async with httpx.AsyncClient(limits=limits, verify=False) as client:

            # Phase 1
            blueprint = await self._phase1_spec_discovery(client)
            if blueprint:
                elapsed = time.monotonic() - self._start_time
                self._log(f"Discovery complete (spec found) — {elapsed:.1f}s, {self._probe_count} probes")
                return DiscoveryResult(
                    spec_blueprint=blueprint,
                    stats={"probes": self._probe_count, "elapsed_sec": elapsed, "method": "spec-discovery"}
                )

            # Phase 2
            profile = await self._phase2_fingerprint(client)

            # Phase 3
            live_endpoints = await self._phase3_path_brute(client, profile)

            # Phase 4
            enriched = await self._phase4_response_mining(client, live_endpoints)

            # Phase 5
            final = await self._phase5_param_inference(client, enriched)

            result_endpoints = [ep.to_blueprint_entry() for ep in final]
            elapsed = time.monotonic() - self._start_time

            self._log(f"Discovery complete — {len(result_endpoints)} endpoints, {elapsed:.1f}s, {self._probe_count} probes")

            return DiscoveryResult(
                endpoints=result_endpoints,
                tech_profile=profile,
                stats={"probes": self._probe_count, "elapsed_sec": elapsed,
                       "endpoints_found": len(result_endpoints), "method": "active-discovery"}
            )
