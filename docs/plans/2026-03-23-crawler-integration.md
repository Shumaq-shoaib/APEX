# APEX Crawler Integration Plan

> **For Antigravity:** REQUIRED WORKFLOW: Use `.agent/workflows/execute-plan.md` to execute this plan in single-flow mode.

**Goal:** Integrate the standalone `apex-crawler` into the APEX dynamic analysis backend so that (1) when a user uploads a spec file, they can opt-in to active crawling that **merges** crawler-discovered endpoints with the spec's endpoints, and (2) when no file is provided, the crawler runs automatically as the primary endpoint discovery mechanism.

**Architecture:** We add the `apex-crawler` source files directly into the dynamic service as a new `app/services/crawler/` package. The orchestrator gains a new `_run_crawler` helper that invokes the `HybridEngine`, merges the resulting blueprint into the existing endpoint list, and logs progress. The `/direct` API route gains an optional `enable_crawl` form field, while `/quick` always enables crawling. The frontend adds a checkbox toggle when a spec file is uploaded.

**Tech Stack:** Python, FastAPI, Playwright, httpx, BeautifulSoup, React/TypeScript (frontend).

---

### Task 1: Copy Crawler Modules into APEX Backend

**Files:**
- Create: `d:\APEX\APEX\apex-dynamic-service\app\services\crawler\__init__.py`
- Create: `d:\APEX\APEX\apex-dynamic-service\app\services\crawler\static_crawler.py`
- Create: `d:\APEX\APEX\apex-dynamic-service\app\services\crawler\dynamic_crawler.py`
- Create: `d:\APEX\APEX\apex-dynamic-service\app\services\crawler\hybrid_engine.py`
- Create: `d:\APEX\APEX\apex-dynamic-service\app\services\crawler\url_filters.py`
- Create: `d:\APEX\APEX\apex-dynamic-service\app\services\crawler\endpoint_normalizer.py`
- Create: `d:\APEX\APEX\apex-dynamic-service\app\services\crawler\blueprint_formatter.py`

**Step 1: Write the failing test**

No standalone test for this task — we are copying existing, tested modules. The import structure changes from `src.X` to `app.services.crawler.X`.

**Step 2: Copy and adapt modules**

Copy the 6 source files from `d:\APEX\apex-crawler\src\` into `d:\APEX\APEX\apex-dynamic-service\app\services\crawler\`, updating all internal imports from `src.X` to relative imports (e.g., `from .static_crawler import StaticCrawler`).

```python
# d:\APEX\APEX\apex-dynamic-service\app\services\crawler\__init__.py
from .hybrid_engine import HybridEngine
from .blueprint_formatter import generate_blueprint
```

Update `hybrid_engine.py` imports:
```python
# Change from:
from src.static_crawler import StaticCrawler
from src.dynamic_crawler import DynamicCrawler
from src.url_filters import URLFilter
from src.endpoint_normalizer import normalize_url

# To:
from .static_crawler import StaticCrawler
from .dynamic_crawler import DynamicCrawler
from .url_filters import URLFilter
from .endpoint_normalizer import normalize_url
```

**Step 3: Verify import**

Run: `cd d:\APEX\APEX\apex-dynamic-service && python -c "from app.services.crawler import HybridEngine; print('OK')"`
Expected: `OK`

**Step 4: Commit**

```bash
cd d:\APEX\APEX
git add apex-dynamic-service/app/services/crawler/
git commit -m "feat: add crawler modules to APEX dynamic service"
```

---

### Task 2: Add Crawler Hook in Orchestrator

**Files:**
- Modify: `d:\APEX\APEX\apex-dynamic-service\app\services\orchestrator.py`

**Step 1: Write the failing test**

No separate test file — we test via the API integration. The orchestrator change is purely internal wiring.

**Step 2: Add `_run_crawler` method and wire it into `run_scan_background`**

Add this method to `SessionOrchestrator`:

```python
async def _run_crawler(self, target_url, existing_endpoints, log_callback=None):
    """Run the APEX Crawler and merge discovered endpoints into existing ones."""
    from app.services.crawler import HybridEngine, generate_blueprint

    if log_callback:
        log_callback("[APEX Crawler] Starting hybrid crawl...")
    
    engine = HybridEngine(target_url)
    await engine.crawl()
    
    crawler_blueprint = generate_blueprint(engine.endpoints)
    crawler_endpoints = crawler_blueprint.get("endpoints", [])
    
    if log_callback:
        log_callback(f"[APEX Crawler] Discovered {len(crawler_endpoints)} endpoints")
    
    # Merge: add crawler endpoints that aren't already in existing set
    existing_paths = {(ep.get("path"), ep.get("method")) for ep in existing_endpoints}
    new_count = 0
    for ep in crawler_endpoints:
        key = (ep.get("path"), ep.get("method"))
        if key not in existing_paths:
            existing_endpoints.append(ep)
            existing_paths.add(key)
            new_count += 1
    
    if log_callback:
        log_callback(f"[APEX Crawler] Merged {new_count} new endpoints (total: {len(existing_endpoints)})")
    
    return existing_endpoints
```

Then modify `run_scan_background` in two places:

**Place 1 (line ~126, after `if not endpoints:`):** Replace the existing `DiscoveryEngine` block. After the existing discovery block, also run the crawler:

```python
# After the existing DiscoveryEngine block (around line 169), add:
# --- APEX Crawler: always run on quick scan (no spec) ---
if session.spec.filename.startswith("Quick Scan:"):
    endpoints = await self._run_crawler(
        session.target_base_url, endpoints,
        log_callback=_discovery_log
    )
    blueprint["endpoints"] = endpoints
    spec.blueprint_json = json.dumps(blueprint)
    self.db.commit()
```

**Place 2 (new block after line 120, for `enable_crawl` on file-upload scans):** This will be wired via a new session flag (Task 3).

**Step 3: Verify**

Manual verification: Start APEX, trigger a quick scan, and confirm crawler endpoints appear in the test cases.

**Step 4: Commit**

```bash
cd d:\APEX\APEX
git add apex-dynamic-service/app/services/orchestrator.py
git commit -m "feat: integrate crawler into orchestrator scan flow"
```

---

### Task 3: Add `enable_crawl` Flag to API Routes

**Files:**
- Modify: `d:\APEX\APEX\apex-dynamic-service\app\api\routes\sessions.py`
- Modify: `d:\APEX\APEX\apex-dynamic-service\app\models\dynamic.py`
- Modify: `d:\APEX\APEX\apex-dynamic-service\app\services\orchestrator.py`

**Step 1: Add `enable_crawl` column to `DynamicTestSession` model**

```python
# In dynamic.py, add to DynamicTestSession class:
enable_crawl = Column(String(10), default="false")  # "true" or "false"
```

**Step 2: Add `enable_crawl` to `/direct` route**

```python
# In sessions.py, add to create_direct_session params:
enable_crawl: Optional[str] = Form("false"),

# Pass to create_session and store on the session object
```

**Step 3: Add `enable_crawl` to `create_session` method**

```python
# In orchestrator.py create_session, accept and store:
enable_crawl: str = "false",
# ...
session.enable_crawl = enable_crawl
```

**Step 4: Wire crawler in orchestrator for file-upload scans**

In `run_scan_background`, after extracting `endpoints` from the blueprint (line ~120), add:

```python
# --- APEX Crawler: merge if enabled ---
if session.enable_crawl == "true" and endpoints:
    def _crawl_log(msg):
        # Log to a crawler test case
        pass
    endpoints = await self._run_crawler(
        session.target_base_url, endpoints,
        log_callback=_crawl_log
    )
    blueprint["endpoints"] = endpoints
    spec.blueprint_json = json.dumps(blueprint)
    self.db.commit()
```

**Step 5: Commit**

```bash
cd d:\APEX\APEX
git add apex-dynamic-service/app/models/dynamic.py
git add apex-dynamic-service/app/api/routes/sessions.py
git add apex-dynamic-service/app/services/orchestrator.py
git commit -m "feat: add enable_crawl flag to direct scan route"
```

---

### Task 4: Add Crawl Toggle to Frontend

**Files:**
- Modify: `d:\APEX\APEX\frontend\dashboard\src\components\dashboard\DynamicConsole.tsx`

**Step 1: Add state for the toggle**

```tsx
const [enableCrawl, setEnableCrawl] = useState(false);
```

**Step 2: Add checkbox UI after the file upload section**

After the file upload `<div>` (around line 427), when `specFile` is set, show:

```tsx
{specFile && (
    <div className="flex items-center gap-2 p-3 border rounded-lg bg-muted/20">
        <input
            type="checkbox"
            id="enableCrawl"
            checked={enableCrawl}
            onChange={(e) => setEnableCrawl(e.target.checked)}
            className="h-4 w-4"
        />
        <Label htmlFor="enableCrawl" className="text-sm cursor-pointer">
            Enable Active Crawling (merge discovered endpoints with spec)
        </Label>
    </div>
)}
```

**Step 3: Send `enable_crawl` in the FormData**

In the `startDynamicScan` function, inside the `specFile` branch (line ~199-210), add:

```tsx
if (enableCrawl) formData.append("enable_crawl", "true");
```

**Step 4: Commit**

```bash
cd d:\APEX\APEX
git add frontend/dashboard/src/components/dashboard/DynamicConsole.tsx
git commit -m "feat: add crawl toggle checkbox to dynamic scan UI"
```
