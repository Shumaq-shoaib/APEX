# Dynamic Scanner Concurrency Implementation Plan

> **For Antigravity:** REQUIRED WORKFLOW: Use `.agent/workflows/execute-plan.md` to execute this plan in single-flow mode.

**Goal:** Speed up the dynamic scanner by implementing a user-configurable concurrency limit for parallel test case execution.

**Architecture:** 
- Add `concurrency_limit` to the backend models and API request schema.
- Add a "Scan Speed (Concurrency Limit)" slider/input to the Frontend `DynamicConsole`.
- Implement `asyncio.Semaphore` in the backend `SessionOrchestrator` to execute `AttackEngine.run_test_case` concurrently up to the selected limit.

**Tech Stack:** React (Frontend), FastAPI, SQLAlchemy, `asyncio` (Backend).

---

### Task 1: Backend Database & Schema Update

**Files:**
- Modify: `d:\APEX\APEX\apex-dynamic-service\app\models\dynamic.py`
- Modify: `d:\APEX\APEX\apex-dynamic-service\app\api\routes\sessions.py`

**Step 1: Add concurrency_limit to Database Model**
Add `concurrency_limit = Column(Integer, default=5)` to `DynamicTestSession`.

**Step 2: Add concurrency_limit to Schema**
Add `concurrency_limit: int = 5` to `DirectScanRequest` and `QuickScanRequest`.

**Step 3: Support in `create_session` Orchestrator Logic**
Update `create_session` signature to accept `concurrency_limit` and pass it to the db model creation.

**Step 4: Commit**
`git add app/models/dynamic.py app/api/routes/sessions.py app/services/orchestrator.py`
`git commit -m "feat: add concurrency_limit to models and routes"`

---

### Task 2: Backend Async Task Execution (Orchestrator)

**Files:**
- Modify: `d:\APEX\APEX\apex-dynamic-service\app\services\orchestrator.py`

**Step 1: Implement Semaphore**
In `run_scan_background`, immediately before `for case in cases:`, introduce an `asyncio.Semaphore(session.concurrency_limit)`.

**Step 2: Wrap Test Case Call**
Create an inner `async def _run_bounded_test(case):` that waits on the semaphore, checks cancellation, and runs `await engine.run_test_case(...)`.

**Step 3: Run Concurrent Loop**
Replace the sequential `for` loop with `await asyncio.gather(*[_run_bounded_test(case) for case in cases])`. Ensure cancellation sets remaining queued statuses correctly without crashing task gathering.

**Step 4: Commit**
`git add app/services/orchestrator.py`
`git commit -m "feat: implement asyncio semaphore for concurrent test execution"`

---

### Task 3: Frontend UI for Concurrency Configuration

**Files:**
- Modify: `d:\APEX\APEX\frontend\dashboard\src\components\dashboard\DynamicConsole.tsx`

**Step 1: Add State**
Add `const [concurrencyLimit, setConcurrencyLimit] = useState<number>(5);`

**Step 2: Add UI Element**
In the Advanced Options area, add a slider or number input labeled "Scan Speed (Concurrent Tasks)" allowing 1-50.

**Step 3: Update API Call**
Attach `concurrency_limit` to the `FormData` or JSON payload in `handleQuickScan` and `handleDirectScan`.

**Step 4: Commit**
`git add frontend/dashboard/src/components/dashboard/DynamicConsole.tsx`
`git commit -m "feat: add user-configurable scan speed to UI"`
