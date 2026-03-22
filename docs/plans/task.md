| Task | Status | Notes |
|------|--------|-------|
| Task 1: Backend - Stop Scan Implementation | Done | Added CANCELLED enum, stop route, and orchestrator hook |
| Task 2: Frontend - Delete Scan History | Done | Added Trash icon to sidebar, routed to DELETE /api/specs/{id} |
| Task 3: Frontend - Active Scan Context | Done | Persisted `dynamicSessionId` via `localStorage`, added Stop button |
| Task 4: Frontend - Unified Dashboard View | Done | `ScanResults` automatically fetches dynamic session by `spec_id` and merges counts into Overview |
| Task 5: Backend - Add concurrency_limit | Done | Added `concurrency_limit` to `DynamicTestSession` model, schemas, and API validation |
| Task 6: Backend - Asyncio Semaphore Logic | Done | Wrap test iteration loop in `asyncio.gather` with bounded concurrency in `SessionOrchestrator` |
| Task 7: Frontend - Concurrency Config UI | Done | Add a slider to `DynamicConsole` for users to set scan speed from 1 to 50 concurrent requests |
