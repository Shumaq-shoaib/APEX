# Dashboard Unification & Scan Controls Implementation Plan

> **For Antigravity:** REQUIRED WORKFLOW: Use `.agent/workflows/execute-plan.md` to execute this plan in single-flow mode.

**Goal:** Unite SAST and DAST results in the frontend, persist active scan state across tabs using React Context, and add Stop/Delete controls for scans.

**Architecture:** 
1. **Stop Scan:** New backend route `POST /api/sessions/{id}/stop` sets status to CANCELLED. Orchestrator loop checks status and breaks.
2. **Delete History:** Call existing `DELETE /api/specs/{id}` from `ScanHistory.tsx` sidebar.
3. **Persist State:** `ActiveScanContext` holds the dynamic scan state. `DynamicConsole.tsx` consumes it (unless viewing a historical scan).
4. **Unified View:** `ScanResults.tsx` fetches the dynamic session (if available) and merges dynamic findings into the "Overview" charts and "Static Findings" tab on the frontend.

**Tech Stack:** FastAPI, React, React Context, Tailwind.

---

### Task 1: Backend - Stop Scan Implementation

**Files:**
- Modify: `d:\APEX\APEX\apex-dynamic-service\app\api\routes\sessions.py`
- Modify: `d:\APEX\APEX\apex-dynamic-service\app\services\orchestrator.py`

**Step 1: Write the API Route**
Add `POST /{session_id}/stop` in `sessions.py`:
```python
@router.post("/{session_id}/stop")
def stop_session(session_id: str, db: Session = Depends(deps.get_db)):
    session = db.query(DynamicTestSession).filter(DynamicTestSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.status in [SessionStatus.COMPLETED, SessionStatus.FAILED]:
        return {"status": "already_finished"}
    
    session.status = SessionStatus.CANCELLED
    db.commit()
    return {"status": "cancelled"}
```

**Step 2: Add Orchestrator Cancellation Hook**
In `orchestrator.py` inside `run_scan_background`, right before `engine = AttackEngine(...)` or inside the `for case in cases:` loop (around line 334):
```python
            for case in cases:
                # Refresh session to check for cancellation
                self.db.refresh(session)
                if session.status == SessionStatus.CANCELLED:
                    logger.info(f"Session {session.id} cancelled by user.")
                    session.error_message = "Scan stopped by user."
                    break

                try:
                    await engine.run_test_case(case, session.target_base_url, session.auth_token)
```
Wait, if it cancels, we also want to mark remaining QUEUED cases as SKIPPED.
```python
            for case in cases:
                self.db.refresh(session)
                if session.status == SessionStatus.CANCELLED:
                    logger.info(f"Session {session.id} cancelled.")
                    for remaining in cases:
                        if remaining.status == CaseStatus.QUEUED:
                            remaining.status = CaseStatus.SKIPPED
                            remaining.logs = "Scan cancelled."
                    self.db.commit()
                    break
```

**Step 3: Commit**
```bash
git add apex-dynamic-service/app/api/routes/sessions.py apex-dynamic-service/app/services/orchestrator.py
git commit -m "feat: add backend support to stop dynamic scans"
```

---

### Task 2: Frontend - Delete Scan History

**Files:**
- Modify: `d:\APEX\APEX\frontend\dashboard\src\components\dashboard\ScanHistory.tsx`
- Modify: `d:\APEX\APEX\frontend\dashboard\src\pages\History.tsx`

**Step 1: Add Delete UI**
In `ScanHistory.tsx`, modify the `specs.map` to include a Trash icon button inside the item.
```tsx
import { Trash2 } from "lucide-react";
// add onDelete?: (id: string) => void to props
```
Add click handler inside the map (using `e.stopPropagation()`):
```tsx
<Button variant="ghost" size="icon" className="h-6 w-6 shrink-0 opacity-50 hover:opacity-100 hover:text-destructive"
    onClick={(e) => { e.stopPropagation(); if(onDelete) onDelete(spec.id); }}>
    <Trash2 className="h-3 w-3" />
</Button>
```

**Step 2: Add Delete Logic**
In `History.tsx`:
```tsx
const handleDelete = async (id: string) => {
    if (!confirm("Delete this scan?")) return;
    try {
        await fetch(`${API_BASE_URL}/api/specs/${id}`, { method: "DELETE" });
        if (selectedScanId === id) setSelectedScanId(null);
        fetchHistory(); // refresh
    } catch (e) { console.error(e); }
};
// pass onDelete={handleDelete} to ScanHistory
```

**Step 3: Commit**
```bash
git add frontend/dashboard/src/components/dashboard/ScanHistory.tsx frontend/dashboard/src/pages/History.tsx
git commit -m "feat: add delete scan history functionality"
```

---

### Task 3: Frontend - Active Scan Context

**Files:**
- Create: `d:\APEX\APEX\frontend\dashboard\src\contexts\ActiveScanContext.tsx`
- Modify: `d:\APEX\APEX\frontend\dashboard\src\App.tsx`
- Modify: `d:\APEX\APEX\frontend\dashboard\src\components\dashboard\DynamicConsole.tsx`

**Step 1: Create Context**
Create `ActiveScanContext.tsx`. Extract `dynamicSessionId`, `dynamicStatus`, `testCases`, `dynamicFindings`, `polling`, `setPolling` into a provider. It polls `/api/sessions/{id}` if `polling` is true.

**Step 2: Wrap App**
In `App.tsx` (or `main.tsx`), wrap routes in `<ActiveScanProvider>`.

**Step 3: Consume in Console**
In `DynamicConsole.tsx`:
Replace local polling logic with context hooks.
```tsx
const { activeSessionId, testCases, dynamicFindings, status, startPolling, stopScan, clearScan } = useActiveScan();
```
Add "Stop Scan" button UI next to status:
```tsx
{status === "RUNNING" && (
    <Button variant="destructive" size="sm" onClick={stopScan} className="h-6 text-xs">
        <Square className="mr-1 h-3 w-3" /> Stop Scan
    </Button>
)}
```
*Important distinction:* If `DynamicConsole` is passed an `initialSessionId` (e.g., viewing History), it should NOT use the global context for its data. It should do a one-off fetch (or Local Context). To simplify the plan, we will just use LocalStorage in `DynamicConsole.tsx` instead of full Context. It's much simpler and less invasive. Let's rewrite this task to use LocalStorage + standalone "Stop Scan".

<ins>Alternative Task 3 (Simpler - Recommended):</ins>
Modify `DynamicConsole.tsx`:
```tsx
// Initial state from local storage or props
const [dynamicSessionId, setDynamicSessionId] = useState<string | null>(() => {
    if (initialSessionId) return initialSessionId;
    return localStorage.getItem('apex_active_session') || null;
});

// Update localStorage when session changes, ONLY if it's the active scan
useEffect(() => {
    if (initialSessionId) return; // Don't persist historical views
    if (dynamicSessionId) localStorage.setItem('apex_active_session', dynamicSessionId);
    else localStorage.removeItem('apex_active_session');
}, [dynamicSessionId, initialSessionId]);
```
Then add Stop Scan API call:
```tsx
const handleStopScan = async () => {
    if (!dynamicSessionId) return;
    try {
        await fetch(`${API_BASE_URL}/api/sessions/${dynamicSessionId}/stop`, { method: "POST" });
        setDynamicStatus("CANCELLED" as SessionStatus); // Add CANCELLED to types if needed
        setPolling(false);
    } catch(e) {}
};
```
This perfectly solves the tab-switching unmount problem.

**Step 4: Commit**
```bash
git add frontend/dashboard/src/components/dashboard/DynamicConsole.tsx
git commit -m "feat: persist dynamic scan state across tabs and add stop button"
```

---

### Task 4: Frontend - Unified Dashboard View

**Files:**
- Modify: `d:\APEX\APEX\frontend\dashboard\src\components\dashboard\ScanResults.tsx`
- Modify: `d:\APEX\APEX\frontend\dashboard\src\components\dashboard\ScanOverview.tsx`

**Step 1: Fetch Dynamic Data**
In `ScanResults.tsx`:
```tsx
const [mergedData, setMergedData] = useState<AnalysisData>(analysisData);

useEffect(() => {
    if (analysisData.dynamic_session_id) {
        // Fetch session
        fetch(`${API_BASE_URL}/api/sessions/${analysisData.dynamic_session_id}`)
            .then(res => res.json())
            .then(sessionData => {
                // Merge dynamic exploits into summary
                const updated = { ...analysisData };
                const newSummary = { ...updated.summary };
                
                // Add logic to count sessionData.findings.severity and add to newSummary
                sessionData.findings.forEach(f => {
                     const sev = f.severity === "Informational" ? "Low" : f.severity;
                     newSummary[sev] = (newSummary[sev] || 0) + 1;
                     newSummary.total += 1;
                });
                updated.summary = newSummary;
                
                // Merge findings into endpoints array (pseudo-code)
                // mapped over updated.endpoints to inject dynamic exploits...
                
                setMergedData(updated);
            });
    } else {
        setMergedData(analysisData);
    }
}, [analysisData]);
```

**Step 2: Update View**
Pass `mergedData` to `<ScanOverview>` and `<StaticFindings>`. Rename `<StaticFindings>` TabTrigger to "All Vulnerabilities".

**Step 3: Commit**
```bash
git add frontend/dashboard/src/components/dashboard/ScanResults.tsx
git commit -m "feat: unify static and dynamic findings in dashboard"
```
