# APEX Quick Fixes Checklist

**Date:** 2026-02-16  
**Priority:** Immediate Actions Required

---

## 🔴 Critical Issues (Fix Today)

### 1. Docker Build Broken
**File:** `frontend/dashboard/Dockerfile`  
**Issue:** `npm install` is commented out - container won't have dependencies  
**Fix:**
```dockerfile
# Line 8-9: Uncomment this line
RUN npm install
```

### 2. Hardcoded API URLs
**Files:** Multiple components  
**Issue:** `http://127.0.0.1:8000` hardcoded in 7+ places  
**Fix:**
```tsx
// Create: frontend/dashboard/src/lib/config.ts
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

// Update in:
// - src/pages/StaticAnalysis.tsx (line 19)
// - src/pages/History.tsx (lines 22, 41)
// - src/components/NewScanSelector.tsx (lines 36, 58)
// - src/components/dashboard/DynamicConsole.tsx (lines 39, 73, 86)

// Replace with:
import { API_BASE_URL } from '@/lib/config';
fetch(`${API_BASE_URL}/api/specs/${specId}`)
```

---

## 🟠 High Priority (Fix This Week)

### 3. Type Safety Gaps
**Files:** Multiple pages/components  
**Issue:** Using `any` type instead of proper interfaces  
**Fix:**
```tsx
// Create: frontend/dashboard/src/types/api.ts
export interface AnalysisData {
  spec_id: string;
  metadata: {
    api_title: string;
    api_version: string;
    file_analyzed: string;
    timestamp_utc: string;
    server_url?: string;
  };
  summary: {
    total: number;
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
    Informational: number;
  };
  endpoints: Array<{
    path: string;
    method: string;
    vulnerabilities: Vulnerability[];
  }>;
}

export interface Vulnerability {
  id: string;
  name: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
  description: string;
  remediation: string;
  cvss_score: number;
}

// Update in components:
const [analysisData, setAnalysisData] = useState<AnalysisData | null>(null);
```

### 4. Config File Mismatch
**Issue:** `components.json` references `tailwind.config.ts` but file is `.js`  
**Fix (Option 1 - Rename):**
```bash
cd frontend/dashboard
mv tailwind.config.js tailwind.config.ts
```

**Fix (Option 2 - Update components.json):**
```json
{
  "tailwind": {
    "config": "tailwind.config.js"
  }
}
```

### 5. Docker Compose Node Modules
**File:** `docker-compose.yml`  
**Issue:** node_modules volume commented out  
**Fix:**
```yaml
frontend:
  volumes:
    - ./frontend/dashboard:/app
    - /app/node_modules  # Uncomment this line
```

### 6. Memory Leak in Polling
**File:** `frontend/dashboard/src/components/dashboard/DynamicConsole.tsx`  
**Issue:** Polling interval may not clean up properly  
**Fix:**
```tsx
// Lines 34-62: Add abort controller
const [abortController, setAbortController] = useState<AbortController | null>(null);

useEffect(() => {
  let interval: NodeJS.Timeout;
  const controller = new AbortController();
  setAbortController(controller);
  
  if (polling && dynamicSessionId) {
    interval = setInterval(async () => {
      try {
        const res = await fetch(
          `${API_BASE_URL}/api/sessions/${dynamicSessionId}/`,
          { signal: controller.signal }
        );
        // ... rest of logic
      } catch (e) {
        if (e.name === 'AbortError') return; // Cancelled
        console.error("Polling error", e);
      }
    }, 1000);
  }
  
  return () => {
    clearInterval(interval);
    controller.abort();
  };
}, [polling, dynamicSessionId]);
```

---

## 🟡 Medium Priority (Fix This Month)

### 7. Add Basic Tests
**Setup:**
```bash
cd frontend/dashboard
npm install -D vitest @testing-library/react @testing-library/jest-dom happy-dom
```

**Add to package.json:**
```json
{
  "scripts": {
    "test": "vitest",
    "test:ui": "vitest --ui"
  }
}
```

**Create:** `frontend/dashboard/vitest.config.ts`
```ts
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'happy-dom',
    globals: true,
    setupFiles: './src/test/setup.ts',
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
});
```

### 8. Environment Variable Validation
**Create:** `frontend/dashboard/src/lib/env.ts`
```ts
import { z } from 'zod';

const envSchema = z.object({
  VITE_API_BASE_URL: z.string().url(),
});

export const env = envSchema.parse({
  VITE_API_BASE_URL: import.meta.env.VITE_API_BASE_URL,
});
```

### 9. Production Build
**Update:** `docker-compose.yml`
```yaml
# Add production profile
services:
  frontend-prod:
    build:
      context: ./frontend/dashboard
      dockerfile: Dockerfile.prod
    profiles: ["production"]
```

**Create:** `frontend/dashboard/Dockerfile.prod`
```dockerfile
FROM node:18-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

### 10. Error Boundaries
**Create:** `frontend/dashboard/src/components/ErrorBoundary.tsx`
```tsx
import React, { Component, ErrorInfo, ReactNode } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { AlertCircle } from "lucide-react";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("Uncaught error:", error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center p-4">
          <Alert variant="destructive" className="max-w-lg">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Something went wrong</AlertTitle>
            <AlertDescription className="mt-2 space-y-2">
              <p>{this.state.error?.message}</p>
              <Button
                variant="outline"
                size="sm"
                onClick={() => window.location.reload()}
              >
                Reload Page
              </Button>
            </AlertDescription>
          </Alert>
        </div>
      );
    }

    return this.props.children;
  }
}
```

**Update:** `frontend/dashboard/src/App.tsx`
```tsx
import { ErrorBoundary } from "@/components/ErrorBoundary";

const App = () => (
  <QueryClientProvider client={queryClient}>
    <ErrorBoundary>
      <TooltipProvider>
        {/* rest of app */}
      </TooltipProvider>
    </ErrorBoundary>
  </QueryClientProvider>
);
```

---

## 🟢 Nice to Have (Optional)

### 11. React Query Migration
**Example for specs:**
```tsx
// hooks/useSpecs.ts
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { API_BASE_URL } from '@/lib/config';

export const useSpecs = () => {
  return useQuery({
    queryKey: ['specs'],
    queryFn: async () => {
      const res = await fetch(`${API_BASE_URL}/api/specs`);
      if (!res.ok) throw new Error('Failed to fetch specs');
      return res.json();
    },
    staleTime: 30000, // 30 seconds
  });
};

export const useUploadSpec = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: async (formData: FormData) => {
      const res = await fetch(`${API_BASE_URL}/api/specs`, {
        method: 'POST',
        body: formData,
      });
      if (!res.ok) throw new Error('Upload failed');
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['specs'] });
    },
  });
};
```

### 12. Logging Service
**Create:** `frontend/dashboard/src/lib/logger.ts`
```tsx
type LogLevel = 'debug' | 'info' | 'warn' | 'error';

class Logger {
  private log(level: LogLevel, message: string, data?: any) {
    const timestamp = new Date().toISOString();
    const logData = {
      timestamp,
      level,
      message,
      ...data,
    };
    
    console[level](JSON.stringify(logData));
    
    // TODO: Send to external service (Sentry, LogRocket, etc.)
  }
  
  debug(message: string, data?: any) {
    this.log('debug', message, data);
  }
  
  info(message: string, data?: any) {
    this.log('info', message, data);
  }
  
  warn(message: string, data?: any) {
    this.log('warn', message, data);
  }
  
  error(message: string, data?: any) {
    this.log('error', message, data);
  }
}

export const logger = new Logger();
```

---

## Verification Steps

After applying fixes, verify:

```bash
# 1. Docker build works
docker compose build frontend
docker compose up frontend

# 2. API calls use env var
grep -r "127.0.0.1:8000" frontend/dashboard/src/
# Should return 0 results

# 3. TypeScript compiles
cd frontend/dashboard
npm run build

# 4. Tests run (after setup)
npm test

# 5. Production build works
docker build -f Dockerfile.prod -t apex-frontend-prod .
```

---

## Tracking

- [ ] Fix 1: Docker npm install
- [ ] Fix 2: Hardcoded API URLs
- [ ] Fix 3: Type safety gaps
- [ ] Fix 4: Config file mismatch
- [ ] Fix 5: Docker compose volumes
- [ ] Fix 6: Polling memory leak
- [ ] Fix 7: Add tests
- [ ] Fix 8: Env validation
- [ ] Fix 9: Production build
- [ ] Fix 10: Error boundaries
- [ ] Fix 11: React Query (optional)
- [ ] Fix 12: Logging service (optional)

---

**Last Updated:** 2026-02-16  
**Status:** Ready for implementation
