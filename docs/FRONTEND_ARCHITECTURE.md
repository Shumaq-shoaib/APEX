# APEX Frontend Architecture

**Last Updated:** 2026-02-16

---

## Technology Stack

```
┌─────────────────────────────────────────────────────┐
│                  APEX Frontend                       │
├─────────────────────────────────────────────────────┤
│  React 18.3.1 + TypeScript 5.8.3                    │
│  Vite 5.4.11 (Build Tool)                           │
│  Tailwind CSS v3.4.17 (Styling)                     │
│  shadcn UI (Component Library)                      │
│  React Router v6 (Routing)                          │
│  TanStack Query v5 (State Management)               │
│  Recharts 2.15.4 (Charts)                           │
│  Lucide React 0.462.0 (Icons)                       │
└─────────────────────────────────────────────────────┘
```

---

## Directory Structure

```
frontend/dashboard/
├── public/                      # Static assets
├── src/
│   ├── components/             # React components
│   │   ├── ui/                # shadcn components (49 files)
│   │   │   ├── button.tsx
│   │   │   ├── card.tsx
│   │   │   ├── table.tsx
│   │   │   └── ... (46 more)
│   │   ├── layout/            # Layout components
│   │   │   ├── AppSidebar.tsx
│   │   │   └── DashboardLayout.tsx
│   │   └── dashboard/         # Business components
│   │       ├── DynamicConsole.tsx
│   │       ├── ScanOverview.tsx
│   │       ├── StaticFindings.tsx
│   │       ├── ScanHistory.tsx
│   │       └── ScanResults.tsx
│   ├── pages/                 # Route components
│   │   ├── StaticAnalysis.tsx
│   │   ├── DynamicAnalysis.tsx
│   │   ├── History.tsx
│   │   └── NotFound.tsx
│   ├── lib/                   # Utilities
│   │   └── utils.ts          # cn() helper
│   ├── hooks/                 # Custom hooks
│   ├── App.tsx               # Root component
│   ├── main.tsx              # Entry point
│   └── index.css             # Global styles
├── components.json            # shadcn config
├── tailwind.config.js         # Tailwind config
├── vite.config.ts            # Vite config
├── tsconfig.json             # TypeScript config
└── package.json              # Dependencies
```

---

## Component Hierarchy

```
App.tsx
├── QueryClientProvider (TanStack Query)
│   └── TooltipProvider (shadcn)
│       └── BrowserRouter (React Router)
│           ├── Toaster (Toast notifications)
│           ├── Sonner (Alternative toasts)
│           └── Routes
│               ├── Route "/"
│               │   └── StaticAnalysis
│               │       └── DashboardLayout
│               │           ├── Header (sticky)
│               │           ├── AppSidebar (desktop)
│               │           └── Main Content
│               │               ├── NewScanSelector
│               │               │   ├── File upload
│               │               │   ├── Mode selector
│               │               │   └── Config form
│               │               ├── ScanOverview
│               │               │   ├── Summary cards
│               │               │   ├── Pie chart
│               │               │   ├── Bar chart
│               │               │   └── Metadata grid
│               │               └── StaticFindings
│               │                   └── Vulnerability list
│               │
│               ├── Route "/dynamic"
│               │   └── DynamicAnalysis
│               │       └── DashboardLayout
│               │           └── DynamicConsole
│               │               ├── Config view
│               │               │   ├── Target URL input
│               │               │   └── Auth token input
│               │               └── Execution view
│               │                   ├── Status header
│               │                   ├── Test queue (left)
│               │                   ├── Terminal logs (right)
│               │                   └── Findings grid (bottom)
│               │
│               └── Route "/history"
│                   └── History
│                       └── DashboardLayout
│                           ├── ScanHistory (sidebar)
│                           └── ScanResults (main)
```

---

## Data Flow

### Static Analysis Flow

```
┌────────────────┐
│ User Action    │ Upload OpenAPI spec file
└───────┬────────┘
        │
        ▼
┌────────────────┐
│ NewScanSelector│ Handle file, show loading
└───────┬────────┘
        │
        │ POST /api/specs (FormData)
        │
        ▼
┌────────────────┐
│ Backend API    │ Analyze spec, return spec_id
└───────┬────────┘
        │
        │ onScanComplete(spec_id)
        │
        ▼
┌────────────────┐
│StaticAnalysis  │ GET /api/specs/{spec_id}
└───────┬────────┘
        │
        │ setState(analysisData)
        │
        ▼
┌────────────────┐
│ ScanOverview + │ Display results
│StaticFindings  │
└────────────────┘
```

### Dynamic Analysis Flow

```
┌────────────────┐
│ User Input     │ spec_id, target_url, auth_token
└───────┬────────┘
        │
        ▼
┌────────────────┐
│DynamicConsole  │ POST /api/sessions/ (create)
└───────┬────────┘
        │
        │ session_id returned
        │
        ▼
┌────────────────┐
│DynamicConsole  │ POST /api/sessions/{id}/start
└───────┬────────┘
        │
        │ Start polling (1s interval)
        │
        ▼
┌────────────────┐
│ Polling Loop   │ GET /api/sessions/{id}/ every 1s
└───────┬────────┘
        │
        │ Update UI with:
        │ - Session status
        │ - Test cases
        │ - Logs
        │ - Findings
        │
        ▼
┌────────────────┐
│ UI Updates     │ Terminal logs, test queue, findings
└────────────────┘
        │
        │ Stop when status = COMPLETED/FAILED
        │
        ▼
┌────────────────┐
│ Final Results  │ Display verified vulnerabilities
└────────────────┘
```

---

## State Management Patterns

### Local State (useState)

**Used for:**
- UI state (loading, error, selected items)
- Form inputs
- Component-specific data

**Example:**
```tsx
const [loading, setLoading] = useState(false);
const [error, setError] = useState<string | null>(null);
const [analysisData, setAnalysisData] = useState<any | null>(null);
```

### React Router State

**Used for:**
- Passing data between routes
- Navigation context

**Example:**
```tsx
// In StaticAnalysis
navigate("/dynamic", {
  state: { specId, targetUrl }
});

// In DynamicAnalysis
const location = useLocation();
const state = location.state as { specId?: string; targetUrl?: string };
```

### TanStack Query (Underutilized)

**Currently:** Installed but minimal usage  
**Should use for:** API calls, caching, background refetching

---

## Styling System

### Design Tokens (CSS Variables)

```css
:root {
  /* Layout */
  --background: 224 15% 5%;      /* #0A0E14 */
  --foreground: 213 27% 90%;     /* #D9E2F0 */
  
  /* Brand */
  --primary: 142 76% 36%;        /* #2D7A4C (Green) */
  --primary-foreground: 355 100% 97%;
  
  /* UI */
  --card: 224 15% 6%;
  --border: 216 34% 17%;
  --muted: 217 32% 15%;
  --accent: 217 32% 17%;
  
  /* Severity Colors */
  --critical: 0 84% 60%;         /* Red */
  --high: 25 95% 53%;            /* Orange */
  --medium: 48 96% 53%;          /* Yellow */
  --low: 213 94% 68%;            /* Blue */
  --informational: 142 76% 36%;  /* Green */
}
```

### Tailwind Utilities

```tsx
// Layout
<div className="flex items-center gap-4">
<div className="grid grid-cols-3 gap-6">
<div className="space-y-4">

// Sizing
<div className="w-full h-screen">
<div className="max-w-7xl mx-auto">

// Colors
<div className="bg-primary text-primary-foreground">
<div className="bg-card border">

// Effects
<div className="hover:shadow-lg transition-all">
<div className="animate-in fade-in duration-700">
```

### Component Variants

```tsx
// Button variants (shadcn)
<Button variant="default">Primary</Button>
<Button variant="destructive">Delete</Button>
<Button variant="outline">Cancel</Button>
<Button variant="ghost">Subtle</Button>

// Badge variants
<Badge variant="default">Info</Badge>
<Badge variant="destructive">Critical</Badge>
<Badge variant="outline">Tag</Badge>
```

---

## Routing Architecture

### Route Configuration

```tsx
<Routes>
  <Route path="/" element={<StaticAnalysis />} />
  <Route path="/dynamic" element={<DynamicAnalysis />} />
  <Route path="/history" element={<History />} />
  <Route path="/rules" element={<Navigate to="/" replace />} />
  <Route path="/settings" element={<Navigate to="/" replace />} />
  <Route path="*" element={<NotFound />} />
</Routes>
```

### Navigation Structure

```
├── Analysis
│   ├── Static Analysis (/)
│   └── Dynamic Analysis (/dynamic)
└── Management
    ├── Scan History (/history)
    ├── Rules & Policies (/rules) [Placeholder]
    └── Settings (/settings) [Placeholder]
```

---

## API Integration

### Current Pattern (Fetch API)

```tsx
// Direct fetch calls in components
const res = await fetch('http://127.0.0.1:8000/api/specs');
const data = await res.json();
```

**Issues:**
- Hardcoded base URL
- No centralized error handling
- No request/response interceptors
- Manual loading states

### Recommended Pattern (Abstracted)

```tsx
// lib/api.ts
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL;

export const api = {
  specs: {
    getAll: () => fetch(`${API_BASE_URL}/api/specs`).then(r => r.json()),
    getById: (id) => fetch(`${API_BASE_URL}/api/specs/${id}`).then(r => r.json()),
    upload: (formData) => fetch(`${API_BASE_URL}/api/specs`, {
      method: 'POST',
      body: formData
    }).then(r => r.json()),
  }
};

// In component
import { api } from '@/lib/api';
const specs = await api.specs.getAll();
```

### With React Query (Best Practice)

```tsx
// hooks/useSpecs.ts
export const useSpecs = () => {
  return useQuery({
    queryKey: ['specs'],
    queryFn: api.specs.getAll,
    staleTime: 30000,
  });
};

// In component
const { data: specs, isLoading, error } = useSpecs();
```

---

## Performance Considerations

### Current Optimizations

✅ Vite for fast dev server  
✅ Code splitting by route (React Router)  
✅ CSS-in-JS avoided (Tailwind classes)  
✅ Animations use CSS (GPU accelerated)

### Missing Optimizations

❌ No lazy loading for routes  
❌ No image optimization  
❌ No bundle size analysis  
❌ No memoization (React.memo, useMemo)  
❌ Charts not virtualized

### Recommendations

```tsx
// Lazy load routes
const StaticAnalysis = lazy(() => import('./pages/StaticAnalysis'));

// Memoize expensive components
const ScanOverview = memo(({ data }) => { ... });

// Virtualize long lists (if needed)
import { useVirtualizer } from '@tanstack/react-virtual';
```

---

## Accessibility Features

### Implemented ✅

- Semantic HTML (`<header>`, `<main>`, `<nav>`)
- ARIA labels on interactive elements
- Focus-visible styles (keyboard navigation)
- Screen reader text (`sr-only` class)
- Color contrast (WCAG AA compliant)
- Keyboard navigation support

### Examples

```tsx
// ARIA labels
<button aria-label="Toggle menu">
  <Menu className="h-5 w-5" />
</button>

// Screen reader only text
<span className="sr-only">Loading...</span>

// Focus styles
:focus-visible {
  @apply outline-none ring-2 ring-ring;
}
```

---

## Error Handling

### Current Pattern

```tsx
try {
  const res = await fetch(url);
  if (!res.ok) throw new Error("Failed");
  const data = await res.json();
  setData(data);
} catch (e) {
  console.error(e);
  setError(e.message);
}
```

### Recommended Pattern

```tsx
// Add error boundary
<ErrorBoundary fallback={<ErrorPage />}>
  <App />
</ErrorBoundary>

// Use React Query for API errors
const { error, isError } = useQuery(...);

// Show user-friendly messages
{isError && <Alert variant="destructive">{error.message}</Alert>}
```

---

## Build & Deployment

### Development

```bash
# Install dependencies
npm install

# Start dev server (HMR enabled)
npm run dev  # http://localhost:5173

# Type check
npm run build  # Compiles TypeScript
```

### Production Build

```bash
# Build optimized bundle
npm run build

# Preview production build
npm run preview
```

### Docker (Current)

```dockerfile
# Development mode (with HMR)
FROM node:18-slim
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host"]
```

**Issue:** Running dev server in container (not production-ready)

### Docker (Recommended)

```dockerfile
# Multi-stage build
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
```

---

## Testing Strategy (Planned)

### Unit Tests (Vitest)

```tsx
// components/__tests__/Button.test.tsx
import { render, screen } from '@testing-library/react';
import { Button } from '@/components/ui/button';

describe('Button', () => {
  it('renders children', () => {
    render(<Button>Click me</Button>);
    expect(screen.getByText('Click me')).toBeInTheDocument();
  });
});
```

### Integration Tests

```tsx
// pages/__tests__/StaticAnalysis.test.tsx
import { render, screen, waitFor } from '@testing-library/react';
import { StaticAnalysis } from '@/pages/StaticAnalysis';

describe('StaticAnalysis', () => {
  it('uploads spec and displays results', async () => {
    // Mock API
    // Render component
    // Simulate file upload
    // Assert results displayed
  });
});
```

### E2E Tests (Playwright - Future)

```ts
test('complete scan workflow', async ({ page }) => {
  await page.goto('http://localhost:5173');
  await page.setInputFiles('input[type="file"]', './test-spec.yaml');
  await page.click('button:has-text("Run Static Analysis")');
  await expect(page.locator('text=Scan Results')).toBeVisible();
});
```

---

## Security Considerations

### Current Measures

✅ TypeScript for type safety  
✅ Input validation on upload  
✅ HTTPS in production (assumed)  
✅ CORS handled by backend

### Recommendations

❌ Add Content Security Policy  
❌ Sanitize user input (if any)  
❌ Implement authentication  
❌ Add rate limiting (frontend)  
❌ Audit npm dependencies

---

## Key Metrics

| Metric | Value |
|--------|-------|
| **Bundle Size** | ~500KB (estimated, gzipped) |
| **Load Time** | <2s (local dev) |
| **Components** | 30+ custom, 49 shadcn |
| **Routes** | 6 defined (3 active, 2 placeholders) |
| **Lines of Code** | ~2,000 (excluding ui/) |
| **Dependencies** | 62 total (dev + prod) |
| **TypeScript Coverage** | ~80% (many `any` types) |
| **Test Coverage** | 0% (no tests yet) |

---

**Document Version:** 1.0  
**Last Updated:** 2026-02-16
