import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import StaticAnalysis from "./pages/StaticAnalysis";
import DynamicAnalysis from "./pages/DynamicAnalysis";
import History from "./pages/History";
import NotFound from "./pages/NotFound";
import ErrorBoundary from "@/components/ErrorBoundary";

const queryClient = new QueryClient();

const App = () => (
  <ErrorBoundary>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<StaticAnalysis />} />
            <Route path="/dynamic" element={<DynamicAnalysis />} />
            <Route path="/history" element={<History />} />
            <Route path="/rules" element={<Navigate to="/" replace />} /> {/* Placeholder */}
            <Route path="/settings" element={<Navigate to="/" replace />} /> {/* Placeholder */}
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  </ErrorBoundary>
);

export default App;
