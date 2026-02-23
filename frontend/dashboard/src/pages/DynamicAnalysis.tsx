import { useLocation } from "react-router-dom";
import DynamicConsole from "@/components/dashboard/DynamicConsole";
import DashboardLayout from "@/components/layout/DashboardLayout";

export default function DynamicAnalysis() {
    const location = useLocation();
    const state = location.state as { specId?: string; targetUrl?: string; sessionId?: string } | null;

    return (
        <DashboardLayout>
            <div className="h-full flex flex-col overflow-hidden">
                <div className="shrink-0 mb-4">
                    <h1 className="text-3xl font-bold tracking-tight mb-2">Dynamic Analysis</h1>
                    <p className="text-muted-foreground">
                        Launch active security probes against a running API to discover real vulnerabilities.
                    </p>
                </div>

                <div className="flex-1 min-h-0">
                    <DynamicConsole
                        specId={state?.specId || undefined}
                        defaultTargetUrl={state?.targetUrl || "http://host.docker.internal:8888"}
                        initialSessionId={state?.sessionId}
                    />
                </div>
            </div>
        </DashboardLayout>
    );
}
