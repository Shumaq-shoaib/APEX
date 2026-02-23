import { useLocation } from "react-router-dom";
import DynamicConsole from "@/components/dashboard/DynamicConsole";
import DashboardLayout from "@/components/layout/DashboardLayout";

export default function DynamicAnalysis() {
    const location = useLocation();
    const state = location.state as { specId?: string; targetUrl?: string; sessionId?: string } | null;

    return (
        <DashboardLayout>
            <div className="space-y-6 h-full flex flex-col">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight mb-2">Dynamic Analysis</h1>
                    <p className="text-muted-foreground">
                        Verify static findings by running active probes against a live target.
                    </p>
                </div>

                <div className="flex-1">
                    <DynamicConsole
                        specId={state?.specId || ""}
                        defaultTargetUrl={state?.targetUrl || "http://localhost:8888"}
                        initialSessionId={state?.sessionId}
                    />
                </div>
            </div>
        </DashboardLayout>
    );
}
