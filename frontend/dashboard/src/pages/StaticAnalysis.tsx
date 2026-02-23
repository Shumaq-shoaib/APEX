import { useState } from "react";
import { useNavigate } from "react-router-dom";
import NewScanSelector from "@/components/NewScanSelector";
import ScanOverview from "@/components/dashboard/ScanOverview";
import StaticFindings from "@/components/dashboard/StaticFindings";
import { Button } from "@/components/ui/button";
import { ArrowRight, RotateCcw } from "lucide-react";
import DashboardLayout from "@/components/layout/DashboardLayout";

import { API_BASE_URL } from "@/lib/config";
import { AnalysisData } from "@/types/api";

export default function StaticAnalysis() {
    const [analysisData, setAnalysisData] = useState<AnalysisData | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const navigate = useNavigate();

    const handleScanComplete = (specId: string) => {
        // Fetch full analysis data now that we have the ID
        setLoading(true);
        fetch(`${API_BASE_URL}/api/specs/${specId}`)
            .then(res => res.json())
            .then(data => {
                setAnalysisData(data);
                setLoading(false);
            })
            .catch(err => {
                console.error("Failed to fetch analysis results:", err);
                setError("Failed to load analysis results");
                setLoading(false);
            });
    };

    const handleReset = () => {
        setAnalysisData(null);
        setError(null);
    };

    const handleVerifyDynamic = () => {
        if (analysisData?.spec_id) {
            navigate("/dynamic", {
                state: {
                    specId: analysisData.spec_id,
                    targetUrl: analysisData.metadata?.server_url
                }
            });
        }
    };

    const handleDynamicScanStarted = (sessionId: string, specId: string) => {
        navigate("/dynamic", {
            state: {
                specId,
                sessionId,
                targetUrl: "http://localhost:8888"
            }
        });
    };

    return (
        <DashboardLayout>
            <div className="space-y-6">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight mb-2">Static Analysis</h1>
                    <p className="text-muted-foreground">
                        Upload OpenAPI specifications to detect design-time vulnerabilities.
                    </p>
                </div>

                {!analysisData ? (
                    <NewScanSelector
                        onScanComplete={handleScanComplete}
                        onDynamicScanStarted={handleDynamicScanStarted}
                    />
                ) : (
                    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-8 duration-700">
                        <div className="flex items-center justify-between bg-card p-4 rounded-lg border shadow-sm">
                            <div className="flex items-center gap-4">
                                <Button variant="outline" onClick={handleReset} size="sm">
                                    <RotateCcw className="mr-2 h-4 w-4" />
                                    New Scan
                                </Button>
                                <div className="h-6 w-px bg-border" />
                                <span className="font-semibold">{analysisData.metadata?.api_title || "API Analysis"}</span>
                                <span className="text-muted-foreground text-sm">{analysisData.metadata?.timestamp_utc}</span>
                            </div>
                            <Button onClick={handleVerifyDynamic} className="bg-primary text-primary-foreground hover:bg-primary/90">
                                Verify with Dynamic Scan
                                <ArrowRight className="ml-2 h-4 w-4" />
                            </Button>
                        </div>

                        <ScanOverview data={analysisData} />
                        <StaticFindings data={analysisData} />
                    </div>
                )}
            </div>
        </DashboardLayout>
    );
}
