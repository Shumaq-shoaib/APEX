import { useState, useEffect } from "react";
import ScanHistory from "@/components/dashboard/ScanHistory";
import DashboardLayout from "@/components/layout/DashboardLayout";
import { AlertCircle } from "lucide-react";
import ScanResults from "@/components/dashboard/ScanResults";
import { API_BASE_URL } from "@/lib/config";
import { AnalysisData } from "@/types/api";

export default function History() {
    const [specs, setSpecs] = useState<AnalysisData[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
    const [analysisData, setAnalysisData] = useState<AnalysisData | null>(null);
    const [loadingDetails, setLoadingDetails] = useState(false);

    useEffect(() => {
        fetchHistory();
    }, []);

    const fetchHistory = async () => {
        setLoading(true);
        try {
            const res = await fetch(`${API_BASE_URL}/api/specs`);
            if (res.ok) {
                const data = await res.json();
                setSpecs(data);
            } else {
                setError("Failed to fetch history");
            }
        } catch (e) {
            setError("Network error");
        } finally {
            setLoading(false);
        }
    };

    const handleScanSelect = async (id: string) => {
        if (id === "new") return; // Should not happen in this view
        setSelectedScanId(id);
        setLoadingDetails(true);
        try {
            const res = await fetch(`${API_BASE_URL}/api/specs/${id}`);
            if (!res.ok) throw new Error("Failed to load details");
            const data: AnalysisData = await res.json();
            setAnalysisData(data);
        } catch (err: unknown) {
            console.error(err);
        } finally {
            setLoadingDetails(false);
        }
    };

    return (
        <DashboardLayout>
            <div className="space-y-6 h-[calc(100vh-8rem)] flex flex-col">
                <div>
                    <h1 className="text-3xl font-bold tracking-tight mb-2">Scan History</h1>
                    <p className="text-muted-foreground">
                        Review past analysis results and reports.
                    </p>
                </div>

                <div className="flex flex-col lg:flex-row gap-6 flex-1 overflow-hidden">
                    {/* List */}
                    <div className="w-full lg:w-80 flex-shrink-0 border rounded-lg overflow-hidden bg-card shadow-sm h-full max-h-[300px] lg:max-h-full">
                        {error && (
                            <div className="p-4 bg-destructive/10 text-destructive text-sm flex items-center gap-2">
                                <AlertCircle className="h-4 w-4" />
                                {error}
                            </div>
                        )}
                        <ScanHistory
                            specs={specs}
                            activeTab={selectedScanId || ""}
                            onTabChange={handleScanSelect}
                            loading={loading}
                        />
                    </div>

                    {/* Details */}
                    <div className="flex-1 overflow-y-auto custom-scrollbar bg-card border rounded-lg shadow-sm p-1">
                        {selectedScanId ? (
                            loadingDetails ? (
                                <div className="flex flex-col items-center justify-center h-full space-y-4">
                                    <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent"></div>
                                    <p className="text-muted-foreground">Loading scan details...</p>
                                </div>
                            ) : (
                                <div className="p-4">
                                    <ScanResults analysisData={analysisData} />
                                </div>
                            )
                        ) : (
                            <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
                                <HistoryIcon className="h-16 w-16 mb-4 opacity-20" />
                                <p>Select a scan from the history to view details</p>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </DashboardLayout>
    );
}

function HistoryIcon({ className }: { className?: string }) {
    return (
        <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            className={className}
        >
            <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 12" />
            <path d="M3 3v9h9" />
            <path d="M12 7v5l4 2" />
        </svg>
    );
}
