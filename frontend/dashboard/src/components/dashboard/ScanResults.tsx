import { useState, useEffect } from "react";
import { API_BASE_URL } from "@/lib/config";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import ScanOverview from "./ScanOverview";
import StaticFindings from "./StaticFindings";
import DynamicConsole from "./DynamicConsole";
import {
    Card, CardContent, CardDescription, CardHeader, CardTitle,
} from "@/components/ui/card";

import { AnalysisData } from "@/types/api";

interface ScanResultsProps {
    analysisData: AnalysisData | null;
}

export default function ScanResults({ analysisData }: ScanResultsProps) {
    const [mergedData, setMergedData] = useState<AnalysisData | null>(analysisData);

    useEffect(() => {
        if (!analysisData) {
            setMergedData(null);
            return;
        }

        // Optimistically set it
        setMergedData(analysisData);

        if (analysisData.spec_id) {
            fetch(`${API_BASE_URL}/api/sessions/by_spec/${analysisData.spec_id}`)
                .then(res => {
                    if (res.ok) return res.json();
                    throw new Error("No session found");
                })
                .then(sessionData => {
                    if (sessionData && sessionData.findings && sessionData.findings.length > 0) {
                        const updated = JSON.parse(JSON.stringify(analysisData));
                        updated.dynamic_session_id = sessionData.id;
                        
                        // Merge findings into summary counts
                        sessionData.findings.forEach((f: any) => {
                            const sev = f.severity === "Informational" ? "Low" : f.severity;
                            if (updated.summary[sev] !== undefined) {
                                updated.summary[sev] += 1;
                                updated.summary.total += 1;
                            }
                        });
                        
                        setMergedData(updated);
                    }
                })
                .catch(() => {
                    // It's ok if there's no dynamic session
                });
        }
    }, [analysisData]);

    if (!mergedData) return null;

    return (
        <Tabs defaultValue="overview" className="w-full">
            <div className="mb-6">
                <TabsList className="grid w-full grid-cols-4 bg-muted/50 p-1 rounded-xl">
                    <TabsTrigger value="overview" className="rounded-lg">Overview</TabsTrigger>
                    <TabsTrigger value="vulnerabilities" className="rounded-lg">All Vulnerabilities</TabsTrigger>
                    <TabsTrigger value="dynamic" className="rounded-lg">Dynamic Verification</TabsTrigger>
                    <TabsTrigger value="details" className="rounded-lg">Raw Data</TabsTrigger>
                </TabsList>
            </div>

            <div className="min-h-[500px]">
                {/* Overview */}
                <TabsContent value="overview" className="mt-0 focus-visible:outline-none">
                    <ScanOverview data={mergedData} />
                </TabsContent>

                {/* Static Findings / All Vulnerabilities */}
                <TabsContent value="vulnerabilities" className="mt-0 focus-visible:outline-none">
                    <StaticFindings data={mergedData} />
                </TabsContent>

                {/* Dynamic Verification */}
                <TabsContent value="dynamic" className="mt-0 focus-visible:outline-none">
                    <DynamicConsole
                        specId={mergedData.spec_id}
                        defaultTargetUrl={mergedData.metadata?.server_url || "http://host.docker.internal:8888"}
                        initialSessionId={mergedData.dynamic_session_id || undefined}
                    />
                </TabsContent>

                {/* Raw Data */}
                <TabsContent value="details" className="mt-0 focus-visible:outline-none">
                    <Card>
                        <CardHeader>
                            <CardTitle>Raw Analysis Data</CardTitle>
                            <CardDescription>Complete JSON output from the security scan</CardDescription>
                        </CardHeader>
                        <CardContent>
                            <pre className="text-xs bg-muted p-4 rounded-lg overflow-auto max-h-[600px] font-mono custom-scrollbar">
                                {JSON.stringify(mergedData, null, 2)}
                            </pre>
                        </CardContent>
                    </Card>
                </TabsContent>
            </div>
        </Tabs>
    );
}
