import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import ScanOverview from "./ScanOverview";
import StaticFindings from "./StaticFindings";
import DynamicConsole from "./DynamicConsole";
import {
    Card, CardContent, CardDescription, CardHeader, CardTitle,
} from "@/components/ui/card";

import { AnalysisData } from "@/types/api";

interface ScanResultsProps {
    analysisData: AnalysisData;
}

export default function ScanResults({ analysisData }: ScanResultsProps) {
    if (!analysisData) return null;

    return (
        <Tabs defaultValue="overview" className="w-full">
            <div className="mb-6">
                <TabsList className="grid w-full grid-cols-4 bg-muted/50 p-1 rounded-xl">
                    <TabsTrigger value="overview" className="rounded-lg">Overview</TabsTrigger>
                    <TabsTrigger value="vulnerabilities" className="rounded-lg">Static Findings</TabsTrigger>
                    <TabsTrigger value="dynamic" className="rounded-lg">Dynamic Verification</TabsTrigger>
                    <TabsTrigger value="details" className="rounded-lg">Raw Data</TabsTrigger>
                </TabsList>
            </div>

            <div className="min-h-[500px]">
                {/* Overview */}
                <TabsContent value="overview" className="mt-0 focus-visible:outline-none">
                    <ScanOverview data={analysisData} />
                </TabsContent>

                {/* Static Findings */}
                <TabsContent value="vulnerabilities" className="mt-0 focus-visible:outline-none">
                    <StaticFindings data={analysisData} />
                </TabsContent>

                {/* Dynamic Verification */}
                <TabsContent value="dynamic" className="mt-0 focus-visible:outline-none">
                    <DynamicConsole
                        specId={analysisData.spec_id}
                        defaultTargetUrl={analysisData.metadata?.server_url || "http://localhost:8888"}
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
                                {JSON.stringify(analysisData, null, 2)}
                            </pre>
                        </CardContent>
                    </Card>
                </TabsContent>
            </div>
        </Tabs>
    );
}
