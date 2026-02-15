import { useState, useEffect } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ArrowLeft, Play, Download } from "lucide-react";
import ScanOverview from "./ScanOverview";
import StaticFindingsList from "./StaticFindingsList";
import DynamicConsole from "./DynamicConsole";

interface ScanResultsProps {
    specId: string;
    onBack: () => void;
}

export default function ScanResults({ specId, onBack }: ScanResultsProps) {
    const [data, setData] = useState<any>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState("overview");

    // Fetch Data
    const loadData = async () => {
        setLoading(true);
        try {
            const res = await fetch(`http://127.0.0.1:8000/api/specs/${specId}`);
            if (!res.ok) throw new Error("Failed to load spec");
            const json = await res.json();
            setData(json);

            // If it's a Direct Scan (no static findings), default to Dynamic tab
            if (json.metadata?.profile_used === "direct" && activeTab === "overview") {
                setActiveTab("dynamic");
            }
        } catch (e: any) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadData();
    }, [specId]);

    if (loading) return <div className="p-12 text-center animate-pulse">Loading Analysis Data...</div>;
    if (error) return <div className="p-12 text-center text-red-500">Error: {error}</div>;
    if (!data) return null;

    // Calculate Grade (Mock logic for now)
    const totalVulns = data.summary?.total || 0;
    const grade = totalVulns === 0 ? "A+" : totalVulns < 5 ? "B" : "F";
    const gradeColor = grade === "A+" ? "text-green-500" : grade === "B" ? "text-yellow-500" : "text-red-500";

    return (
        <div className="space-y-6 animate-in slide-in-from-right-4 duration-500">
            {/* Header */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b pb-4">
                <div className="space-y-1">
                    <div className="flex items-center gap-2">
                        <Button variant="ghost" size="sm" onClick={onBack} className="h-8 w-8 p-0 rounded-full">
                            <ArrowLeft className="h-4 w-4" />
                        </Button>
                        <h1 className="text-2xl font-bold tracking-tight">{data.metadata?.api_title || "Untitled API"}</h1>
                        <Badge variant="outline">{data.metadata?.api_version}</Badge>
                    </div>
                    <p className="text-muted-foreground text-sm ml-10">
                        Analyzed {new Date(data.metadata?.timestamp_utc).toLocaleString()}
                    </p>
                </div>

                <div className="flex items-center gap-6">
                    <div className="text-right hidden md:block">
                        <div className="text-xs text-muted-foreground uppercase tracking-wider">Security Grade</div>
                        <div className={`text-3xl font-black ${gradeColor}`}>{grade}</div>
                    </div>
                    {/* Action: If static only, button to jump to dynamic */}
                    <Button variant="outline" size="sm" onClick={() => setActiveTab('dynamic')}>
                        {data.dynamic_session_id ? "View Attack Session" : "Start Dynamic Verification"}
                    </Button>
                </div>
            </div>

            {/* Content Hooks */}
            <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                <TabsList className="w-full justify-start border-b rounded-none h-auto p-0 bg-transparent gap-6">
                    <TabsTrigger value="overview" className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent px-4 py-2">
                        Overview
                    </TabsTrigger>
                    <TabsTrigger value="static" className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent px-4 py-2">
                        Static Findings
                        <Badge variant="secondary" className="ml-2 text-[10px]">{data.summary?.total || 0}</Badge>
                    </TabsTrigger>
                    <TabsTrigger value="dynamic" className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent px-4 py-2">
                        Dynamic Verification
                    </TabsTrigger>
                    <TabsTrigger value="details" className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent px-4 py-2">
                        Raw JSON
                    </TabsTrigger>
                </TabsList>

                <div className="py-6">
                    <TabsContent value="overview">
                        <ScanOverview data={data} />
                    </TabsContent>

                    <TabsContent value="static">
                        <StaticFindingsList endpoints={data.endpoints} />
                    </TabsContent>

                    <TabsContent value="dynamic">
                        <DynamicConsole
                            specId={specId}
                            dynamicSessionId={data.dynamic_session_id}
                            initialTargetUrl={data.metadata?.server_url}
                            onSessionCreated={(sid) => {
                                // Reload data to get the new session ID linked
                                // Ideally backend link is instant, but we might need to locally patching it
                                setData({ ...data, dynamic_session_id: sid });
                            }}
                        />
                    </TabsContent>

                    <TabsContent value="details">
                        <div className="bg-slate-950 text-slate-50 p-4 rounded-lg overflow-auto max-h-[500px] text-xs font-mono">
                            <pre>{JSON.stringify(data, null, 2)}</pre>
                        </div>
                    </TabsContent>
                </div>
            </Tabs>
        </div>
    );
}
