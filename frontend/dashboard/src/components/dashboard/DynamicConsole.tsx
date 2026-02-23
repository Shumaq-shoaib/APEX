import { useState, useEffect } from "react";
import { Shield, Play, Terminal, Lock, Activity } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
    Card, CardContent, CardDescription, CardHeader, CardTitle,
} from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { API_BASE_URL } from "@/lib/config";
import { DynamicSession, TestCase, Finding } from "@/types/api";

interface DynamicConsoleProps {
    specId: string;
    defaultTargetUrl: string;
    initialSessionId?: string;
}

export default function DynamicConsole({ specId, defaultTargetUrl, initialSessionId }: DynamicConsoleProps) {
    // State
    const [targetUrl, setTargetUrl] = useState(defaultTargetUrl);
    const [authToken, setAuthToken] = useState("");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Session State
    const [dynamicSessionId, setDynamicSessionId] = useState<string | null>(initialSessionId || null);
    const [dynamicStatus, setDynamicStatus] = useState<DynamicSession['status'] | null>(initialSessionId ? "RUNNING" : null);
    const [testCases, setTestCases] = useState<TestCase[]>([]);
    const [dynamicFindings, setDynamicFindings] = useState<Finding[]>([]);
    const [polling, setPolling] = useState(!!initialSessionId);
    const [selectedCase, setSelectedCase] = useState<TestCase | null>(null);

    // Poll Dynamic Session
    useEffect(() => {
        let interval: NodeJS.Timeout;
        const controller = new AbortController();

        if (polling && dynamicSessionId) {
            interval = setInterval(async () => {
                try {
                    const res = await fetch(`${API_BASE_URL}/api/sessions/${dynamicSessionId}/`, { signal: controller.signal });
                    if (res.ok) {
                        const data = await res.json();
                        setDynamicStatus(data.status);
                        setTestCases(data.test_cases || []);

                        // If selected case is still valid, update it (to show new logs)
                        if (selectedCase) {
                            const updatedCase = data.test_cases?.find((tc: TestCase) => tc.id === selectedCase.id);
                            if (updatedCase) setSelectedCase(updatedCase);
                        }

                        if (data.status === "COMPLETED" || data.status === "FAILED") {
                            setDynamicFindings(data.findings || []);
                            setPolling(false);
                        }
                    }
                } catch (e: unknown) {
                    if (!(e instanceof DOMException && e.name === "AbortError")) {
                        console.error("Polling error", e);
                    }
                }
            }, 1000);
        }
        return () => {
            clearInterval(interval);
            controller.abort();
        };
    }, [polling, dynamicSessionId, selectedCase]);

    const startDynamicScan = async () => {
        if (!specId) {
            setError("No API Specification selected. Please upload a spec in Static Analysis or select one from History.");
            return;
        }
        try {
            setLoading(true);
            setError(null);
            // 1. Create Session
            const res1 = await fetch(`${API_BASE_URL}/api/sessions/`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    spec_id: specId,
                    target_url: targetUrl,
                    auth_token: authToken || null
                })
            });
            if (!res1.ok) throw new Error("Failed to create session");
            const session = await res1.json();

            // 2. Start Scan
            const res2 = await fetch(`${API_BASE_URL}/api/sessions/${session.id}/start/`, { method: "POST" });
            if (!res2.ok) throw new Error("Failed to start scan");

            setDynamicSessionId(session.id);
            setDynamicStatus("PENDING");
            setPolling(true);
            // Reset previous results
            setTestCases([]);
            setDynamicFindings([]);
            setSelectedCase(null);

        } catch (e: unknown) {
            setError(e instanceof Error ? e.message : "Failed to start dynamic scan");
        } finally {
            setLoading(false);
        }
    };

    // 1. Config View
    if (!dynamicSessionId) {
        return (
            <div className="flex flex-col items-center justify-center p-8 space-y-6 max-w-2xl mx-auto">
                <div className="text-center space-y-2">
                    <div className="bg-primary/10 p-4 rounded-full inline-block mb-2">
                        <Terminal className="h-8 w-8 text-primary" />
                    </div>
                    <h2 className="text-2xl font-bold">Dynamic Verification</h2>
                    <p className="text-muted-foreground">
                        Configure target environment to verify static findings against a running API.
                    </p>
                </div>

                <Card className="w-full">
                    <CardContent className="space-y-4 pt-6">
                        <div className="space-y-2">
                            <Label htmlFor="targetUrl">Target URL</Label>
                            <div className="flex gap-2">
                                <Input
                                    id="targetUrl"
                                    value={targetUrl}
                                    onChange={(e) => setTargetUrl(e.target.value)}
                                    placeholder="http://localhost:8888"
                                />
                            </div>
                            <p className="text-xs text-muted-foreground">
                                Base URL of the running API. Use <code>host.docker.internal</code> for local Docker services.
                            </p>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="authToken" className="flex items-center gap-2">
                                <Lock className="h-3 w-3" /> Authorization Token (Optional)
                            </Label>
                            <Textarea
                                id="authToken"
                                value={authToken}
                                onChange={(e) => setAuthToken(e.target.value)}
                                placeholder="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                                className="font-mono text-xs"
                            />
                        </div>

                        {error && <p className="text-sm text-destructive font-medium">{error}</p>}

                        <Button onClick={startDynamicScan} disabled={loading} className="w-full">
                            {loading ? (
                                <>Starting Engine...</>
                            ) : (
                                <><Play className="mr-2 h-4 w-4" /> Start Dynamic Scan</>
                            )}
                        </Button>
                    </CardContent>
                </Card>
            </div>
        );
    }

    // 2. Execution View
    return (
        <div className="space-y-6 h-full flex flex-col">
            {/* Status Header */}
            <Card className="flex-shrink-0">
                <CardHeader className="py-4">
                    <div className="flex items-center justify-between">
                        <div className="space-y-1">
                            <CardTitle className="text-lg flex items-center gap-2">
                                <Activity className="h-5 w-5 text-primary" />
                                Scan Status: <span className={dynamicStatus === "RUNNING" ? "text-primary animate-pulse" : ""}>{dynamicStatus}</span>
                            </CardTitle>
                            <CardDescription className="font-mono text-xs">Session: {dynamicSessionId}</CardDescription>
                        </div>
                        <div className="text-right">
                            <div className="text-2xl font-bold font-mono">{testCases.length}</div>
                            <div className="text-xs text-muted-foreground">Test Cases Executed</div>
                        </div>
                    </div>
                </CardHeader>
            </Card>

            {/* Main Console Layout */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1 min-h-[500px]">

                {/* Left: Execution Queue */}
                <Card className="col-span-1 flex flex-col overflow-hidden border-2">
                    <CardHeader className="py-3 border-b bg-muted/40">
                        <CardTitle className="text-sm font-medium">Test Queue</CardTitle>
                    </CardHeader>
                    <ScrollArea className="flex-1">
                        <div className="divide-y">
                            {testCases.map((tc: TestCase) => (
                                <div
                                    key={tc.id}
                                    onClick={() => setSelectedCase(tc)}
                                    className={`p-3 cursor-pointer transition-colors hover:bg-muted/60 text-sm ${selectedCase?.id === tc.id ? "bg-muted border-l-4 border-l-primary" : "border-l-4 border-l-transparent"}`}
                                >
                                    <div className="flex justify-between items-center mb-1">
                                        <span className="font-semibold text-xs uppercase tracking-wider">{tc.check_type}</span>
                                        <Badge variant={tc.status === "EXECUTED" ? "outline" : "secondary"} className="text-[10px] h-5">
                                            {tc.status}
                                        </Badge>
                                    </div>
                                    <div className="text-xs text-muted-foreground truncate font-mono" title={`${tc.method} ${tc.endpoint_path}`}>
                                        {tc.method} {tc.endpoint_path}
                                    </div>
                                </div>
                            ))}
                            {testCases.length === 0 && (
                                <div className="p-8 text-center text-xs text-muted-foreground">
                                    Initializing test suite...
                                </div>
                            )}
                        </div>
                    </ScrollArea>
                </Card>

                {/* Right: Terminal Output */}
                <Card className="col-span-2 flex flex-col overflow-hidden bg-black text-green-400 font-mono text-xs shadow-inner border-gray-800">
                    <CardHeader className="py-2 border-b border-green-900/30 bg-gray-900/50">
                        <div className="flex justify-between items-center">
                            <CardTitle className="text-xs uppercase text-green-500/80 tracking-widest flex items-center gap-2">
                                <Terminal className="h-3 w-3" /> Console Output
                            </CardTitle>
                            {selectedCase && <span className="text-gray-600 text-[10px]">{selectedCase.id}</span>}
                        </div>
                    </CardHeader>
                    <ScrollArea className="flex-1 bg-black/90">
                        <div className="p-4">
                            {selectedCase ? (
                                <pre className="whitespace-pre-wrap leading-relaxed pb-4">
                                    {selectedCase.logs || "> Initializing scanner...\n> Waiting for output..."}
                                </pre>
                            ) : (
                                <div className="flex flex-col items-center justify-center h-40 text-green-800/50">
                                    <Activity className="h-8 w-8 mb-2 opacity-50" />
                                    <p>Select a test case to monitor execution.</p>
                                </div>
                            )}
                        </div>
                    </ScrollArea>
                </Card>
            </div>

            {/* Verified Vulnerabilities (Bottom) */}
            {dynamicFindings.length > 0 && (
                <div className="space-y-4 animate-in fade-in slide-in-from-bottom-8">
                    <div className="flex items-center gap-2">
                        <Shield className="h-5 w-5 text-destructive" />
                        <h3 className="text-lg font-semibold">Verified Vulnerabilities</h3>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {dynamicFindings.map((finding) => (
                            <Card
                                key={finding.id}
                                className={`bg-card border-l-4 cursor-pointer hover:shadow-md transition-all ${finding.severity === 'Critical' || finding.severity === 'High' ? 'border-l-destructive' : 'border-l-orange-500'}`}
                                onClick={() => {
                                    if (finding.test_case_id) {
                                        const linkedCase = testCases?.find((tc: TestCase) => tc.id === finding.test_case_id);
                                        if (linkedCase) setSelectedCase(linkedCase);
                                    }
                                }}
                            >
                                <CardHeader className="pb-2">
                                    <div className="flex justify-between items-start">
                                        <CardTitle className="text-sm font-semibold flex items-center gap-2">
                                            {finding.title}
                                        </CardTitle>
                                        <Badge variant={finding.severity === "High" || finding.severity === "Critical" ? "destructive" : "secondary"}>
                                            {finding.severity}
                                        </Badge>
                                    </div>
                                </CardHeader>
                                <CardContent>
                                    <p className="text-xs text-muted-foreground mb-2 line-clamp-2">
                                        {finding.description}
                                    </p>
                                    <div className="flex items-center gap-4 text-[10px] font-mono text-muted-foreground">
                                        <span>CVSS: {finding.cvss_score}</span>
                                        {finding.test_case_id && <span className="text-primary underline">View Logs</span>}
                                    </div>
                                </CardContent>
                            </Card>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
