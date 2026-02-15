import { useState, useEffect, useRef } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Shield, Play, Terminal, AlertTriangle, Info, CheckCircle, Activity, BarChart3 } from "lucide-react";
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

interface DynamicConsoleProps {
    specId: string;
    dynamicSessionId: string | null;
    initialTargetUrl?: string;
    onSessionCreated: (sessionId: string) => void;
}

export default function DynamicConsole({ specId, dynamicSessionId, initialTargetUrl, onSessionCreated }: DynamicConsoleProps) {
    const [status, setStatus] = useState<string | null>(null);
    const [testCases, setTestCases] = useState<any[]>([]);
    const [findings, setFindings] = useState<any[]>([]);
    const [polling, setPolling] = useState(false);
    const [selectedCase, setSelectedCase] = useState<any>(null);

    // Start Form State
    const [targetUrl, setTargetUrl] = useState(initialTargetUrl || "http://localhost:8888");
    const [authToken, setAuthToken] = useState("");
    const [authSecondary, setAuthSecondary] = useState("");
    const [starting, setStarting] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Auto-scroll terminal
    const terminalEndRef = useRef<HTMLDivElement>(null);
    useEffect(() => {
        terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [selectedCase?.logs]);

    // Polling Logic
    useEffect(() => {
        let interval: NodeJS.Timeout;
        if ((polling || dynamicSessionId) && dynamicSessionId) {
            // Create internal polling function
            const poll = async () => {
                try {
                    const res = await fetch(`http://127.0.0.1:8000/api/sessions/${dynamicSessionId}`);
                    if (res.ok) {
                        const data = await res.json();
                        setStatus(data.status);
                        setTestCases(data.test_cases || []);

                        // If finished, stop polling eventually, but keep separate finding list
                        if (data.status === "COMPLETED" || data.status === "FAILED") {
                            setFindings(data.findings || []);
                            // Don't stop polling immediately if you want to see final updates? 
                            // Actually, once completed, it's done.
                            setPolling(false);
                        }
                    }
                } catch (e) {
                    console.error("Poll Error", e);
                }
            };

            poll(); // Initial call
            if (status !== "COMPLETED" && status !== "FAILED") {
                interval = setInterval(poll, 1500);
                setPolling(true);
            }
        }
        return () => clearInterval(interval);
    }, [dynamicSessionId, status]);

    const handleStartScan = async () => {
        setStarting(true);
        setError(null);
        try {
            // 1. Create Session
            const res1 = await fetch("http://127.0.0.1:8000/api/sessions/", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    spec_id: specId,
                    target_url: targetUrl,
                    auth_token: authToken || null,
                    auth_token_secondary: authSecondary || null
                })
            });
            if (!res1.ok) throw new Error("Failed to create session");
            const session = await res1.json();

            // 2. Start
            const res2 = await fetch(`http://127.0.0.1:8000/api/sessions/${session.id}/start`, { method: "POST" });
            if (!res2.ok) throw new Error("Failed to launch scan");

            onSessionCreated(session.id);
            setPolling(true);
        } catch (e: any) {
            setError(e.message);
        } finally {
            setStarting(false);
        }
    };

    // Render: Configuration Screen (if no session)
    if (!dynamicSessionId) {
        return (
            <Card className="border-l-4 border-l-blue-500 bg-slate-50 dark:bg-slate-900/50">
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <Shield className="h-5 w-5 text-blue-500" />
                        Configure Dynamic Attack
                    </CardTitle>
                    <CardDescription>
                        This will run active vulnerability tests (SQLi, XSS, BOLA) against your running API.
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="space-y-2">
                            <Label>Target API URL</Label>
                            <input type="text" value={targetUrl} onChange={e => setTargetUrl(e.target.value)}
                                className="flex h-10 w-full rounded-md border bg-background px-3" placeholder="http://localhost:8000" />
                        </div>
                        <div className="space-y-2">
                            <Label>Auth Token (Optional)</Label>
                            <input type="text" value={authToken} onChange={e => setAuthToken(e.target.value)}
                                className="flex h-10 w-full rounded-md border bg-background px-3" placeholder="Bearer ..." />
                        </div>
                        <div className="space-y-2">
                            <Label>Secondary Token (For BOLA)</Label>
                            <input type="text" value={authSecondary} onChange={e => setAuthSecondary(e.target.value)}
                                className="flex h-10 w-full rounded-md border bg-background px-3" placeholder="Bearer ... (Different User)" />
                        </div>
                    </div>
                    {error && <p className="text-red-500 text-sm">{error}</p>}
                    <Button onClick={handleStartScan} disabled={starting} className="w-full md:w-auto bg-blue-600 hover:bg-blue-700">
                        {starting ? "Initializing..." : <><Play className="mr-2 h-4 w-4" /> Start Attack Simulation</>}
                    </Button>
                </CardContent>
            </Card>
        );
    }

    // Render: Console View
    return (
        <div className="space-y-6">
            {/* 1. Quick Stats & Graphs */}
            {findings.length > 0 && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 animate-in fade-in zoom-in duration-500">
                    <Card className="md:col-span-1 bg-gradient-to-br from-red-50 to-white dark:from-red-950/20 dark:to-slate-900 border-red-100">
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-bold flex items-center gap-2 text-red-600">
                                <AlertTriangle className="h-4 w-4" /> Risk Profile
                            </CardTitle>
                        </CardHeader>
                        <CardContent className="h-[200px]">
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={(() => {
                                            const counts: any = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
                                            findings.forEach(f => counts[f.severity.toUpperCase()]++);
                                            return Object.entries(counts).map(([name, value]) => ({
                                                name, value,
                                                color: name === 'CRITICAL' ? '#ef4444' : name === 'HIGH' ? '#f97316' : name === 'MEDIUM' ? '#eab308' : '#3b82f6'
                                            })).filter(d => d.value > 0);
                                        })()}
                                        innerRadius={40} outerRadius={60} paddingAngle={5} dataKey="value"
                                    >
                                        {findings.length > 0 && [0, 1, 2, 3, 4].map((i) => <Cell key={i} />)}
                                    </Pie>
                                    <Tooltip />
                                </PieChart>
                            </ResponsiveContainer>
                        </CardContent>
                    </Card>

                    <Card className="md:col-span-2">
                        <CardHeader className="pb-2">
                            <CardTitle className="text-sm font-bold flex items-center gap-2">
                                <BarChart3 className="h-4 w-4 text-blue-500" /> Vulnerability Types
                            </CardTitle>
                        </CardHeader>
                        <CardContent className="h-[200px]">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={(() => {
                                    const types: any = {};
                                    findings.forEach(f => types[f.title] = (types[f.title] || 0) + 1);
                                    return Object.entries(types).map(([name, value]) => ({ name, value }));
                                })()}>
                                    <XAxis dataKey="name" hide />
                                    <Tooltip />
                                    <Bar dataKey="value" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                                </BarChart>
                            </ResponsiveContainer>
                        </CardContent>
                    </Card>
                </div>
            )}

            {/* Status Bar */}
            <div className="flex items-center justify-between bg-card p-4 rounded-lg border shadow-sm">
                <div className="flex items-center gap-4">
                    <div className={`p-2 rounded-full ${status === "RUNNING" ? "bg-green-100 text-green-600 animate-pulse" : "bg-slate-100"}`}>
                        <Terminal className="h-6 w-6" />
                    </div>
                    <div>
                        <h3 className="font-semibold">Attack Session Active</h3>
                        <p className="text-sm text-muted-foreground">ID: {dynamicSessionId} • Status: <span className="font-mono text-blue-600">{status}</span></p>
                    </div>
                </div>
                <div className="text-right">
                    <div className="text-2xl font-bold">{testCases.length}</div>
                    <div className="text-xs text-muted-foreground">Test Cases</div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[600px]">
                {/* Queue List */}
                <Card className="col-span-1 flex flex-col overflow-hidden border-slate-200 shadow-md">
                    <CardHeader className="py-3 bg-slate-50 border-b">
                        <CardTitle className="text-sm font-medium">Execution Queue</CardTitle>
                    </CardHeader>
                    <div className="flex-1 overflow-y-auto">
                        {testCases.map((tc) => (
                            <div key={tc.id}
                                onClick={() => setSelectedCase(tc)}
                                className={`p-3 border-b cursor-pointer hover:bg-slate-50 transition-colors ${selectedCase?.id === tc.id ? "bg-blue-50 border-l-4 border-l-blue-500" : ""}`}>
                                <div className="flex justify-between items-center mb-1">
                                    <span className="font-bold text-xs">{tc.check_type}</span>
                                    <Badge variant={tc.status === "EXECUTED" ? "outline" : "secondary"} className="text-[10px] h-5">
                                        {tc.status}
                                    </Badge>
                                </div>
                                <div className="text-xs font-mono truncate text-slate-600">
                                    {tc.method} {tc.endpoint_path}
                                </div>
                            </div>
                        ))}
                    </div>
                </Card>

                {/* Terminal */}
                <Card className="col-span-2 flex flex-col overflow-hidden bg-slate-950 text-green-400 border-slate-800 shadow-xl">
                    <CardHeader className="py-2 bg-slate-900 border-b border-slate-800 flex flex-row justify-between items-center">
                        <span className="text-xs font-mono">root@apex-engine:~# view_logs</span>
                        <span className="text-xs text-slate-500">{selectedCase?.id || "waiting..."}</span>
                    </CardHeader>
                    <div className="flex-1 overflow-y-auto p-4 font-mono text-xs custom-scrollbar">
                        {selectedCase ? (
                            <pre className="whitespace-pre-wrap leading-relaxed">{selectedCase.logs || "> No logs available yet."}</pre>
                        ) : (
                            <div className="flex flex-col items-center justify-center h-full text-slate-700">
                                <Terminal className="h-12 w-12 mb-2 opacity-20" />
                                <p>Select a test case to inspect attack payload.</p>
                            </div>
                        )}
                        <div ref={terminalEndRef} />
                    </div>
                </Card>
            </div>

            {/* Verified Findings */}
            {findings.length > 0 && (
                <div className="space-y-4 pt-6 border-t">
                    <h3 className="text-xl font-bold flex items-center gap-2">
                        <CheckCircle className="text-green-500" /> Verified Vulnerabilities
                    </h3>

                    <div className="grid grid-cols-1 gap-4">
                        {(() => {
                            // Aggregation logic
                            const groups: { [key: string]: any } = {};
                            findings.forEach(f => {
                                const title = f.title.trim();
                                if (!groups[title]) {
                                    groups[title] = {
                                        ...f,
                                        title: title,
                                        endpoints: new Set([`${f.method} ${f.endpoint_path}`])
                                    };
                                } else {
                                    groups[title].endpoints.add(`${f.method} ${f.endpoint_path}`);
                                }
                            });

                            // Sorting Logic
                            const severityOrder: { [key: string]: number } = {
                                "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4
                            };

                            const sortedGroups = Object.values(groups).sort((a, b) => {
                                const orderA = severityOrder[a.severity?.toUpperCase()] ?? 99;
                                const orderB = severityOrder[b.severity?.toUpperCase()] ?? 99;
                                return orderA - orderB;
                            });

                            return sortedGroups.map(f => (
                                <Card key={f.title} className="border-red-200 bg-red-50/50 overflow-hidden">
                                    <div className="flex flex-col md:flex-row">
                                        <div className="p-4 flex-1">
                                            <div className="flex justify-between items-start mb-2">
                                                <CardTitle className="text-lg text-red-700">{f.title}</CardTitle>
                                                <Badge variant="destructive" className="ml-2">{f.severity}</Badge>
                                            </div>
                                            <p className="text-sm text-slate-700 mb-4">{f.description}</p>

                                            <div className="space-y-2">
                                                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500">Affected Endpoints</h4>
                                                <div className="flex flex-wrap gap-2">
                                                    {Array.from(f.endpoints).map((ep: any) => (
                                                        <Badge key={ep} variant="outline" className="bg-white font-mono text-[10px]">
                                                            {ep}
                                                        </Badge>
                                                    ))}
                                                </div>
                                            </div>
                                        </div>

                                        {f.remediation && (
                                            <div className="bg-white/50 p-4 border-t md:border-t-0 md:border-l border-red-100 md:w-1/3">
                                                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1">
                                                    <Shield className="h-3 w-3" /> Remediation
                                                </h4>
                                                <p className="text-xs text-slate-600 italic">
                                                    {f.remediation}
                                                </p>
                                            </div>
                                        )}
                                    </div>
                                </Card>
                            ));
                        })()}
                    </div>
                </div>
            )}
        </div>
    );
}
