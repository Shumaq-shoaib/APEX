import { useState, useEffect, useRef, useMemo } from "react";
import {
    Shield, Play, Terminal, Lock, Activity, Download, Upload,
    AlertTriangle, RotateCcw, ChevronDown, FileText,
    ArrowUpDown, Search, X, Info, Wrench, CheckCircle2, Eye
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import {
    Card, CardContent, CardDescription, CardHeader, CardTitle,
} from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
    ResizablePanelGroup, ResizablePanel, ResizableHandle
} from "@/components/ui/resizable";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import {
    DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger
} from "@/components/ui/dropdown-menu";
import { API_BASE_URL } from "@/lib/config";
import { TestCase, Finding } from "@/types/api";

interface DynamicConsoleProps {
    specId?: string;
    defaultTargetUrl: string;
    initialSessionId?: string;
}

type SessionStatus = "PENDING" | "RUNNING" | "COMPLETED" | "FAILED";
type SeverityFilter = "all" | "Critical" | "High" | "Medium" | "Low";

const SEVERITY_ORDER: Record<string, number> = {
    Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4, Informational: 4
};

function normalizeSeverity(s: string): string {
    return s === "Informational" ? "Low" : s;
}

export default function DynamicConsole({ specId, defaultTargetUrl, initialSessionId }: DynamicConsoleProps) {
    const [targetUrl, setTargetUrl] = useState(defaultTargetUrl);
    const [authToken, setAuthToken] = useState("");
    const [specFile, setSpecFile] = useState<File | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const [dynamicSessionId, setDynamicSessionId] = useState<string | null>(initialSessionId || null);
    const [dynamicStatus, setDynamicStatus] = useState<SessionStatus | null>(initialSessionId ? "RUNNING" : null);
    const [testCases, setTestCases] = useState<TestCase[]>([]);
    const [dynamicFindings, setDynamicFindings] = useState<Finding[]>([]);
    const [polling, setPolling] = useState(!!initialSessionId);
    const [selectedCase, setSelectedCase] = useState<TestCase | null>(null);
    const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
    const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
    const [searchQuery, setSearchQuery] = useState("");
    const [errorMessage, setErrorMessage] = useState<string | null>(null);
    const [pollFailCount, setPollFailCount] = useState(0);
    const terminalEndRef = useRef<HTMLDivElement>(null);

    const confirmedExploits = useMemo(() => {
        return dynamicFindings.filter(f => {
            const cvss = typeof f.cvss_score === "string" ? parseFloat(f.cvss_score) : (f.cvss_score ?? 0);
            return cvss > 0;
        });
    }, [dynamicFindings]);

    const unverifiedFindings = useMemo(() => {
        return dynamicFindings.filter(f => {
            const cvss = typeof f.cvss_score === "string" ? parseFloat(f.cvss_score) : (f.cvss_score ?? 0);
            return cvss <= 0;
        });
    }, [dynamicFindings]);

    const filteredExploits = useMemo(() => {
        let results = [...confirmedExploits];
        if (severityFilter !== "all") {
            results = results.filter(f => f.severity === severityFilter);
        }
        if (searchQuery.trim()) {
            const q = searchQuery.toLowerCase();
            results = results.filter(f =>
                f.title.toLowerCase().includes(q) ||
                f.endpoint_path?.toLowerCase().includes(q) ||
                f.check_type?.toLowerCase().includes(q)
            );
        }
        results.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));
        return results;
    }, [confirmedExploits, severityFilter, searchQuery]);

    const severityCounts = useMemo(() => {
        const counts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
        confirmedExploits.forEach(f => {
            const key = f.severity === "Informational" ? "Low" : f.severity;
            if (key in counts) counts[key] = (counts[key] || 0) + 1;
        });
        return counts;
    }, [confirmedExploits]);

    useEffect(() => {
        let interval: NodeJS.Timeout;
        const controller = new AbortController();

        if (polling && dynamicSessionId) {
            interval = setInterval(async () => {
                try {
                    const res = await fetch(
                        `${API_BASE_URL}/api/sessions/${dynamicSessionId}/`,
                        { signal: controller.signal }
                    );
                    if (res.ok) {
                        const data = await res.json();
                        setPollFailCount(0);
                        setDynamicStatus(data.status);
                        setTestCases(data.test_cases || []);

                        if (selectedCase) {
                            const updated = data.test_cases?.find((tc: TestCase) => tc.id === selectedCase.id);
                            if (updated) setSelectedCase(updated);
                        }

                        const incoming = (data.findings || []).map((f: Finding) => ({
                            ...f,
                            severity: normalizeSeverity(f.severity)
                        }));
                        if (incoming.length > 0) setDynamicFindings(incoming);

                        if (data.status === "COMPLETED" || data.status === "FAILED") {
                            setDynamicFindings(incoming);
                            if (data.status === "FAILED") {
                                setErrorMessage(data.error_message || "Scan failed. Check scanner logs for details.");
                            }
                            setPolling(false);
                        }
                    } else {
                        setPollFailCount(c => c + 1);
                    }
                } catch (e: unknown) {
                    if (!(e instanceof DOMException && e.name === "AbortError")) {
                        setPollFailCount(c => c + 1);
                    }
                }
            }, 1500);
        }
        return () => { clearInterval(interval); controller.abort(); };
    }, [polling, dynamicSessionId, selectedCase]);

    useEffect(() => {
        if (terminalEndRef.current) terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }, [selectedCase?.logs]);

    const startDynamicScan = async () => {
        if (!targetUrl.trim()) {
            setError("Target URL is required.");
            return;
        }
        try {
            setLoading(true);
            setError(null);
            setErrorMessage(null);

            let sessionData: { id: string; spec_id: string };

            if (specId) {
                const res1 = await fetch(`${API_BASE_URL}/api/sessions/`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ spec_id: specId, target_url: targetUrl, auth_token: authToken || null })
                });
                if (!res1.ok) throw new Error("Failed to create session");
                sessionData = await res1.json();

                const res2 = await fetch(`${API_BASE_URL}/api/sessions/${sessionData.id}/start/`, { method: "POST" });
                if (!res2.ok) throw new Error("Failed to start scan");
            } else if (specFile) {
                const formData = new FormData();
                formData.append("file", specFile);
                formData.append("target_url", targetUrl);
                if (authToken) formData.append("auth_token", authToken);
                const res = await fetch(`${API_BASE_URL}/api/sessions/direct`, { method: "POST", body: formData });
                if (!res.ok) throw new Error("Failed to launch scan with spec file");
                sessionData = await res.json();
            } else {
                const res = await fetch(`${API_BASE_URL}/api/sessions/quick`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ target_url: targetUrl, auth_token: authToken || null })
                });
                if (!res.ok) throw new Error("Failed to launch quick scan");
                sessionData = await res.json();
            }

            setDynamicSessionId(sessionData.id);
            setDynamicStatus("PENDING");
            setPolling(true);
            setTestCases([]);
            setDynamicFindings([]);
            setSelectedCase(null);
            setSelectedFinding(null);
            setPollFailCount(0);
        } catch (e: unknown) {
            setError(e instanceof Error ? e.message : "Failed to start scan");
        } finally {
            setLoading(false);
        }
    };

    const handleRetry = () => {
        setDynamicSessionId(null);
        setDynamicStatus(null);
        setTestCases([]);
        setDynamicFindings([]);
        setSelectedCase(null);
        setSelectedFinding(null);
        setErrorMessage(null);
        setError(null);
        setPollFailCount(0);
    };

    const downloadReport = (format: "html" | "pdf") => {
        if (!dynamicSessionId) return;
        window.open(`${API_BASE_URL}/api/sessions/${dynamicSessionId}/report?format=${format}`, "_blank");
    };

    // ---------- Config View ----------
    if (!dynamicSessionId) {
        return (
            <div className="flex flex-col items-center justify-center p-8 space-y-6 max-w-2xl mx-auto">
                <div className="text-center space-y-2">
                    <div className="bg-primary/10 p-4 rounded-full inline-block mb-2">
                        <Terminal className="h-8 w-8 text-primary" />
                    </div>
                    <h2 className="text-2xl font-bold">Dynamic Analysis</h2>
                    <p className="text-muted-foreground">
                        Launch active security probes against a running API to discover real vulnerabilities.
                    </p>
                </div>

                <Card className="w-full">
                    <CardContent className="space-y-4 pt-6">
                        <div className="space-y-2">
                            <Label htmlFor="targetUrl">Target URL <span className="text-destructive">*</span></Label>
                            <Input
                                id="targetUrl"
                                value={targetUrl}
                                onChange={(e) => setTargetUrl(e.target.value)}
                                placeholder="http://host.docker.internal:8888"
                            />
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

                        {!specId && (
                            <div className="space-y-2">
                                <Label className="flex items-center gap-2">
                                    <Upload className="h-3 w-3" /> OpenAPI Spec (Optional)
                                </Label>
                                <div className="border border-dashed rounded-lg p-4 flex items-center justify-center text-center">
                                    <Input
                                        type="file"
                                        accept=".json,.yaml,.yml"
                                        className="hidden"
                                        id="spec-upload-dynamic"
                                        onChange={(e) => setSpecFile(e.target.files?.[0] || null)}
                                    />
                                    <label htmlFor="spec-upload-dynamic" className="cursor-pointer text-sm text-muted-foreground hover:text-foreground transition-colors">
                                        {specFile ? (
                                            <span className="text-green-600 font-medium">{specFile.name}</span>
                                        ) : (
                                            <span>Upload a spec for targeted scanning, or leave empty for quick scan</span>
                                        )}
                                    </label>
                                </div>
                                <p className="text-xs text-muted-foreground">
                                    Providing a spec enables endpoint-specific testing. Without it, APEX will auto-discover endpoints using its built-in crawler.
                                </p>
                            </div>
                        )}

                        {specId && (
                            <div className="bg-muted/50 rounded-lg p-3 flex items-center gap-2 text-xs">
                                <CheckCircle2 className="h-4 w-4 text-green-600 shrink-0" />
                                <span>API Specification loaded from Static Analysis. Endpoints will be tested precisely.</span>
                            </div>
                        )}

                        {error && <p className="text-sm text-destructive font-medium">{error}</p>}

                        <Button onClick={startDynamicScan} disabled={loading || !targetUrl.trim()} className="w-full">
                            {loading ? (
                                <>Starting Engine...</>
                            ) : (
                                <><Play className="mr-2 h-4 w-4" /> Start Dynamic Analysis</>
                            )}
                        </Button>
                    </CardContent>
                </Card>
            </div>
        );
    }

    // ---------- Execution View ----------
    return (
        <div className="flex flex-col gap-4 h-full overflow-hidden">
            {/* Error Banner */}
            {dynamicStatus === "FAILED" && errorMessage && (
                <Alert variant="destructive" className="shrink-0">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertTitle>Scan Failed</AlertTitle>
                    <AlertDescription className="flex items-center justify-between">
                        <span>{errorMessage}</span>
                        <Button variant="outline" size="sm" onClick={handleRetry} className="ml-4 shrink-0">
                            <RotateCcw className="mr-2 h-3 w-3" /> Retry
                        </Button>
                    </AlertDescription>
                </Alert>
            )}

            {pollFailCount >= 5 && polling && (
                <Alert variant="destructive" className="shrink-0">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertTitle>Connection Lost</AlertTitle>
                    <AlertDescription>Unable to reach the scanner backend. Retrying automatically...</AlertDescription>
                </Alert>
            )}

            {/* Status Header */}
            <Card className="shrink-0">
                <CardHeader className="py-3">
                    <div className="flex items-center justify-between">
                        <div className="space-y-1">
                            <CardTitle className="text-lg flex items-center gap-2">
                                <Activity className="h-5 w-5 text-primary" />
                                Scan Status:
                                <span className={
                                    dynamicStatus === "RUNNING" ? "text-primary animate-pulse" :
                                    dynamicStatus === "COMPLETED" ? "text-green-600" :
                                    dynamicStatus === "FAILED" ? "text-destructive" : ""
                                }>
                                    {dynamicStatus}
                                </span>
                            </CardTitle>
                            <CardDescription className="font-mono text-xs">Session: {dynamicSessionId}</CardDescription>
                        </div>
                        <div className="flex items-center gap-4">
                            {dynamicStatus === "COMPLETED" && (
                                <DropdownMenu>
                                    <DropdownMenuTrigger asChild>
                                        <Button variant="outline" size="sm">
                                            <Download className="mr-2 h-4 w-4" /> Export Report <ChevronDown className="ml-2 h-3 w-3" />
                                        </Button>
                                    </DropdownMenuTrigger>
                                    <DropdownMenuContent>
                                        <DropdownMenuItem onClick={() => downloadReport("pdf")}>
                                            <FileText className="mr-2 h-4 w-4" /> Download PDF
                                        </DropdownMenuItem>
                                        <DropdownMenuItem onClick={() => downloadReport("html")}>
                                            <FileText className="mr-2 h-4 w-4" /> Download HTML
                                        </DropdownMenuItem>
                                    </DropdownMenuContent>
                                </DropdownMenu>
                            )}
                            <div className="text-right">
                                <div className="text-2xl font-bold font-mono">{testCases.length}</div>
                                <div className="text-xs text-muted-foreground">Test Cases</div>
                            </div>
                            <div className="text-right">
                                <div className="text-2xl font-bold font-mono text-destructive">{confirmedExploits.length}</div>
                                <div className="text-xs text-muted-foreground">Exploits</div>
                            </div>
                        </div>
                    </div>
                </CardHeader>
            </Card>

            {/* Scrollable content area */}
            <div className="flex-1 overflow-y-auto space-y-4 pb-4">
                {/* Console Layout */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 h-[450px]">
                    <Card className="col-span-1 flex flex-col overflow-hidden border-2">
                        <CardHeader className="py-3 border-b bg-muted/40 shrink-0">
                            <CardTitle className="text-sm font-medium">Test Queue</CardTitle>
                        </CardHeader>
                        <ScrollArea className="flex-1">
                            <div className="divide-y">
                                {testCases.map((tc: TestCase) => (
                                    <div key={tc.id} onClick={() => setSelectedCase(tc)}
                                        className={`p-3 cursor-pointer transition-colors hover:bg-muted/60 text-sm ${
                                            selectedCase?.id === tc.id ? "bg-muted border-l-4 border-l-primary" : "border-l-4 border-l-transparent"
                                        }`}>
                                        <div className="flex justify-between items-center mb-1">
                                            <span className="font-semibold text-xs uppercase tracking-wider">{tc.check_type}</span>
                                            <Badge variant={tc.status === "EXECUTED" ? "outline" : "secondary"} className="text-[10px] h-5">{tc.status}</Badge>
                                        </div>
                                        <div className="text-xs text-muted-foreground truncate font-mono" title={`${tc.method} ${tc.endpoint_path}`}>
                                            {tc.method} {tc.endpoint_path}
                                        </div>
                                    </div>
                                ))}
                                {testCases.length === 0 && (
                                    <div className="p-8 text-center text-xs text-muted-foreground">
                                        {dynamicStatus === "RUNNING" ? (
                                            <div className="flex flex-col items-center gap-2"><Activity className="h-5 w-5 animate-spin" />Discovering API endpoints...</div>
                                        ) : "Waiting for scan to start..."}
                                    </div>
                                )}
                            </div>
                        </ScrollArea>
                    </Card>

                    <Card className="col-span-2 flex flex-col overflow-hidden bg-black text-green-400 font-mono text-xs shadow-inner border-gray-800">
                        <CardHeader className="py-2 border-b border-green-900/30 bg-gray-900/50 shrink-0">
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
                                        <div ref={terminalEndRef} />
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

                {/* Section 1: Confirmed Exploits */}
                {(confirmedExploits.length > 0 || dynamicStatus === "COMPLETED") && (
                    <div className="space-y-3">
                        <div className="flex items-center justify-between flex-wrap gap-2">
                            <div className="flex items-center gap-2">
                                <Shield className="h-5 w-5 text-destructive" />
                                <h3 className="text-lg font-semibold">Confirmed Exploits</h3>
                                <Badge variant="destructive" className="ml-1">{confirmedExploits.length}</Badge>
                            </div>
                            <div className="flex items-center gap-2">
                                <div className="flex gap-1">
                                    <Button variant={severityFilter === "all" ? "default" : "outline"} size="sm" className="h-7 text-xs" onClick={() => setSeverityFilter("all")}>All</Button>
                                    {(["Critical", "High", "Medium", "Low"] as const).map(sev => (
                                        severityCounts[sev] > 0 && (
                                            <Button key={sev} variant={severityFilter === sev ? "default" : "outline"} size="sm"
                                                className={`h-7 text-xs ${severityFilter === sev ? (
                                                    sev === "Critical" || sev === "High" ? "bg-destructive text-destructive-foreground hover:bg-destructive/90" :
                                                    sev === "Medium" ? "bg-orange-500 text-white hover:bg-orange-600" :
                                                    "bg-yellow-500 text-black hover:bg-yellow-600"
                                                ) : ""}`}
                                                onClick={() => setSeverityFilter(sev)}>
                                                {sev} ({severityCounts[sev]})
                                            </Button>
                                        )
                                    ))}
                                </div>
                                <div className="relative">
                                    <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground" />
                                    <Input placeholder="Filter..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)} className="h-7 text-xs pl-7 w-40" />
                                    {searchQuery && (<button onClick={() => setSearchQuery("")} className="absolute right-2 top-1/2 -translate-y-1/2"><X className="h-3 w-3 text-muted-foreground hover:text-foreground" /></button>)}
                                </div>
                            </div>
                        </div>

                        <div className="border rounded-lg overflow-hidden h-[420px]">
                            <ResizablePanelGroup direction="horizontal">
                                <ResizablePanel defaultSize={40} minSize={25}>
                                    <div className="flex flex-col h-full">
                                        <div className="px-3 py-2 border-b bg-muted/40 text-xs font-medium text-muted-foreground flex items-center gap-2 shrink-0">
                                            <ArrowUpDown className="h-3 w-3" /> {filteredExploits.length} exploit(s)
                                        </div>
                                        <ScrollArea className="flex-1">
                                            <div className="divide-y">
                                                {filteredExploits.map((finding) => (
                                                    <div key={finding.id} onClick={() => setSelectedFinding(finding)}
                                                        className={`p-3 cursor-pointer transition-colors hover:bg-muted/60 ${
                                                            selectedFinding?.id === finding.id ? "bg-muted border-l-4 border-l-primary" : "border-l-4 border-l-transparent"
                                                        }`}>
                                                        <div className="flex justify-between items-start gap-2 mb-1">
                                                            <span className="text-sm font-medium leading-tight line-clamp-2">{finding.title}</span>
                                                            <Badge variant={finding.severity === "Critical" || finding.severity === "High" ? "destructive" : "secondary"} className="text-[10px] h-5 shrink-0">{finding.severity}</Badge>
                                                        </div>
                                                        <div className="flex items-center gap-2 text-[10px] text-muted-foreground font-mono"><span>{finding.method} {finding.endpoint_path}</span></div>
                                                        <div className="flex items-center gap-3 mt-1 text-[10px] text-muted-foreground">
                                                            {finding.check_type && <span className="uppercase tracking-wider">{finding.check_type}</span>}
                                                            <span className="font-semibold">CVSS: {finding.cvss_score}</span>
                                                        </div>
                                                    </div>
                                                ))}
                                                {filteredExploits.length === 0 && confirmedExploits.length > 0 && (
                                                    <div className="p-8 text-center text-xs text-muted-foreground">No exploits match the current filter.</div>
                                                )}
                                                {confirmedExploits.length === 0 && (
                                                    <div className="p-8 text-center text-xs text-muted-foreground">No confirmed exploits found.</div>
                                                )}
                                            </div>
                                        </ScrollArea>
                                    </div>
                                </ResizablePanel>

                                <ResizableHandle withHandle />

                                <ResizablePanel defaultSize={60} minSize={30}>
                                    {selectedFinding ? (
                                        <div className="flex flex-col h-full">
                                            <div className="p-4 border-b bg-muted/20 space-y-2 shrink-0">
                                                <div className="flex items-start justify-between gap-3">
                                                    <h4 className="text-sm font-semibold leading-tight">{selectedFinding.title}</h4>
                                                    <div className="flex items-center gap-2 shrink-0">
                                                        <Badge variant={selectedFinding.severity === "Critical" || selectedFinding.severity === "High" ? "destructive" : "secondary"}>{selectedFinding.severity}</Badge>
                                                        <Badge variant="outline">CVSS {selectedFinding.cvss_score}</Badge>
                                                    </div>
                                                </div>
                                                <div className="flex flex-wrap gap-2 text-[11px] text-muted-foreground font-mono">
                                                    <span className="bg-muted px-2 py-0.5 rounded">{selectedFinding.method} {selectedFinding.endpoint_path}</span>
                                                    {selectedFinding.check_type && <span className="bg-muted px-2 py-0.5 rounded uppercase">{selectedFinding.check_type}</span>}
                                                </div>
                                                {selectedFinding.description && <p className="text-xs text-muted-foreground leading-relaxed">{selectedFinding.description}</p>}
                                            </div>
                                            <Tabs defaultValue="request" className="flex-1 flex flex-col min-h-0">
                                                <div className="border-b px-4 shrink-0">
                                                    <TabsList className="h-9 bg-transparent p-0 gap-4">
                                                        <TabsTrigger value="request" className="text-xs data-[state=active]:shadow-none data-[state=active]:border-b-2 data-[state=active]:border-primary rounded-none px-1 pb-2">Request</TabsTrigger>
                                                        <TabsTrigger value="response" className="text-xs data-[state=active]:shadow-none data-[state=active]:border-b-2 data-[state=active]:border-primary rounded-none px-1 pb-2">Response</TabsTrigger>
                                                        <TabsTrigger value="remediation" className="text-xs data-[state=active]:shadow-none data-[state=active]:border-b-2 data-[state=active]:border-primary rounded-none px-1 pb-2"><Wrench className="h-3 w-3 mr-1" />Remediation</TabsTrigger>
                                                    </TabsList>
                                                </div>
                                                <TabsContent value="request" className="flex-1 m-0 min-h-0 overflow-auto">
                                                    <div className="bg-zinc-950 text-green-400 font-mono text-xs p-4 min-h-full">
                                                        <pre className="whitespace-pre-wrap leading-relaxed">{selectedFinding.evidence?.request_dump || "No request data captured."}</pre>
                                                    </div>
                                                </TabsContent>
                                                <TabsContent value="response" className="flex-1 m-0 min-h-0 overflow-auto">
                                                    <div className="bg-zinc-950 text-amber-400 font-mono text-xs p-4 min-h-full">
                                                        <pre className="whitespace-pre-wrap leading-relaxed">{selectedFinding.evidence?.response_dump || "No response data captured."}</pre>
                                                    </div>
                                                </TabsContent>
                                                <TabsContent value="remediation" className="flex-1 m-0 min-h-0 overflow-auto">
                                                    <div className="p-4 space-y-3">
                                                        <div className="flex items-center gap-2 text-sm font-medium"><Info className="h-4 w-4 text-blue-500" />Remediation Guidance</div>
                                                        <div className="bg-blue-50 dark:bg-blue-950/30 border border-blue-200 dark:border-blue-900 rounded-lg p-4">
                                                            <pre className="text-xs leading-relaxed whitespace-pre-wrap text-foreground">{selectedFinding.remediation || "No specific remediation advice available."}</pre>
                                                        </div>
                                                    </div>
                                                </TabsContent>
                                            </Tabs>
                                        </div>
                                    ) : (
                                        <div className="flex flex-col items-center justify-center h-full text-muted-foreground/50 gap-3">
                                            <Shield className="h-10 w-10" />
                                            <p className="text-sm">Select an exploit to view evidence</p>
                                            <p className="text-xs">Click any vulnerability on the left to inspect the HTTP request/response</p>
                                        </div>
                                    )}
                                </ResizablePanel>
                            </ResizablePanelGroup>
                        </div>
                    </div>
                )}

                {/* Section 2: Unverified / Low-confidence findings (collapsed by default) */}
                {unverifiedFindings.length > 0 && dynamicStatus === "COMPLETED" && (
                    <details className="group border rounded-lg">
                        <summary className="flex items-center justify-between p-4 cursor-pointer hover:bg-muted/40 transition-colors">
                            <div className="flex items-center gap-2">
                                <Eye className="h-4 w-4 text-muted-foreground" />
                                <span className="text-sm font-medium text-muted-foreground">Additional Observations</span>
                                <Badge variant="outline" className="text-xs">{unverifiedFindings.length}</Badge>
                            </div>
                            <span className="text-xs text-muted-foreground">These findings could not be confirmed with a CVSS score. Click to expand.</span>
                        </summary>
                        <div className="border-t divide-y max-h-[300px] overflow-y-auto">
                            {unverifiedFindings.map(f => (
                                <div key={f.id} className="p-3 text-sm">
                                    <div className="flex justify-between items-start gap-2">
                                        <span className="font-medium text-muted-foreground">{f.title}</span>
                                        <Badge variant="outline" className="text-[10px] shrink-0">{f.check_type}</Badge>
                                    </div>
                                    <div className="text-xs text-muted-foreground font-mono mt-1">{f.method} {f.endpoint_path}</div>
                                    {f.description && <p className="text-xs text-muted-foreground/70 mt-1 line-clamp-2">{f.description}</p>}
                                </div>
                            ))}
                        </div>
                    </details>
                )}
            </div>
        </div>
    );
}
