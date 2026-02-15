import { useState, useEffect } from "react";
import {
  Accordion, AccordionContent, AccordionItem, AccordionTrigger,
} from "@/components/ui/accordion";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Card, CardContent, CardDescription, CardHeader, CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer,
} from "recharts";
import { Upload, Shield, AlertTriangle, Info, FileText } from "lucide-react";

// Color mapping
const severityColors = {
  Critical: "hsl(var(--critical))",
  High: "hsl(var(--high))",
  Medium: "hsl(var(--medium))",
  Low: "hsl(var(--low))",
  Informational: "hsl(var(--informational))",
};

// Icon mapping
const severityIcons = {
  Critical: AlertTriangle,
  High: AlertTriangle,
  Medium: Info,
  Low: Info,
  Informational: Info,
};

export default function Dashboard() {
  const [analysisData, setAnalysisData] = useState<any | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // History Specs Logic
  const [historySpecs, setHistorySpecs] = useState<any[]>([]);
  const [activeTab, setActiveTab] = useState("new");

  // Advanced Options State
  const [profile, setProfile] = useState("default");
  const [failOn, setFailOn] = useState("none");
  const [policyFile, setPolicyFile] = useState<File | null>(null);
  const [spectralFile, setSpectralFile] = useState<File | null>(null);
  const [generateBlueprint, setGenerateBlueprint] = useState(false);

  // Fetch History
  const fetchHistory = async () => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/specs");
      if (res.ok) {
        const data = await res.json();
        setHistorySpecs(data);
      }
    } catch (e) {
      console.error("Failed to fetch history", e);
    }
  };

  useEffect(() => {
    fetchHistory();
    const interval = setInterval(fetchHistory, 5000);
    return () => clearInterval(interval);
  }, []);

  // Dynamic Analysis State
  const [dynamicSessionId, setDynamicSessionId] = useState<string | null>(null);
  const [dynamicStatus, setDynamicStatus] = useState<string | null>(null);
  const [dynamicFindings, setDynamicFindings] = useState<any[]>([]);
  const [polling, setPolling] = useState(false);
  const [targetUrl, setTargetUrl] = useState("http://localhost:8888");
  const [authToken, setAuthToken] = useState("");
  const [authSecondaryToken, setAuthSecondaryToken] = useState(""); // For BOLA

  // Hacker Console State
  const [selectedCase, setSelectedCase] = useState<any>(null);
  const [testCases, setTestCases] = useState<any[]>([]);

  // Poll Dynamic Session
  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (polling && dynamicSessionId) {
      interval = setInterval(async () => {
        try {
          const res = await fetch(`http://127.0.0.1:8000/api/sessions/${dynamicSessionId}`);
          if (res.ok) {
            const data = await res.json();
            setDynamicStatus(data.status);
            setTestCases(data.test_cases || []);

            if (data.status === "COMPLETED" || data.status === "FAILED") {
              setDynamicFindings(data.findings || []);
              setPolling(false);
            }
          }
        } catch (e) {
          console.error("Polling error", e);
        }
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [polling, dynamicSessionId]);

  // Handle Tab Load for Dynamic Info
  const handleTabChange = async (val: string) => {
    setActiveTab(val);
    setError(null);
    setDynamicSessionId(null);
    setDynamicStatus(null);
    setDynamicFindings([]);
    setPolling(false);

    if (val === "new") {
      setAnalysisData(null);
      return;
    }

    setLoading(true);
    setAnalysisData(null);
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/specs/${val}`);
      if (!res.ok) throw new Error("Failed to load spec details");
      const data = await res.json();
      setAnalysisData(data);
      if (data.metadata?.server_url) {
        setTargetUrl(data.metadata.server_url);
      } else {
        setTargetUrl("http://localhost:8888");
      }

      // Check if dynamic session exists
      if (data.dynamic_session_id) {
        setDynamicSessionId(data.dynamic_session_id);
        // Start polling immediately to get status/results
        setPolling(true);
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setSelectedFile(file);
    setLoading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("profile", profile);
      formData.append("fail_on", failOn);
      formData.append("generate_blueprint", generateBlueprint.toString());
      if (policyFile) formData.append("policy_pack", policyFile);
      if (spectralFile) formData.append("spectral_in", spectralFile);

      const response = await fetch("http://127.0.0.1:8000/api/specs", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) throw new Error("Analysis failed");

      const result = await response.json();

      // Refresh history and switch tab
      await fetchHistory();
      if (result.spec_id) {
        setActiveTab(result.spec_id);
      }
      setAnalysisData(result);
    } catch (err: any) {
      setError(err.message || "Something went wrong");
    } finally {
      setLoading(false);
    }
  };

  const handleDirectScan = async () => {
    if (!selectedFile) {
      setError("Please select an OpenAPI file first.");
      return;
    }
    setLoading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append("file", selectedFile);
      formData.append("target_url", targetUrl);
      if (authToken) formData.append("auth_token", authToken);
      if (authSecondaryToken) formData.append("auth_token_secondary", authSecondaryToken);

      const response = await fetch("http://127.0.0.1:8000/api/sessions/direct", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errText = await response.text();
        throw new Error(`Scan failed to start: ${errText}`);
      }

      const session = await response.json();

      // Refresh history to show the new "Direct Scan" entry
      await fetchHistory();

      // Switch to the new spec tab and LOAD DATA
      if (session.spec_id) {
        // Force data load by triggering our tab change logic
        // Note: setActiveTab triggers the UI tab switch, handleTabChange loads the data.
        // We need both because our current Tabs onValueChange is wired to handleTabChange,
        // but setting state programmatically does NOT trigger the event handler.
        await handleTabChange(session.spec_id);
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityBadgeVariant = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical": return "critical";
      case "high": return "high";
      case "medium": return "medium";
      case "low": return "low";
      case "informational": return "informational";
      default: return "secondary";
    }
  };

  const chartData = analysisData
    ? Object.entries(analysisData.summary)
      .filter(([key]) => key !== "total")
      .map(([severity, count]) => ({
        name: severity,
        value: count as number,
        color: severityColors[severity as keyof typeof severityColors],
      }))
    : [];

  const startDynamicScan = async () => {
    if (!analysisData?.spec_id) return;
    try {
      setLoading(true);
      // 1. Create Session
      // Defaulting target URL to internal container or localhost for demo purposes
      //Ideally user input
      const res1 = await fetch("http://127.0.0.1:8000/api/sessions/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          spec_id: analysisData.spec_id,
          target_url: targetUrl,
          auth_token: authToken || null
        })
      });
      if (!res1.ok) throw new Error("Failed to create session");
      const session = await res1.json();

      // 2. Start Scan
      const res2 = await fetch(`http://127.0.0.1:8000/api/sessions/${session.id}/start`, { method: "POST" });
      if (!res2.ok) throw new Error("Failed to start scan");

      setDynamicSessionId(session.id);
      setDynamicStatus("PENDING");
      setPolling(true);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const renderDynamic = () => {
    if (!dynamicSessionId) {
      return (
        <Card>
          <CardHeader>
            <CardTitle>Dynamic Verification</CardTitle>
            <CardDescription>
              Verify static findings and detecting runtime vulnerabilities (BOLA, Broken Auth).
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col items-center gap-4">
            <Shield className="h-16 w-16 text-muted-foreground opacity-20" />
            <p className="text-sm text-muted-foreground text-center max-w-md">
              No dynamic scan found for this specification. Start a scan to verify vulnerabilities against a running target.
            </p>
            <button
              onClick={startDynamicScan}
              disabled={loading}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
            >
              Start Dynamic Scan
            </button>
            <div className="w-full max-w-sm mt-4">
              <Label htmlFor="targetUrl">Target URL</Label>
              <input
                id="targetUrl"
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                placeholder="http://localhost:8888"
              />
              <p className="text-xs text-muted-foreground mt-1">
                Ensure the backend can reach this URL (e.g. use host.docker.internal for local apps).
              </p>
            </div>
            <div className="w-full max-w-sm mt-4">
              <Label htmlFor="authToken">Auth Token (Optional)</Label>
              <textarea
                id="authToken"
                value={authToken}
                onChange={(e) => setAuthToken(e.target.value)}
                className="flex h-20 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                placeholder="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
              />
              <p className="text-xs text-muted-foreground mt-1">
                Provide a valid JWT/Bearer token to test protected endpoints and BOLA risks.
              </p>
            </div>
          </CardContent>
        </Card>
      );
    }

    return (
      <div className="space-y-6">
        {/* Status Header */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2">
                  Scan Status: {dynamicStatus}
                  {dynamicStatus === "RUNNING" && <span className="flex h-3 w-3 relative">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
                  </span>}
                </CardTitle>
                <CardDescription>Session ID: {dynamicSessionId}</CardDescription>
              </div>
              <div className="text-right">
                <div className="text-2xl font-bold">{testCases.length}</div>
                <div className="text-xs text-muted-foreground">Total Tests</div>
              </div>
            </div>
          </CardHeader>
        </Card>

        {/* Console View */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[500px]">
          {/* Left: Test Case List */}
          <Card className="col-span-1 flex flex-col overflow-hidden">
            <CardHeader className="py-3 border-b bg-muted/30">
              <CardTitle className="text-sm">Execution Queue</CardTitle>
            </CardHeader>
            <div className="flex-1 overflow-y-auto p-0">
              {testCases.map((tc: any) => (
                <div
                  key={tc.id}
                  onClick={() => setSelectedCase(tc)}
                  className={`p-3 border-b cursor-pointer transition-colors hover:bg-muted/50 ${selectedCase?.id === tc.id ? "bg-muted" : ""} text-sm`}
                >
                  <div className="flex justify-between items-center mb-1">
                    <span className="font-semibold">{tc.check_type}</span>
                    <Badge variant={tc.status === "EXECUTED" ? "outline" : "secondary"} className="text-[10px] h-5">
                      {tc.status}
                    </Badge>
                  </div>
                  <div className="text-xs text-muted-foreground truncate font-mono">
                    {tc.method} {tc.endpoint_path}
                  </div>
                  {tc.rule_id && (
                    <div className="mt-1 text-[10px] text-blue-500 flex items-center gap-1">
                      <Shield className="h-3 w-3" /> Verifying: {tc.rule_id}
                    </div>
                  )}
                </div>
              ))}
              {testCases.length === 0 && <div className="p-4 text-center text-xs text-muted-foreground">Queuing tests...</div>}
            </div>
          </Card>

          {/* Right: Logs / Output */}
          <Card className="col-span-2 flex flex-col overflow-hidden bg-black text-green-400 font-mono text-xs">
            <CardHeader className="py-2 border-b border-green-900 bg-gray-900">
              <div className="flex justify-between items-center">
                <CardTitle className="text-sm text-green-500">Terminal Output</CardTitle>
                {selectedCase && <span className="text-gray-500">{selectedCase.id}</span>}
              </div>
            </CardHeader>
            <div className="flex-1 overflow-y-auto p-4 custom-scrollbar">
              {selectedCase ? (
                <pre className="whitespace-pre-wrap leading-relaxed">
                  {selectedCase.logs || "> Waiting for execution logs..."}
                </pre>
              ) : (
                <div className="flex flex-col items-center justify-center h-full text-green-800 opacity-50">
                  <p>Select a test case to view logs.</p>
                </div>
              )}
            </div>
          </Card>
        </div>

        {/* Verified Vulnerabilities (Bottom) */}
        {dynamicFindings.length > 0 && (
          <div className="space-y-4">
            <h3 className="text-lg font-semibold">Verified Vulnerabilities</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {dynamicFindings.map((finding) => (
                <Card
                  key={finding.id}
                  className={`bg-card border-${finding.severity === "High" || finding.severity === "Critical" ? "destructive" : "warning"} cursor-pointer hover:bg-accent/50 transition-colors`}
                  onClick={() => {
                    if (finding.test_case_id) {
                      const linkedCase = testCases?.find((tc: any) => tc.id === finding.test_case_id);
                      if (linkedCase) setSelectedCase(linkedCase);
                    }
                  }}
                >
                  <CardHeader className="pb-2">
                    <div className="flex justify-between items-start">
                      <CardTitle className="text-base font-medium flex items-center gap-2">
                        {finding.title}
                        {finding.test_case_id && <Badge variant="outline" className="text-xs">Logs Available</Badge>}
                      </CardTitle>
                      <Badge variant={finding.severity === "High" || finding.severity === "Critical" ? "destructive" : "default"}>
                        {finding.severity}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <p className="text-xs text-muted-foreground mb-2">
                      {finding.description}
                    </p>
                    <p className="text-xs font-mono">CVSS: {finding.cvss_score}</p>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  };

  // Helper to render the results view
  const renderResults = () => {
    if (!analysisData) return null;

    return (
      <Tabs defaultValue="overview" className="w-full mt-6">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="vulnerabilities">Static Findings</TabsTrigger>
          <TabsTrigger value="dynamic">Dynamic Verification</TabsTrigger>
          <TabsTrigger value="details">Details</TabsTrigger>
        </TabsList>

        {/* Overview */}
        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {Object.entries(analysisData.summary)
              .filter(([key]) => key !== "total")
              .map(([severity, count]) => {
                const Icon = severityIcons[severity as keyof typeof severityIcons];
                return (
                  <Card key={severity} className="relative overflow-hidden">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm font-medium flex items-center justify-between">
                        {severity}
                        <Icon className="h-4 w-4" />
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold">{count as number}</div>
                      <div
                        className="absolute bottom-0 left-0 h-1 w-full"
                        style={{ backgroundColor: severityColors[severity as keyof typeof severityColors] }}
                      />
                    </CardContent>
                  </Card>
                );
              })}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Severity Distribution</CardTitle>
                <CardDescription>Breakdown of vulnerabilities by severity level</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={chartData}
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      dataKey="value"
                      label={({ name, value }) => value > 0 ? `${name}: ${value}` : null}
                    >
                      {chartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Vulnerability Count</CardTitle>
                <CardDescription>Total vulnerabilities found per severity</CardDescription>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={chartData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="value" fill="hsl(var(--primary))" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="h-5 w-5" />
                Analysis Metadata
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div>
                  <p className="text-sm text-muted-foreground">API Title</p>
                  <p className="font-semibold">{analysisData.metadata.api_title}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">API Version</p>
                  <p className="font-semibold">{analysisData.metadata.api_version}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">File Analyzed</p>
                  <p className="font-semibold">{analysisData.metadata.file_analyzed}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Scan Time</p>
                  <p className="font-semibold">
                    {new Date(analysisData.metadata.timestamp_utc).toLocaleDateString()}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Vulnerabilities */}
        <TabsContent value="vulnerabilities" className="space-y-4">
          {analysisData.endpoints.map((endpoint: any, endpointIndex: number) => {
            // Sort Vulnerabilities: Critical > High > Medium > Low > Info
            const severityRank: Record<string, number> = {
              "Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4
            };

            const sortedVulns = [...endpoint.vulnerabilities].sort((a, b) => {
              const rankA = severityRank[a.severity] ?? 5;
              const rankB = severityRank[b.severity] ?? 5;
              return rankA - rankB;
            });

            return (
              <div key={endpointIndex} className="space-y-4">
                <h3 className="text-lg font-semibold">{endpoint.path}</h3>
                {sortedVulns.map((vuln: any, vulnIndex: number) => (
                  <Card key={vulnIndex} className="transition-all hover:shadow-lg">
                    <CardHeader>
                      <div className="flex items-start justify-between">
                        <div className="space-y-1">
                          <CardTitle className="text-lg">{vuln.name}</CardTitle>
                          <CardDescription>{vuln.id}</CardDescription>
                        </div>
                        <Badge variant={getSeverityBadgeVariant(vuln.severity)}>
                          {vuln.severity}
                        </Badge>
                      </div>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <p className="text-sm">{vuln.details.description}</p>
                      <div className="space-y-2">
                        <h4 className="font-semibold text-sm">Recommendation</h4>
                        <p className="text-sm text-muted-foreground">{vuln.recommendation}</p>
                      </div>
                      {vuln.evidence?.examples?.length > 0 && (
                        <div className="space-y-2">
                          <h4 className="font-semibold text-sm">Evidence</h4>
                          <div className="space-y-1">
                            {vuln.evidence.examples.map((example: string, idx: number) => (
                              <code key={idx} className="block text-xs bg-muted p-2 rounded">
                                {example}
                              </code>
                            ))}
                          </div>
                        </div>
                      )}
                      <div className="flex items-center justify-between text-xs text-muted-foreground">
                        <span>OWASP: {vuln.owasp_ref}</span>
                        <span>Score: {vuln.severity_score}</span>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )
          })}
        </TabsContent>

        {/* Dynamic Analysis */}
        <TabsContent value="dynamic" className="space-y-4">
          {renderDynamic()}
        </TabsContent>

        {/* Raw JSON */}
        <TabsContent value="details" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Raw Analysis Data</CardTitle>
              <CardDescription>Complete JSON output from the security scan</CardDescription>
            </CardHeader>
            <CardContent>
              <pre className="text-xs bg-muted p-4 rounded-lg overflow-auto max-h-96">
                {JSON.stringify(analysisData, null, 2)}
              </pre>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    );
  };

  return (
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold bg-gradient-to-r from-primary to-green-400 bg-clip-text text-transparent">
              APEX
            </h1>
            <p className="text-muted-foreground mt-1">
              API Pentest and evaluation with realtime examination
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary" />
            <span className="text-sm text-muted-foreground">v6.8.0</span>
          </div>
        </div>

        {/* Global Tabs */}
        <Tabs value={activeTab} onValueChange={handleTabChange} className="w-full">
          <div className="mb-6 overflow-x-auto pb-2">
            <TabsList className="min-w-fit justify-start bg-background border rounded-lg h-auto p-1 gap-1">
              <TabsTrigger value="new" className="px-4 py-2">
                + New Scan
              </TabsTrigger>
              {historySpecs.map((spec) => (
                <TabsTrigger key={spec.id} value={spec.id} className="px-4 py-2">
                  {spec.filename}
                  <span className="ml-2 text-xs text-muted-foreground opacity-50">
                    {new Date(spec.upload_date).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </TabsTrigger>
              ))}
            </TabsList>
          </div>

          <TabsContent value="new" className="mt-0">
            <Tabs defaultValue="static" className="w-full">
              <TabsList className="grid w-full grid-cols-2 mb-4">
                <TabsTrigger value="static">Static Spec Analysis</TabsTrigger>
                <TabsTrigger value="dynamic">Dynamic Endpoint Analysis</TabsTrigger>
              </TabsList>

              {/* 1. Static Audit Workflow */}
              <TabsContent value="static">
                <Card className="border-dashed border-2 hover:border-primary/50 transition-colors">
                  <CardContent className="p-8">
                    <div className="flex flex-col items-center justify-center space-y-4">
                      <Upload className="h-12 w-12 text-muted-foreground" />
                      <div className="text-center">
                        <h3 className="text-lg font-semibold">Upload API Specification</h3>
                        <p className="text-sm text-muted-foreground">
                          Upload your OpenAPI/Swagger spec file for vulnerability analysis
                        </p>
                      </div>
                      <label className="cursor-pointer bg-primary text-primary-foreground px-6 py-2 rounded-lg hover:bg-primary/90 transition-colors">
                        Choose File
                        <input
                          type="file"
                          className="hidden"
                          accept=".yaml,.yml,.json"
                          onChange={handleFileUpload}
                        />
                      </label>
                      {selectedFile && (
                        <p className="text-sm text-muted-foreground">Selected: {selectedFile.name}</p>
                      )}
                      {loading && <p className="text-sm text-muted-foreground">Analyzing... please wait</p>}
                      {error && <p className="text-sm text-red-500">Error: {error}</p>}
                    </div>

                    <div className="mt-6">
                      <Accordion type="single" collapsible>
                        <AccordionItem value="advanced">
                          <AccordionTrigger className="text-sm font-medium">Advanced Analysis Options</AccordionTrigger>
                          <AccordionContent>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-4">
                              <div className="space-y-4">
                                <div className="space-y-2">
                                  <Label>Severity Profile</Label>
                                  <Select value={profile} onValueChange={setProfile}>
                                    <SelectTrigger><SelectValue /></SelectTrigger>
                                    <SelectContent>
                                      <SelectItem value="default">Default</SelectItem>
                                      <SelectItem value="production">Production (Strict)</SelectItem>
                                      <SelectItem value="pci">PCI-DSS</SelectItem>
                                      <SelectItem value="hipaa">HIPAA</SelectItem>
                                    </SelectContent>
                                  </Select>
                                </div>
                                <div className="space-y-2">
                                  <Label>Failure Threshold</Label>
                                  <Select value={failOn} onValueChange={setFailOn}>
                                    <SelectTrigger><SelectValue /></SelectTrigger>
                                    <SelectContent>
                                      <SelectItem value="none">None</SelectItem>
                                      <SelectItem value="low">Low</SelectItem>
                                      <SelectItem value="medium">Medium</SelectItem>
                                      <SelectItem value="critical">Critical</SelectItem>
                                    </SelectContent>
                                  </Select>
                                </div>
                                <div className="flex items-center space-x-2 pt-2">
                                  <Switch id="blueprint" checked={generateBlueprint} onCheckedChange={setGenerateBlueprint} />
                                  <Label htmlFor="blueprint">Generate Scan Blueprint</Label>
                                </div>
                              </div>
                              <div className="space-y-4">
                                <div className="space-y-2">
                                  <Label>Policy Pack (Optional YAML)</Label>
                                  <input type="file" accept=".yaml,.yml" onChange={(e) => setPolicyFile(e.target.files?.[0] || null)} className="block w-full text-sm text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-violet-50 file:text-violet-700 hover:file:bg-violet-100" />
                                </div>
                                <div className="space-y-2">
                                  <Label>Spectral Ruleset (Optional YAML)</Label>
                                  <input type="file" accept=".yaml,.yml" onChange={(e) => setSpectralFile(e.target.files?.[0] || null)} className="block w-full text-sm text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-violet-50 file:text-violet-700 hover:file:bg-violet-100" />
                                </div>
                              </div>
                            </div>
                          </AccordionContent>
                        </AccordionItem>
                      </Accordion>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* 2. Direct Dynamic Scan Workflow */}
              <TabsContent value="dynamic">
                <Card>
                  <CardHeader>
                    <CardTitle>Dynamic Endpoint Analysis</CardTitle>
                    <CardDescription>Skip static analysis and immediately fuzzy-test your API using an OpenAPI Spec.</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid w-full max-w-sm items-center gap-1.5">
                      <Label htmlFor="oasFile">OpenAPI Spec (Required)</Label>
                      <input
                        id="oasFile"
                        type="file"
                        accept=".yaml,.yml,.json"
                        onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                        className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                      />
                    </div>

                    <div className="grid w-full max-w-sm items-center gap-1.5">
                      <Label htmlFor="targetUrlDirect">Target API URL</Label>
                      <input
                        id="targetUrlDirect"
                        type="text"
                        value={targetUrl}
                        onChange={(e) => setTargetUrl(e.target.value)}
                        className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                        placeholder="http://localhost:8000"
                      />
                    </div>

                    <div className="grid w-full max-w-sm items-center gap-1.5">
                      <Label htmlFor="authTokenDirect">Primary Auth Token (Optional)</Label>
                      <input
                        id="authTokenDirect"
                        type="text"
                        value={authToken}
                        onChange={(e) => setAuthToken(e.target.value)}
                        className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                        placeholder="Bearer eyJ..."
                      />
                    </div>

                    <div className="grid w-full max-w-sm items-center gap-1.5">
                      <Label htmlFor="authSecondaryDirect">Secondary Token (For BOLA)</Label>
                      <input
                        id="authSecondaryDirect"
                        type="text"
                        value={authSecondaryToken}
                        onChange={(e) => setAuthSecondaryToken(e.target.value)}
                        className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                        placeholder="Bearer eyJ... (Victim User)"
                      />
                      <p className="text-[10px] text-muted-foreground">Required for True BOLA detection.</p>
                    </div>

                    <button
                      onClick={handleDirectScan}
                      disabled={loading || !selectedFile}
                      className="mt-4 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors w-full max-w-sm font-semibold flex items-center justify-center gap-2"
                    >
                      {loading ? "Initializing..." : <><Shield className="w-4 h-4" /> Launch Attack</>}
                    </button>
                    {error && <p className="text-sm text-red-500">{error}</p>}
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </TabsContent>

          {/* Content for history items */}
          {historySpecs.map(spec => (
            <TabsContent key={spec.id} value={spec.id} className="mt-0">
              {loading ? (
                <div className="flex justify-center p-12">
                  <div className="animate-pulse text-lg text-muted-foreground">Loading analysis results...</div>
                </div>
              ) : (
                renderResults()
              )}
            </TabsContent>
          ))}
        </Tabs>
      </div>
    </div>
  );
}
