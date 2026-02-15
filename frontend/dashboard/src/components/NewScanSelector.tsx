import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { FileText, Shield, Upload, Zap, Lock } from "lucide-react";

interface NewScanSelectorProps {
    onScanComplete: (specId: string) => void;
}

export default function NewScanSelector({ onScanComplete }: NewScanSelectorProps) {
    const [mode, setMode] = useState<"static" | "dynamic">("static");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Form States
    const [selectedFile, setSelectedFile] = useState<File | null>(null);
    const [targetUrl, setTargetUrl] = useState("http://localhost:8888");
    const [authToken, setAuthToken] = useState("");
    const [authSecondary, setAuthSecondary] = useState("");

    const handleStaticScan = async () => {
        if (!selectedFile) return;
        setLoading(true);
        setError(null);
        try {
            const formData = new FormData();
            formData.append("file", selectedFile);
            formData.append("generate_blueprint", "true");
            // Add defaults for now, could expand to full advanced form later
            formData.append("profile", "default");
            formData.append("fail_on", "none");

            const res = await fetch("http://127.0.0.1:8000/api/specs", { method: "POST", body: formData });
            if (!res.ok) throw new Error("Static Scan failed");
            const data = await res.json();
            onScanComplete(data.spec_id);
        } catch (e: any) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    };

    const handleDynamicScan = async () => {
        if (!selectedFile) return;
        setLoading(true);
        setError(null);
        try {
            const formData = new FormData();
            formData.append("file", selectedFile);
            formData.append("target_url", targetUrl);
            if (authToken) formData.append("auth_token", authToken);
            if (authSecondary) formData.append("auth_token_secondary", authSecondary);

            const res = await fetch("http://127.0.0.1:8000/api/sessions/direct", { method: "POST", body: formData });
            if (!res.ok) throw new Error("Dynamic Scan failed to launch");
            const data = await res.json();
            onScanComplete(data.spec_id); // Direct scan creates a spec wrapper
        } catch (e: any) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="max-w-4xl mx-auto py-12 space-y-8 animate-in fade-in duration-700">
            <div className="text-center space-y-4">
                <h2 className="text-4xl font-extrabold tracking-tight lg:text-5xl bg-gradient-to-r from-blue-600 to-green-500 bg-clip-text text-transparent">
                    Select Your Scan Strategy
                </h2>
                <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                    Choose between a comprehensive static code analysis or an active dynamic attack simulation against a running target.
                </p>
            </div>

            <div className="grid md:grid-cols-2 gap-6 items-start">
                {/* Static Card */}
                <Card
                    className={`cursor-pointer transition-all duration-300 border-2 hover:shadow-xl ${mode === "static" ? "border-blue-500 ring-2 ring-blue-500/20" : "border-slate-200 opacity-80 hover:opacity-100"}`}
                    onClick={() => setMode("static")}
                >
                    <CardHeader>
                        <CardTitle className="flex items-center gap-3 text-xl">
                            <div className="p-2 bg-blue-100 text-blue-600 rounded-lg">
                                <FileText className="h-6 w-6" />
                            </div>
                            Static Code Audit
                        </CardTitle>
                        <CardDescription className="text-sm pt-2">
                            Parses your OpenAPI specification to find compliance violations, logic errors, and security misconfigurations without sending traffic.
                        </CardDescription>
                    </CardHeader>
                </Card>

                {/* Dynamic Card */}
                <Card
                    className={`cursor-pointer transition-all duration-300 border-2 hover:shadow-xl ${mode === "dynamic" ? "border-green-500 ring-2 ring-green-500/20" : "border-slate-200 opacity-80 hover:opacity-100"}`}
                    onClick={() => setMode("dynamic")}
                >
                    <CardHeader>
                        <CardTitle className="flex items-center gap-3 text-xl">
                            <div className="p-2 bg-green-100 text-green-600 rounded-lg">
                                <Shield className="h-6 w-6" />
                            </div>
                            Dynamic Attack Simulation
                        </CardTitle>
                        <CardDescription className="text-sm pt-2">
                            Uses your OpenAPI spec as a map to launch active attacks (SQLi, XSS, BOLA) against your running API server.
                        </CardDescription>
                    </CardHeader>
                </Card>
            </div>

            {/* Configuration Area */}
            <Card className="border-t-4 border-t-slate-900 shadow-lg">
                <CardContent className="p-8 space-y-6">
                    <div className="space-y-4">
                        <Label className="text-base font-semibold">1. Upload OpenAPI Specification (JSON/YAML)</Label>
                        <div className="border-2 border-dashed rounded-lg p-8 flex flex-col items-center justify-center text-center hover:bg-slate-50 transition-colors">
                            <Upload className="h-10 w-10 text-muted-foreground mb-4" />
                            <Input
                                type="file"
                                accept=".json,.yaml,.yml"
                                className="hidden"
                                id="file-upload"
                                onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                            />
                            <label htmlFor="file-upload" className="cursor-pointer">
                                <span className="bg-slate-900 text-white px-4 py-2 rounded-md font-medium text-sm hover:bg-slate-800 transition-colors">
                                    Browse Files
                                </span>
                            </label>
                            {selectedFile && <p className="mt-2 text-sm font-medium text-green-600">{selectedFile.name}</p>}
                        </div>
                    </div>

                    {mode === "dynamic" && (
                        <div className="space-y-4 animate-in slide-in-from-top-4 duration-300">
                            <div className="grid md:grid-cols-2 gap-6">
                                <div className="space-y-2">
                                    <Label>Target Base URL</Label>
                                    <Input value={targetUrl} onChange={e => setTargetUrl(e.target.value)} placeholder="http://localhost:8000" />
                                    <p className="text-xs text-muted-foreground">URL where your API is running.</p>
                                </div>
                                <div className="space-y-2">
                                    <Label>Primary Auth Token</Label>
                                    <Input value={authToken} onChange={e => setAuthToken(e.target.value)} placeholder="Bearer eyJ..." />
                                </div>
                            </div>
                            <div className="space-y-2">
                                <div className="flex items-center gap-2">
                                    <Label>Secondary Auth Token</Label>
                                    <span className="text-[10px] bg-yellow-100 text-yellow-800 px-2 py-0.5 rounded-full font-mono">Recommended for BOLA</span>
                                </div>
                                <Input value={authSecondary} onChange={e => setAuthSecondary(e.target.value)} placeholder="Bearer eyJ... (User B)" />
                            </div>
                        </div>
                    )}

                    {error && (
                        <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md flex items-center gap-2">
                            <AlertTriangle className="h-4 w-4" /> {error}
                        </div>
                    )}

                    <div className="pt-4 flex justify-end">
                        <Button
                            size="lg"
                            disabled={!selectedFile || loading}
                            onClick={mode === "static" ? handleStaticScan : handleDynamicScan}
                            className={`w-full md:w-auto font-bold ${mode === "dynamic" ? "bg-green-600 hover:bg-green-700" : "bg-blue-600 hover:bg-blue-700"}`}
                        >
                            {loading ? "Analyzing..." : (mode === "static" ? "Run Static Analysis" : "Launch Attack Simulation")}
                        </Button>
                    </div>
                </CardContent>
            </Card>
        </div>
    )
}
