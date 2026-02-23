import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { FileText, Activity, Upload, AlertTriangle, ArrowRight } from "lucide-react";
import { API_BASE_URL } from "@/lib/config";

interface NewScanSelectorProps {
    onScanComplete: (specId: string) => void;
    onDynamicScanStarted?: (sessionId: string, specId: string) => void;
}

export default function NewScanSelector({ onScanComplete }: NewScanSelectorProps) {
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [selectedFile, setSelectedFile] = useState<File | null>(null);
    const navigate = useNavigate();

    const handleStaticScan = async () => {
        if (!selectedFile) return;
        setLoading(true);
        setError(null);
        try {
            const formData = new FormData();
            formData.append("file", selectedFile);
            formData.append("generate_blueprint", "true");
            formData.append("profile", "default");
            formData.append("fail_on", "none");

            const res = await fetch(`${API_BASE_URL}/api/specs`, { method: "POST", body: formData });
            if (!res.ok) throw new Error("Static analysis failed");
            const data = await res.json();
            onScanComplete(data.spec_id);
        } catch (e: unknown) {
            setError(e instanceof Error ? e.message : "Static analysis failed");
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
                    Choose between a comprehensive static analysis of your OpenAPI spec or jump straight into dynamic analysis against a live target.
                </p>
            </div>

            <div className="grid md:grid-cols-2 gap-6 items-start">
                {/* Static Card */}
                <Card className="border-2 border-blue-500 ring-2 ring-blue-500/20 shadow-xl">
                    <CardHeader>
                        <CardTitle className="flex items-center gap-3 text-xl">
                            <div className="p-2 bg-blue-100 text-blue-600 rounded-lg">
                                <FileText className="h-6 w-6" />
                            </div>
                            Static Analysis
                        </CardTitle>
                        <CardDescription className="text-sm pt-2">
                            Parses your OpenAPI specification to find compliance violations, logic errors, and security misconfigurations without sending traffic.
                        </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="border-2 border-dashed rounded-lg p-6 flex flex-col items-center justify-center text-center hover:bg-slate-50 dark:hover:bg-slate-900 transition-colors">
                            <Upload className="h-8 w-8 text-muted-foreground mb-3" />
                            <Input
                                type="file"
                                accept=".json,.yaml,.yml"
                                className="hidden"
                                id="file-upload"
                                onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                            />
                            <label htmlFor="file-upload" className="cursor-pointer">
                                <span className="bg-slate-900 dark:bg-slate-100 dark:text-slate-900 text-white px-4 py-2 rounded-md font-medium text-sm hover:opacity-90 transition-opacity">
                                    Browse Files
                                </span>
                            </label>
                            {selectedFile && <p className="mt-2 text-sm font-medium text-green-600">{selectedFile.name}</p>}
                        </div>

                        {error && (
                            <div className="bg-destructive/10 text-destructive text-sm p-3 rounded-md flex items-center gap-2">
                                <AlertTriangle className="h-4 w-4" /> {error}
                            </div>
                        )}

                        <Button
                            size="lg"
                            disabled={!selectedFile || loading}
                            onClick={handleStaticScan}
                            className="w-full bg-blue-600 hover:bg-blue-700 font-bold"
                        >
                            {loading ? "Analyzing..." : "Run Static Analysis"}
                        </Button>
                    </CardContent>
                </Card>

                {/* Dynamic Card - navigates to /dynamic */}
                <Card
                    className="border-2 border-green-500 ring-2 ring-green-500/20 shadow-xl cursor-pointer hover:shadow-2xl transition-all group"
                    onClick={() => navigate("/dynamic")}
                >
                    <CardHeader>
                        <CardTitle className="flex items-center gap-3 text-xl">
                            <div className="p-2 bg-green-100 text-green-600 rounded-lg">
                                <Activity className="h-6 w-6" />
                            </div>
                            Dynamic Analysis
                        </CardTitle>
                        <CardDescription className="text-sm pt-2">
                            Launch active security probes (SQLi, BOLA, SSRF, JWT attacks) against a running API target. Spec file is optional.
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="flex items-center justify-between p-4 bg-green-50 dark:bg-green-950/30 rounded-lg border border-green-200 dark:border-green-900">
                            <div className="space-y-1">
                                <p className="text-sm font-medium">Ready to scan a live API?</p>
                                <p className="text-xs text-muted-foreground">No spec file required — just provide a target URL.</p>
                            </div>
                            <ArrowRight className="h-5 w-5 text-green-600 group-hover:translate-x-1 transition-transform" />
                        </div>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}
