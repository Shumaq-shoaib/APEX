import {
    Card, CardContent, CardDescription, CardHeader, CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { AlertCircle, ShieldAlert, CheckCircle2 } from "lucide-react";
import { AnalysisData, StaticVulnerability } from "@/types/api";

interface StaticFindingsProps {
    data: AnalysisData;
}

const getSeverityBadgeVariant = (severity: string) => {
    switch (severity.toLowerCase()) {
        case "critical": return "destructive";
        case "high": return "destructive";
        case "medium": return "secondary"; // Using secondary for medium to differentiate (orange/yellow usually custom)
        case "low": return "secondary";
        case "informational": return "outline";
        default: return "secondary";
    }
};

const getSeverityColorClass = (severity: string) => {
    switch (severity.toLowerCase()) {
        case "critical": return "border-l-4 border-l-red-500";
        case "high": return "border-l-4 border-l-orange-500";
        case "medium": return "border-l-4 border-l-yellow-500";
        case "low": return "border-l-4 border-l-blue-500";
        case "informational": return "border-l-4 border-l-green-500";
        default: return "";
    }
};


export default function StaticFindings({ data }: StaticFindingsProps) {
    if (!data?.endpoints) return <div className="p-8 text-center text-muted-foreground">No static findings available.</div>;

    return (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
            <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold tracking-tight">Static Findings</h2>
                <Badge variant="outline" className="px-3 py-1">
                    {data.summary.total} Issues Found
                </Badge>
            </div>

            {data.endpoints.map((endpoint, endpointIndex: number) => {
                // Sort Vulnerabilities: Critical > High > Medium > Low > Info
                const severityRank: Record<string, number> = {
                    "Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4
                };

                const sortedVulns = [...endpoint.vulnerabilities].sort((a: StaticVulnerability, b: StaticVulnerability) => {
                    const rankA = severityRank[a.severity] ?? 5;
                    const rankB = severityRank[b.severity] ?? 5;
                    return rankA - rankB;
                });

                if (sortedVulns.length === 0) return null;

                return (
                    <div key={endpointIndex} className="space-y-4">
                        <div className="flex items-center gap-2 px-1">
                            <code className="text-sm font-mono bg-muted px-2 py-1 rounded text-primary border">{endpoint.method}</code>
                            <h3 className="text-lg font-semibold tracking-tight">{endpoint.path}</h3>
                        </div>

                        <div className="grid grid-cols-1 gap-4">
                            {sortedVulns.map((vuln: StaticVulnerability, vulnIndex: number) => (
                                <Card key={vulnIndex} className={`transition-all hover:shadow-md ${getSeverityColorClass(vuln.severity)}`}>
                                    <CardHeader className="pb-2">
                                        <div className="flex items-start justify-between gap-4">
                                            <div className="space-y-1">
                                                <CardTitle className="text-base font-medium flex items-center gap-2">
                                                    <ShieldAlert className="h-4 w-4 text-muted-foreground" />
                                                    {vuln.name}
                                                </CardTitle>
                                                <CardDescription className="font-mono text-xs opacity-80">{vuln.id}</CardDescription>
                                            </div>
                                            <Badge variant={getSeverityBadgeVariant(vuln.severity)}>
                                                {vuln.severity}
                                            </Badge>
                                        </div>
                                    </CardHeader>
                                    <CardContent className="space-y-4 pt-2">
                                        <p className="text-sm leading-relaxed text-muted-foreground">{vuln.details.description}</p>

                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                                            <div className="bg-muted/30 p-3 rounded-md space-y-2">
                                                <h4 className="font-semibold text-sm flex items-center gap-2">
                                                    <CheckCircle2 className="h-3 w-3 text-green-500" />
                                                    Recommendation
                                                </h4>
                                                <p className="text-xs text-muted-foreground">{vuln.recommendation}</p>
                                            </div>

                                            {vuln.evidence?.examples?.length > 0 && (
                                                <div className="bg-muted/30 p-3 rounded-md space-y-2">
                                                    <h4 className="font-semibold text-sm flex items-center gap-2">
                                                        <AlertCircle className="h-3 w-3 text-orange-500" />
                                                        Evidence
                                                    </h4>
                                                    <div className="space-y-1 max-h-[100px] overflow-y-auto custom-scrollbar">
                                                        {vuln.evidence.examples.map((example: string, idx: number) => (
                                                            <code key={idx} className="block text-[10px] font-mono bg-background p-1.5 rounded border break-all">
                                                                {example}
                                                            </code>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}
                                        </div>

                                        <div className="flex items-center justify-between text-xs text-muted-foreground pt-2 border-t mt-2">
                                            <span className="font-mono">Reference: {vuln.owasp_ref}</span>
                                            <span className="font-mono">Score: {vuln.severity_score}</span>
                                        </div>
                                    </CardContent>
                                </Card>
                            ))}
                        </div>
                    </div>
                )
            })}
        </div>
    );
}
