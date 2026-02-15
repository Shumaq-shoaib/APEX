import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Lightbulb, FileCode, ExternalLink } from "lucide-react";

interface StaticFindingsListProps {
    endpoints: any[];
}

const severityRank: Record<string, number> = {
    "Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4
};

const getSeverityVariant = (severity: string) => {
    switch (severity.toLowerCase()) {
        case "critical": return "destructive"; // Shadcn default destructive is usually red/dark
        case "high": return "destructive";
        case "medium": return "default"; // Warning often fits default or secondary depending on theme
        case "low": return "secondary";
        default: return "outline";
    }
};

export default function StaticFindingsList({ endpoints }: StaticFindingsListProps) {
    if (!endpoints || endpoints.length === 0) {
        return (
            <div className="flex flex-col items-center justify-center p-12 text-muted-foreground bg-slate-50 rounded-lg border border-dashed">
                <FileCode className="h-10 w-10 mb-2 opacity-20" />
                <p>No static analysis findings to display.</p>
            </div>
        )
    }

    return (
        <div className="space-y-6">
            {endpoints.map((endpoint, i) => {
                if (!endpoint.vulnerabilities || endpoint.vulnerabilities.length === 0) return null;

                const sortedVulns = [...endpoint.vulnerabilities].sort((a, b) => {
                    const rankA = severityRank[a.severity] ?? 5;
                    const rankB = severityRank[b.severity] ?? 5;
                    return rankA - rankB;
                });

                return (
                    <Card key={i} className="overflow-hidden">
                        <CardHeader className="bg-slate-50/50 py-3 border-b">
                            <CardTitle className="font-mono text-sm flex items-center gap-2">
                                <span className="bg-slate-200 px-2 py-0.5 rounded text-slate-700">PATH</span>
                                {endpoint.path}
                            </CardTitle>
                        </CardHeader>
                        <CardContent className="p-0">
                            <Accordion type="single" collapsible className="w-full">
                                {sortedVulns.map((vuln, idx) => (
                                    <AccordionItem key={idx} value={`item-${i}-${idx}`} className="px-4 border-b last:border-0">
                                        <AccordionTrigger className="hover:no-underline py-4">
                                            <div className="flex items-center justify-between w-full pr-4">
                                                <div className="flex items-center gap-3">
                                                    <Badge variant={getSeverityVariant(vuln.severity)} className="w-20 justify-center">
                                                        {vuln.severity}
                                                    </Badge>
                                                    <span className="font-semibold text-sm">{vuln.name}</span>
                                                </div>
                                                <span className="text-xs text-muted-foreground mr-2 font-mono opacity-50">{vuln.rule_key}</span>
                                            </div>
                                        </AccordionTrigger>
                                        <AccordionContent className="pb-4 pt-1 space-y-4">

                                            {/* Description */}
                                            <div className="text-sm text-slate-700 dark:text-slate-300">
                                                {vuln.details?.description || vuln.description}
                                            </div>

                                            {/* Recommendation */}
                                            <div className="bg-blue-50 dark:bg-blue-900/20 p-3 rounded-lg border border-blue-100 dark:border-blue-800">
                                                <h4 className="flex items-center gap-2 text-xs font-bold text-blue-700 dark:text-blue-400 mb-1">
                                                    <Lightbulb className="h-3 w-3" /> REMEDIATION
                                                </h4>
                                                <p className="text-sm">{vuln.recommendation}</p>
                                            </div>

                                            {/* Evidence / Examples */}
                                            {vuln.evidence?.examples?.length > 0 && (
                                                <div className="space-y-2">
                                                    <h4 className="text-xs font-semibold text-muted-foreground">EVIDENCE</h4>
                                                    <div className="space-y-1">
                                                        {vuln.evidence.examples.map((ex: string, k: number) => (
                                                            <code key={k} className="block text-xs bg-slate-100 dark:bg-slate-900 p-2 rounded break-all border">
                                                                {ex}
                                                            </code>
                                                        ))}
                                                    </div>
                                                </div>
                                            )}

                                            {/* Reference */}
                                            <div className="flex items-center justify-end pt-2">
                                                {vuln.owasp_ref && (
                                                    <Badge variant="outline" className="text-[10px] text-muted-foreground flex gap-1">
                                                        <ExternalLink className="h-3 w-3" /> {vuln.owasp_ref}
                                                    </Badge>
                                                )}
                                            </div>
                                        </AccordionContent>
                                    </AccordionItem>
                                ))}
                            </Accordion>
                        </CardContent>
                    </Card>
                )
            })}
        </div>
    );
}
