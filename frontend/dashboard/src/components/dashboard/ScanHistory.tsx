import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { PlusCircle, FileClock } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { AnalysisData } from "@/types/api";

interface ScanHistoryProps {
    specs: AnalysisData[];
    activeTab: string;
    onTabChange: (id: string) => void;
    loading?: boolean;
}

export default function ScanHistory({ specs, activeTab, onTabChange, loading = false }: ScanHistoryProps) {
    return (
        <div className="flex flex-col h-full border-r bg-muted/10">
            <div className="p-4 border-b">
                <Button
                    variant={activeTab === "new" ? "default" : "outline"}
                    className="w-full justify-start gap-2 h-10"
                    onClick={() => onTabChange("new")}
                >
                    <PlusCircle className="h-4 w-4" />
                    New Scan
                </Button>
            </div>
            <ScrollArea className="flex-1">
                <div className="p-2 space-y-1">
                    {loading && specs.length === 0 && (
                        <div className="p-2 space-y-2">
                            {[1, 2, 3].map(i => <Skeleton key={i} className="h-16 w-full rounded-md" />)}
                        </div>
                    )}

                    {!loading && specs.length === 0 && (
                        <div className="text-center p-8 text-sm text-muted-foreground">
                            No scan history
                        </div>
                    )}

                    {specs.map((spec) => (
                        <Button
                            key={spec.id}
                            variant={activeTab === spec.id ? "secondary" : "ghost"}
                            className={cn(
                                "w-full justify-start font-normal h-auto py-4 px-3",
                                activeTab === spec.id && "bg-muted font-medium border-l-4 border-l-primary rounded-l-none"
                            )}
                            onClick={() => onTabChange(spec.id)}
                        >
                            <div className="flex flex-col items-start gap-1 w-full overflow-hidden">
                                <div className="flex items-center gap-2 w-full">
                                    <FileClock className="h-3 w-3 flex-shrink-0 text-muted-foreground" />
                                    <span className="truncate text-sm">{spec.filename}</span>
                                </div>
                                <span className="text-xs text-muted-foreground ml-5">
                                    {new Date(spec.upload_date).toLocaleDateString()} {new Date(spec.upload_date).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                </span>
                            </div>
                        </Button>
                    ))}
                </div>
            </ScrollArea>
        </div>
    );
}
