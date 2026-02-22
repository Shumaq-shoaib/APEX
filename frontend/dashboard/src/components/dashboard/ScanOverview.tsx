import {
    Card, CardContent, CardDescription, CardHeader, CardTitle,
} from "@/components/ui/card";
import {
    PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis,
    CartesianGrid, Tooltip, ResponsiveContainer,
} from "recharts";
import { AlertTriangle, Info, FileText, CheckCircle } from "lucide-react";
import { AnalysisData } from "@/types/api";

interface ScanOverviewProps {
    data: AnalysisData;
}

// Color mapping
const severityColors = {
    Critical: "hsl(var(--critical))",
    High: "hsl(var(--high))",
    Medium: "hsl(var(--medium))",
    Low: "hsl(var(--low))",
    Informational: "hsl(var(--informational))",
};

const severityIcons = {
    Critical: AlertTriangle,
    High: AlertTriangle,
    Medium: Info,
    Low: Info,
    Informational: Info,
};

export default function ScanOverview({ data }: ScanOverviewProps) {
    if (!data) return null;

    const chartData = Object.entries(data.summary ?? {})
        .filter(([key]) => key !== "total")
        .map(([severity, count]) => ({
            name: severity,
            value: typeof count === "number" ? count : 0,
            color: severityColors[severity as keyof typeof severityColors] || severityColors.Informational,
        }));

    return (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {/* Summary Cards */}
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
                {Object.entries(data.summary)
                    .filter(([key]) => key !== "total")
                    .map(([severity, count]) => {
                        const Icon = severityIcons[severity as keyof typeof severityIcons] || Info;
                        const color = severityColors[severity as keyof typeof severityColors] || severityColors.Informational;
                        return (
                            <Card key={severity} className="relative overflow-hidden border-none shadow-sm bg-card hover:bg-accent/10 transition-colors">
                                <CardHeader className="pb-2">
                                    <CardTitle className="text-sm font-medium flex items-center justify-between text-muted-foreground">
                                        {severity}
                                        <Icon className="h-4 w-4 opacity-70" style={{ color }} />
                                    </CardTitle>
                                </CardHeader>
                                <CardContent>
                                    <div className="text-2xl font-bold">{count as number}</div>
                                    <div
                                        className="absolute bottom-0 left-0 h-1 w-full opacity-50"
                                        style={{ backgroundColor: color }}
                                    />
                                </CardContent>
                            </Card>
                        );
                    })}
            </div>

            {/* Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card className="col-span-1">
                    <CardHeader>
                        <CardTitle>Severity Distribution</CardTitle>
                        <CardDescription>Breakdown of vulnerabilities by severity level</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="h-[300px] w-full">
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={chartData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={60}
                                        outerRadius={80}
                                        paddingAngle={5}
                                        dataKey="value"
                                        label={({ name, value }) => value > 0 ? `${name}: ${value}` : null}
                                    >
                                        {chartData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={entry.color} strokeWidth={0} />
                                        ))}
                                    </Pie>
                                    <Tooltip
                                        contentStyle={{ backgroundColor: "hsl(var(--popover))", borderRadius: "8px", border: "1px solid hsl(var(--border))" }}
                                        itemStyle={{ color: "hsl(var(--popover-foreground))" }}
                                    />
                                </PieChart>
                            </ResponsiveContainer>
                        </div>
                    </CardContent>
                </Card>

                <Card className="col-span-1">
                    <CardHeader>
                        <CardTitle>Vulnerability Count</CardTitle>
                        <CardDescription>Total vulnerabilities found per severity</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="h-[300px] w-full">
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={chartData} margin={{ top: 20, right: 30, left: 0, bottom: 0 }}>
                                    <CartesianGrid strokeDasharray="3 3" vertical={false} opacity={0.2} />
                                    <XAxis dataKey="name" tick={{ fontSize: 12 }} axisLine={false} tickLine={false} />
                                    <YAxis tick={{ fontSize: 12 }} axisLine={false} tickLine={false} />
                                    <Tooltip
                                        cursor={{ fill: "hsl(var(--muted)/0.2)" }}
                                        contentStyle={{ backgroundColor: "hsl(var(--popover))", borderRadius: "8px", border: "1px solid hsl(var(--border))" }}
                                        itemStyle={{ color: "hsl(var(--popover-foreground))" }}
                                    />
                                    <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                                        {chartData.map((entry, index) => (
                                            <Cell key={`cell-${index}`} fill={entry.color} />
                                        ))}
                                    </Bar>
                                </BarChart>
                            </ResponsiveContainer>
                        </div>
                    </CardContent>
                </Card>
            </div>

            {/* Metadata */}
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                        <FileText className="h-5 w-5 text-primary" />
                        Analysis Metadata
                    </CardTitle>
                </CardHeader>
                <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                        <div className="space-y-1">
                            <p className="text-sm text-muted-foreground">API Title</p>
                            <p className="font-semibold">{data.metadata.api_title}</p>
                        </div>
                        <div className="space-y-1">
                            <p className="text-sm text-muted-foreground">API Version</p>
                            <p className="font-semibold">{data.metadata.api_version}</p>
                        </div>
                        <div className="space-y-1">
                            <p className="text-sm text-muted-foreground">File Analyzed</p>
                            <div className="flex items-center gap-2">
                                <p className="font-semibold truncate max-w-[200px]" title={data.metadata.file_analyzed}>
                                    {data.metadata.file_analyzed}
                                </p>
                                <CheckCircle className="h-3 w-3 text-green-500" />
                            </div>
                        </div>
                        <div className="space-y-1">
                            <p className="text-sm text-muted-foreground">Scan Time</p>
                            <p className="font-semibold">
                                {new Date(data.metadata.timestamp_utc).toLocaleDateString()} {new Date(data.metadata.timestamp_utc).toLocaleTimeString()}
                            </p>
                        </div>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
