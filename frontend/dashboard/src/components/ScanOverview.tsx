import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { AlertTriangle, Info, FileText } from "lucide-react";

interface ScanOverviewProps {
    data: any;
}

const severityColors: Record<string, string> = {
    Critical: "hsl(var(--destructive))",
    High: "#f97316", // Orange-500
    Medium: "#eab308", // Yellow-500
    Low: "#3b82f6", // Blue-500
    Informational: "#64748b", // Slate-500
};

const severityIcons: Record<string, any> = {
    Critical: AlertTriangle,
    High: AlertTriangle,
    Medium: Info,
    Low: Info,
    Informational: Info,
};

export default function ScanOverview({ data }: ScanOverviewProps) {
    if (!data || !data.summary) return null;

    const chartData = Object.entries(data.summary)
        .filter(([key]) => key !== "total")
        .map(([severity, count]) => ({
            name: severity,
            value: count as number,
            color: severityColors[severity] || "#cccccc",
        }));

    return (
        <div className="space-y-6 animate-in fade-in duration-500">
            {/* KPI Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
                {chartData.map((item) => {
                    const Icon = severityIcons[item.name] || Info;
                    return (
                        <Card key={item.name} className="relative overflow-hidden border-t-4" style={{ borderTopColor: item.color }}>
                            <CardHeader className="pb-2">
                                <CardTitle className="text-sm font-medium flex justify-between items-center text-muted-foreground">
                                    {item.name}
                                    <Icon className="h-4 w-4 opacity-50" />
                                </CardTitle>
                            </CardHeader>
                            <CardContent>
                                <div className="text-3xl font-bold">{item.value}</div>
                            </CardContent>
                        </Card>
                    )
                })}
            </div>

            {/* Charts */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card>
                    <CardHeader>
                        <CardTitle>Severity Distribution</CardTitle>
                        <CardDescription>Proportion of issues by risk level</CardDescription>
                    </CardHeader>
                    <CardContent className="h-[300px]">
                        <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                                <Pie
                                    data={chartData}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={60}
                                    outerRadius={90}
                                    paddingAngle={5}
                                    dataKey="value"
                                >
                                    {chartData.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                    ))}
                                </Pie>
                                <Tooltip
                                    contentStyle={{ borderRadius: '8px', border: 'None', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                                />
                            </PieChart>
                        </ResponsiveContainer>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader>
                        <CardTitle>Issues Count</CardTitle>
                        <CardDescription>Absolute number of findings</CardDescription>
                    </CardHeader>
                    <CardContent className="h-[300px]">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={chartData}>
                                <CartesianGrid strokeDasharray="3 3" vertical={false} opacity={0.3} />
                                <XAxis dataKey="name" tick={{ fontSize: 12 }} axisLine={false} tickLine={false} />
                                <YAxis axisLine={false} tickLine={false} />
                                <Tooltip cursor={{ fill: 'transparent' }} contentStyle={{ borderRadius: '8px' }} />
                                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                                    {chartData.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                    ))}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    </CardContent>
                </Card>
            </div>

            {/* Metadata Footer */}
            <Card>
                <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-base">
                        <FileText className="h-4 w-4" /> Analysis Metadata
                    </CardTitle>
                </CardHeader>
                <CardContent>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                        <div>
                            <p className="text-muted-foreground">API Title</p>
                            <p className="font-semibold">{data.metadata?.api_title}</p>
                        </div>
                        <div>
                            <p className="text-muted-foreground">Scanned File</p>
                            <p className="font-semibold truncate" title={data.metadata?.file_analyzed}>{data.metadata?.file_analyzed}</p>
                        </div>
                        <div>
                            <p className="text-muted-foreground">Scan Date</p>
                            <p className="font-semibold">{data.metadata?.timestamp_utc ? new Date(data.metadata.timestamp_utc).toLocaleDateString() : 'N/A'}</p>
                        </div>
                        <div>
                            <p className="text-muted-foreground">Profile</p>
                            <Badge variant="outline">{data.metadata?.profile_used || 'default'}</Badge>
                        </div>
                    </div>
                </CardContent>
            </Card>
        </div>
    );
}
