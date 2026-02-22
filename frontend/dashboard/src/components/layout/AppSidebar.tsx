import { NavLink } from "react-router-dom";
import {
    LayoutDashboard,
    Activity,
    History,
    Settings,
    ShieldAlert
} from "lucide-react";
import { cn } from "@/lib/utils";

export default function AppSidebar() {
    return (
        <aside className="hidden lg:flex w-64 flex-col border-r bg-card h-[calc(100vh-3.5rem)] sticky top-14">
            <div className="flex flex-col gap-2 p-4">
                <div className="px-2 py-2">
                    <h2 className="mb-2 px-2 text-lg font-semibold tracking-tight">
                        Analysis
                    </h2>
                    <div className="space-y-1">
                        <NavLink
                            to="/"
                            className={({ isActive }) =>
                                cn(
                                    "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all hover:bg-accent hover:text-accent-foreground",
                                    isActive ? "bg-accent text-accent-foreground" : "text-muted-foreground"
                                )
                            }
                        >
                            <LayoutDashboard className="h-4 w-4" />
                            Static Analysis
                        </NavLink>
                        <NavLink
                            to="/dynamic"
                            className={({ isActive }) =>
                                cn(
                                    "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all hover:bg-accent hover:text-accent-foreground",
                                    isActive ? "bg-accent text-accent-foreground" : "text-muted-foreground"
                                )
                            }
                        >
                            <Activity className="h-4 w-4" />
                            Dynamic Analysis
                        </NavLink>
                    </div>
                </div>
                <div className="px-2 py-2">
                    <h2 className="mb-2 px-2 text-lg font-semibold tracking-tight">
                        Management
                    </h2>
                    <div className="space-y-1">
                        <NavLink
                            to="/history"
                            className={({ isActive }) =>
                                cn(
                                    "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all hover:bg-accent hover:text-accent-foreground",
                                    isActive ? "bg-accent text-accent-foreground" : "text-muted-foreground"
                                )
                            }
                        >
                            <History className="h-4 w-4" />
                            Scan History
                        </NavLink>
                        <NavLink
                            to="/rules"
                            className={({ isActive }) =>
                                cn(
                                    "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all hover:bg-accent hover:text-accent-foreground",
                                    isActive ? "bg-accent text-accent-foreground" : "text-muted-foreground"
                                )
                            }
                        >
                            <ShieldAlert className="h-4 w-4" />
                            Rules & Policies
                        </NavLink>
                        <NavLink
                            to="/settings"
                            className={({ isActive }) =>
                                cn(
                                    "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-all hover:bg-accent hover:text-accent-foreground",
                                    isActive ? "bg-accent text-accent-foreground" : "text-muted-foreground"
                                )
                            }
                        >
                            <Settings className="h-4 w-4" />
                            Settings
                        </NavLink>
                    </div>
                </div>
            </div>
        </aside>
    );
}
